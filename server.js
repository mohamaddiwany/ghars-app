'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
if (!process.env.GHARS_ADMIN_CODE || (process.env.GHARS_ADMIN_CODE.length < 12 || process.env.GHARS_ADMIN_CODE.startsWith('REPLACE_'))) throw new Error('Set GHARS_ADMIN_CODE to a secret of at least 12 characters.');
const {buildNotifications,validIdentity,normalizeIdentity,validDay}=require('./rules');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'ghars.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS students (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, grade TEXT NOT NULL, group_id TEXT NOT NULL,
 national_id TEXT NOT NULL DEFAULT '', parent_phone TEXT NOT NULL DEFAULT '',
 allergy TEXT NOT NULL DEFAULT '', chronic TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
 id_reviewed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS guides (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE, group_id TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS attendance (
 id INTEGER PRIMARY KEY AUTOINCREMENT, student_id INTEGER NOT NULL, date TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('present','late','absent')), marked_by TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(student_id,date), FOREIGN KEY(student_id) REFERENCES students(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notification_reads (
 user_key TEXT NOT NULL, notification_key TEXT NOT NULL, PRIMARY KEY(user_key,notification_key)
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, role TEXT NOT NULL, user_id TEXT, student_id INTEGER, csrf TEXT NOT NULL,
 expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL
);`);

const groups = [
 {id:'g1',name:'الأول + الثاني'},
 {id:'g2',name:'الثالث + الرابع'},
 {id:'g3',name:'الخامس + السادس'},
 {id:'g4',name:'الأشبال (الإعدادي والثانوي)'}
];
const GROUP_IDS = new Set(groups.map(x=>x.id));
function env(name, fallback){ const v=process.env[name]; return v===undefined||v===''?fallback:v; }
function groupName(id){ return groups.find(g=>g.id===id)?.name || id; }
function hash(v){ return crypto.createHash('sha256').update(String(v)).digest('hex'); }
function scryptHash(v){ const salt=crypto.randomBytes(16).toString('hex'); const derived=crypto.scryptSync(String(v),salt,32).toString('hex'); return `scrypt$${salt}$${derived}`; }
function scryptVerify(v,stored){ try{ const [,salt,hex]=stored.split('$'); const a=Buffer.from(hex,'hex'); const b=crypto.scryptSync(String(v),salt,32); return a.length===b.length&&crypto.timingSafeEqual(a,b); }catch{return false;} }
function clean(s){ return String(s??'').trim(); }
function json(res,status,obj){ const body=JSON.stringify(obj); res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}); res.end(body); }
function redirect(res,loc){ res.writeHead(302,{Location:loc}); res.end(); }
function parseCookies(req){ const out={}; for(const part of (req.headers.cookie||'').split(';')){const i=part.indexOf('='); if(i>0) {try{out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());}catch{}}} return out; }
function sessionFrom(req){ const raw=parseCookies(req).ghars_session; if(!raw) return null; const row=db.prepare('SELECT * FROM sessions WHERE token_hash=? AND expires_at>?').get(hash(raw),Date.now()); if(row?.role==='guide'&&!db.prepare('SELECT id FROM guides WHERE id=?').get(Number(row.user_id)))return null;return row||null; }
function requireRole(req,res,roles){ const s=sessionFrom(req); if(!s){json(res,401,{error:'غير مسجل الدخول'});return null;} if(!roles.includes(s.role)){json(res,403,{error:'ليس لديك صلاحية لهذا الإجراء'});return null;} return s; }
async function body(req){ return await new Promise((resolve,reject)=>{let d=''; req.on('data',c=>{d+=c;if(d.length>1e6) req.destroy();});req.on('end',()=>{try{resolve(d?JSON.parse(d):{})}catch(e){reject(e)}});req.on('error',reject)}); }
function publicStudent(r){ return {id:r.id,name:r.name,grade:r.grade,groupId:r.group_id,parentPhone:r.parent_phone,idReviewed:!!r.id_reviewed}; }
function healthStudent(r){ return {...publicStudent(r),nationalId:r.national_id,health:{allergy:r.allergy,chronic:r.chronic,notes:r.notes}}; }
function importStudents(data){
 if(!Array.isArray(data)||!data.length||data.length>2000)throw new Error('Expected 1–2000 students');
 const seen=new Set();
 for(const s of data){if(!Number.isSafeInteger(s.id)||s.id<1||seen.has(s.id)||!clean(s.name)||!clean(s.grade)||!GROUP_IDS.has(s.group)||typeof s.nationalId!=='string'||typeof s.parentPhone!=='string')throw new Error('Invalid student data');seen.add(s.id);}
 const ins=db.prepare(`INSERT INTO students(id,name,grade,group_id,national_id,parent_phone,allergy,chronic,notes,id_reviewed) VALUES(?,?,?,?,?,?,?,?,?,0)`);
 db.exec('BEGIN');try{for(const s of data)ins.run(s.id,clean(s.name),clean(s.grade),s.group,clean(s.nationalId),clean(s.parentPhone),clean(s.health?.allergy),clean(s.health?.chronic),clean(s.health?.notes));db.exec('COMMIT')}catch(e){db.exec('ROLLBACK');throw e;}
 return data.length;
}
if(process.env.SEED_FILE && !db.prepare('SELECT COUNT(*) c FROM students').get().c) importStudents(JSON.parse(fs.readFileSync(process.env.SEED_FILE,'utf8')));
const attempts=new Map();
function loginAllowed(req){
 const key=hash(req.socket.remoteAddress||'local'),now=Date.now();
 if(attempts.size>10000) for(const [k,v] of attempts)if(v.until<now)attempts.delete(k);
 const old=attempts.get(key);const entry=old&&old.until>now?old:{count:0,until:now+15*60000};entry.count++;attempts.set(key,entry);return entry.count<=30;
}
function notifications(ss){
 const all=db.prepare('SELECT * FROM students ORDER BY name').all();
 const records=db.prepare('SELECT student_id,date,status FROM attendance ORDER BY date').all();
 let result=buildNotifications(all,records,new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jerusalem',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date()));
 if(ss.role==='guide'){
  const g=db.prepare('SELECT * FROM guides WHERE id=?').get(Number(ss.user_id));
  result=result.filter(n=>g&&n.groupId===g.group_id&&n.type==='absence').map(({nationalId,...n})=>n);
 }
 const read=new Set(db.prepare('SELECT notification_key FROM notification_reads WHERE user_key=?').all(ss.role+':'+ss.user_id).map(r=>r.notification_key));
 return result.map(n=>({...n,read:read.has(n.key)}));
}

function login(req,res,data){
 if(!loginAllowed(req))return json(res,429,{error:'محاولات كثيرة. حاول بعد 15 دقيقة.'});
 const role=clean(data.role), name=clean(data.name), code=clean(data.code);
 if(role==='admin'){
   if(name!=='المدير العام' || !crypto.timingSafeEqual(Buffer.from(hash(code)),Buffer.from(hash(process.env.GHARS_ADMIN_CODE)))) return json(res,401,{error:'بيانات المدير غير صحيحة'});
   const token=crypto.randomBytes(32).toString('base64url'), csrf=crypto.randomBytes(24).toString('base64url');
   db.prepare('INSERT INTO sessions(token_hash,role,user_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?,?)').run(hash(token),'admin','admin',csrf,Date.now()+Number(env('SESSION_DAYS','7'))*86400000,Date.now());
   res.setHeader('Set-Cookie',`ghars_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; ${process.env.COOKIE_SECURE==='1'?'Secure; ':''}Path=/; Max-Age=${Number(env('SESSION_DAYS','7'))*86400}`);
   return json(res,200,{role:'admin',name:'المدير العام',csrf});
 }
 if(role==='parent'){
   const matches=db.prepare('SELECT * FROM students WHERE name=? AND national_id=? AND id_reviewed=1').all(name,code);const r=matches.length===1?matches[0]:null;
   if(!r) return json(res,401,{error:'اسم الطالب أو رقم الهوية غير صحيح. إذا كانت الهوية غير محدثة، يحتاج المدير لتصحيحها أولًا.'});
   const token=crypto.randomBytes(32).toString('base64url'), csrf=crypto.randomBytes(24).toString('base64url');
   db.prepare('INSERT INTO sessions(token_hash,role,student_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?,?)').run(hash(token),'parent',r.id,csrf,Date.now()+7*86400000,Date.now());
   res.setHeader('Set-Cookie',`ghars_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; ${process.env.COOKIE_SECURE==='1'?'Secure; ':''}Path=/; Max-Age=604800`);
   return json(res,200,{role:'parent',name:r.name,student:publicStudent(r),csrf});
 }
 if(role==='guide'){
   const r=db.prepare('SELECT * FROM guides WHERE name=? AND phone=?').get(name,code);
   if(!r) return json(res,401,{error:'حساب المرشد غير موجود. ينشئه المدير العام أولًا.'});
   const token=crypto.randomBytes(32).toString('base64url'), csrf=crypto.randomBytes(24).toString('base64url');
   db.prepare('INSERT INTO sessions(token_hash,role,user_id,csrf,expires_at,created_at) VALUES(?,?,?,?,?,?)').run(hash(token),'guide',String(r.id),csrf,Date.now()+7*86400000,Date.now());
   res.setHeader('Set-Cookie',`ghars_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; ${process.env.COOKIE_SECURE==='1'?'Secure; ':''}Path=/; Max-Age=604800`);
   return json(res,200,{role:'guide',name:r.name,guide:{id:r.id,name:r.name,phone:r.phone,groupId:r.group_id},csrf});
 }
 return json(res,400,{error:'نوع الدخول غير صحيح'});
}
function api(req,res,url){
 const method=req.method;
 if(url.pathname==='/api/login'&&method==='POST') return body(req).then(x=>login(req,res,x)).catch(()=>json(res,400,{error:'طلب غير صالح'}));

 if(url.pathname==='/api/me'&&method==='GET'){ const s=sessionFrom(req); if(!s)return json(res,401,{error:'غير مسجل الدخول'}); if(s.role==='admin')return json(res,200,{role:'admin',name:'المدير العام',csrf:s.csrf}); if(s.role==='parent'){const r=db.prepare('SELECT * FROM students WHERE id=?').get(s.student_id);return json(res,200,{role:'parent',name:r.name,student:publicStudent(r),csrf:s.csrf});} const g=db.prepare('SELECT * FROM guides WHERE id=?').get(Number(s.user_id));return json(res,200,{role:'guide',name:g.name,guide:{id:g.id,name:g.name,phone:g.phone,groupId:g.group_id},csrf:s.csrf}); }
 const s=sessionFrom(req); if(method!=='GET' && s){ const provided=req.headers['x-csrf-token']; if(provided!==s.csrf)return json(res,403,{error:'رمز الحماية غير صحيح'}); }
 if(url.pathname==='/api/logout'&&method==='POST'){ const raw=parseCookies(req).ghars_session;if(raw)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(raw));res.setHeader('Set-Cookie',`ghars_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);return json(res,200,{ok:true}); }
 if(url.pathname==='/api/notifications'&&method==='GET'){const ss=requireRole(req,res,['admin','guide']);if(!ss)return;const items=notifications(ss);return json(res,200,{items,unread:items.filter(n=>!n.read).length});}
 if(url.pathname==='/api/notifications/read'&&method==='POST'){const ss=requireRole(req,res,['admin','guide']);if(!ss)return;return body(req).then(d=>{const items=notifications(ss);if(!items.some(n=>n.key===d.key))return json(res,404,{error:'التنبيه غير موجود'});db.prepare('INSERT OR IGNORE INTO notification_reads VALUES(?,?)').run(ss.role+':'+ss.user_id,d.key);return json(res,200,{ok:true});}).catch(()=>json(res,400,{error:'طلب غير صالح'}));}
 if(url.pathname==='/api/import'&&method==='POST'){const ss=requireRole(req,res,['admin']);if(!ss)return;return body(req).then(d=>{if(db.prepare('SELECT COUNT(*) c FROM students').get().c)return json(res,409,{error:'الاستيراد الأولي متاح فقط عندما تكون قائمة الطلاب فارغة، لمنع التكرار والكتابة فوق التعديلات.'});const count=importStudents(d.students);return json(res,200,{count});}).catch(()=>json(res,400,{error:'ملف بيانات غير صالح. لم تُحفظ أي تغييرات.'}));}
 if(url.pathname==='/api/groups'&&method==='GET') return json(res,200,{groups});
 if(url.pathname==='/api/dashboard'&&method==='GET'){ const ss=requireRole(req,res,['admin']);if(!ss)return; const counts=groups.map(g=>({...g,count:db.prepare('SELECT COUNT(*) c FROM students WHERE group_id=?').get(g.id).c}));const total=db.prepare('SELECT COUNT(*) c FROM students').get().c;const unreviewed=db.prepare('SELECT COUNT(*) c FROM students WHERE id_reviewed=0').get().c;return json(res,200,{total,unreviewed,groups:counts}); }
 if(url.pathname==='/api/students'&&method==='GET'){ const ss=requireRole(req,res,['admin','guide']);if(!ss)return; const q=clean(url.searchParams.get('q')); let rows; if(ss.role==='guide'){ const g=db.prepare('SELECT group_id FROM guides WHERE id=?').get(Number(ss.user_id)); if(!g)return json(res,403,{error:'المرشد غير موجود'}); rows=q?db.prepare(`SELECT * FROM students WHERE group_id=? AND (name LIKE ? OR grade LIKE ?) ORDER BY name`).all(g.group_id,'%'+q+'%','%'+q+'%'):db.prepare('SELECT * FROM students WHERE group_id=? ORDER BY name').all(g.group_id); return json(res,200,{students:rows.map(publicStudent)}); } rows=q?db.prepare(`SELECT * FROM students WHERE name LIKE ? OR grade LIKE ? ORDER BY name`).all('%'+q+'%','%'+q+'%'):db.prepare('SELECT * FROM students ORDER BY name').all();return json(res,200,{students:rows.map(healthStudent)}); }
 const sm=url.pathname.match(/^\/api\/students\/(\d+)$/); if(sm){ const id=Number(sm[1]); const ss=requireRole(req,res,['admin']);if(!ss)return; if(method==='PUT')return body(req).then(d=>{const old=db.prepare('SELECT * FROM students WHERE id=?').get(id);if(!old)return json(res,404,{error:'الطالب غير موجود'});const name=clean(d.name),grade=clean(d.grade),groupId=clean(d.groupId),nationalId=clean(d.nationalId),parentPhone=clean(d.parentPhone);if(!name||!grade||!GROUP_IDS.has(groupId))return json(res,400,{error:'بيانات الطالب ناقصة'});if(d.idReviewed&&!validIdentity(nationalId))return json(res,400,{error:'لا يمكن اعتماد رقم هوية غير صالح حسابيًا. صحّح الرقم أولًا.'});db.prepare('UPDATE students SET name=?,grade=?,group_id=?,national_id=?,parent_phone=?,allergy=?,chronic=?,notes=?,id_reviewed=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(name,grade,groupId,nationalId,parentPhone,clean(d.allergy),clean(d.chronic),clean(d.notes),d.idReviewed?1:0,id);if(old.national_id!==nationalId||!d.idReviewed)db.prepare("DELETE FROM sessions WHERE role='parent' AND student_id=?").run(id);return json(res,200,{student:healthStudent(db.prepare('SELECT * FROM students WHERE id=?').get(id))});}).catch(()=>json(res,400,{error:'بيانات غير صالحة'})); if(method==='GET'){const r=db.prepare('SELECT * FROM students WHERE id=?').get(id);return r?json(res,200,{student:healthStudent(r)}):json(res,404,{error:'الطالب غير موجود'});} }
 if(url.pathname==='/api/guides'&&method==='GET'){const ss=requireRole(req,res,['admin']);if(!ss)return;return json(res,200,{guides:db.prepare('SELECT id,name,phone,group_id groupId FROM guides ORDER BY name').all()});}
 if(url.pathname==='/api/guides'&&method==='POST')return requireRole(req,res,['admin'])&&body(req).then(d=>{const name=clean(d.name),phone=clean(d.phone),groupId=clean(d.groupId);if(!name||!phone||!GROUP_IDS.has(groupId))return json(res,400,{error:'بيانات المرشد ناقصة'});try{const r=db.prepare('INSERT INTO guides(name,phone,group_id) VALUES(?,?,?)').run(name,phone,groupId);return json(res,201,{guide:{id:Number(r.lastInsertRowid),name,phone,groupId}})}catch(e){return json(res,409,{error:'رقم الهاتف مستخدم لمرشد آخر'})}}).catch(()=>json(res,400,{error:'بيانات غير صالحة'}));
 const gm=url.pathname.match(/^\/api\/guides\/(\d+)$/);if(gm&&method==='DELETE'){const ss=requireRole(req,res,['admin']);if(!ss)return;db.prepare("DELETE FROM sessions WHERE role='guide' AND user_id=?").run(gm[1]);db.prepare('DELETE FROM guides WHERE id=?').run(Number(gm[1]));return json(res,200,{ok:true});}
 if(url.pathname==='/api/attendance'&&method==='GET'){ const ss=requireRole(req,res,['admin','guide','parent']);if(!ss)return; const studentId=url.searchParams.get('studentId');const groupId=url.searchParams.get('groupId');const from=url.searchParams.get('from')||'0000-01-01',to=url.searchParams.get('to')||'9999-12-31';let rows=[]; if(ss.role==='parent') rows=db.prepare(`SELECT a.*,s.name student_name,s.group_id FROM attendance a JOIN students s ON s.id=a.student_id WHERE a.student_id=? AND a.date BETWEEN ? AND ? ORDER BY a.date DESC`).all(ss.student_id,from,to); else if(ss.role==='guide'){const g=db.prepare('SELECT * FROM guides WHERE id=?').get(Number(ss.user_id));rows=db.prepare(`SELECT a.*,s.name student_name,s.group_id FROM attendance a JOIN students s ON s.id=a.student_id WHERE s.group_id=? AND a.date BETWEEN ? AND ? ${studentId?'AND a.student_id=?':''} ORDER BY a.date DESC,s.name`).all(...(studentId?[g.group_id,from,to,Number(studentId)]:[g.group_id,from,to]));} else {rows=db.prepare(`SELECT a.*,s.name student_name,s.group_id FROM attendance a JOIN students s ON s.id=a.student_id WHERE a.date BETWEEN ? AND ? ${groupId?'AND s.group_id=?':''} ${studentId?'AND a.student_id=?':''} ORDER BY a.date DESC,s.name`).all(...(groupId&&studentId?[from,to,groupId,Number(studentId)]:groupId?[from,to,groupId]:studentId?[from,to,Number(studentId)]:[from,to]));} return json(res,200,{attendance:rows}); }
 if(url.pathname==='/api/attendance'&&method==='POST'){ const ss=requireRole(req,res,['admin','guide']);if(!ss)return;return body(req).then(d=>{const date=clean(d.date),items=Array.isArray(d.items)?d.items:[];if(!validDay(date)||date>new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Jerusalem'}).format(new Date())||!items.length)return json(res,400,{error:'التاريخ أو السجلات غير صالحة'});let allowedGroup=null;if(ss.role==='guide')allowedGroup=db.prepare('SELECT group_id FROM guides WHERE id=?').get(Number(ss.user_id))?.group_id;for(const it of items){const st=db.prepare('SELECT group_id FROM students WHERE id=?').get(Number(it.studentId));if(!st||!['present','late','absent'].includes(it.status)||(allowedGroup&&st.group_id!==allowedGroup))return json(res,400,{error:'أحد سجلات الحضور غير صالح أو خارج فرقتك'});}const up=db.prepare(`INSERT INTO attendance(student_id,date,status,marked_by,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(student_id,date) DO UPDATE SET status=excluded.status,marked_by=excluded.marked_by,updated_at=CURRENT_TIMESTAMP`);for(const it of items){const st=db.prepare('SELECT group_id FROM students WHERE id=?').get(Number(it.studentId));if(!st||!['present','late','absent'].includes(it.status)||(allowedGroup&&st.group_id!==allowedGroup))continue;up.run(Number(it.studentId),date,it.status,ss.role==='guide'?`guide:${ss.user_id}`:'admin');}return json(res,200,{ok:true});}).catch(()=>json(res,400,{error:'بيانات غير صالحة'})); }
 if(url.pathname==='/api/report'&&method==='GET'){const ss=requireRole(req,res,['admin']);if(!ss)return;const from=url.searchParams.get('from')||'0000-01-01',to=url.searchParams.get('to')||'9999-12-31';const rows=db.prepare('SELECT status,COUNT(*) c FROM attendance WHERE date BETWEEN ? AND ? GROUP BY status').all(from,to);const out={present:0,late:0,absent:0};for(const r of rows)out[r.status]=r.c;out.total=out.present+out.late+out.absent;out.rate=out.total?Math.round(((out.present+out.late)/out.total)*100):0;return json(res,200,out);}
 return json(res,404,{error:'المسار غير موجود'});
}

function serve(req,res){
 try{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');res.setHeader('X-Frame-Options','DENY');
 const u=new URL(req.url,`http://${req.headers.host||'localhost'}`);
 if(u.pathname.startsWith('/api/')) return api(req,res,u);
 let file=u.pathname==='/'?path.join(PUBLIC,'index.html'):path.join(PUBLIC,u.pathname.replace(/^\//,''));
 if(!file.startsWith(PUBLIC+path.sep))return json(res,403,{error:'Forbidden'});
 fs.stat(file,(e,st)=>{if(e||!st.isFile())return json(res,404,{error:'الصفحة غير موجودة'});const ext=path.extname(file);const types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8'};res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-cache':'public, max-age=3600'});fs.createReadStream(file).pipe(res);});
 }catch(e){if(!res.headersSent)json(res,400,{error:'طلب غير صالح'});else res.end();}
}
const port=Number(env('PORT','3000'));
http.createServer(serve).listen(port,()=>console.log(`Ghars running at http://localhost:${port}`));
