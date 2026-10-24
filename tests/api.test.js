const {test}=require('node:test');const assert=require('node:assert/strict');const {spawn}=require('node:child_process');const {mkdtempSync,rmSync}=require('node:fs');const os=require('node:os');const path=require('node:path');const net=require('node:net');
test('import, role boundaries, CSRF, identity edits and live absence notifications',async()=>{
 const port=await new Promise(resolve=>{const s=net.createServer().listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
 const dir=mkdtempSync(path.join(os.tmpdir(),'ghars-test-'));const child=spawn(process.execPath,['server.js'],{cwd:path.join(__dirname,'..'),env:{...process.env,PORT:String(port),DATA_DIR:dir,GHARS_ADMIN_CODE:'test-secret-12345',SEED_FILE:''},stdio:['ignore','pipe','pipe']});
 try{
 await new Promise((resolve,reject)=>{child.stdout.once('data',resolve);child.once('exit',c=>reject(new Error('Server exited '+c)));child.stderr.on('data',()=>{});});
 const base='http://127.0.0.1:'+port;
 async function call(route,method='GET',data,auth){const r=await fetch(base+route,{method,headers:{'Content-Type':'application/json',...(auth?{cookie:auth.cookie,'X-CSRF-Token':auth.csrf}:{})},body:data===undefined?undefined:JSON.stringify(data)});return {status:r.status,body:await r.json(),cookie:r.headers.get('set-cookie')?.split(';')[0]};}
 async function login(role,name,code){const r=await call('/api/login','POST',{role,name,code});assert.equal(r.status,200);return {cookie:r.cookie,csrf:r.body.csrf};}
 assert.equal((await call('/api/students')).status,401);
 const admin=await login('admin','المدير العام','test-secret-12345');
 const students=[{id:1,name:'طالب أول',grade:'أول',group:'g1',nationalId:'123456782',parentPhone:'0500000000'},{id:2,name:'طالب ثان',grade:'ثالث',group:'g2',nationalId:'000000000',parentPhone:''}];
 assert.equal((await call('/api/import','POST',{students},{cookie:admin.cookie,csrf:'wrong'})).status,403);
 assert.equal((await call('/api/import','POST',{students},admin)).body.count,2);
 assert.equal((await call('/api/import','POST',{students},admin)).status,409);
 assert.equal((await call('/api/login','POST',{role:'parent',name:'طالب أول',code:'123456782'})).status,401);
 await call('/api/guides','POST',{name:'مرشد اختبار',phone:'0501111111',groupId:'g1'},admin);
 const guide=await login('guide','مرشد اختبار','0501111111');
 const visible=await call('/api/students','GET',undefined,guide);assert.equal(visible.body.students.length,1);assert.equal(visible.body.students[0].nationalId,undefined);
 assert.equal((await call('/api/students/2','GET',undefined,guide)).status,403);
 assert.equal((await call('/api/attendance','POST',{date:'2026-10-01',items:[{studentId:1,status:'absent'},{studentId:2,status:'absent'}]},guide)).status,400);
 assert.equal((await call('/api/attendance','GET',undefined,admin)).body.attendance.length,0);
 assert.equal((await call('/api/attendance','POST',{date:'2026-02-30',items:[{studentId:1,status:'absent'}]},admin)).status,400);
 for(const date of ['2026-10-01','2026-10-08','2026-10-15'])assert.equal((await call('/api/attendance','POST',{date,items:[{studentId:1,status:'absent'}]},guide)).status,200);
 const n=await call('/api/notifications','GET',undefined,guide);assert.equal(n.body.items.length,1);assert.equal(n.body.items[0].type,'absence');assert.equal(n.body.items[0].nationalId,undefined);
 assert.equal((await call('/api/notifications/read','POST',{key:n.body.items[0].key},guide)).status,200);assert.equal((await call('/api/notifications','GET',undefined,guide)).body.unread,0);
 const update={name:'طالب أول',grade:'أول',groupId:'g1',nationalId:'123456781',parentPhone:'0500000000',idReviewed:true};
 assert.equal((await call('/api/students/1','PUT',update,admin)).status,400);update.nationalId='123456782';assert.equal((await call('/api/students/1','PUT',update,admin)).status,200);
 const parent=await login('parent','طالب أول','123456782');assert.equal((await call('/api/notifications','GET',undefined,parent)).status,403);assert.equal((await call('/api/students','GET',undefined,parent)).status,403);assert.equal((await call('/api/attendance?studentId=2','GET',undefined,parent)).body.attendance.every(r=>r.student_id===1),true);
 await call('/api/attendance','POST',{date:'2026-10-22',items:[{studentId:1,status:'present'}]},guide);assert.equal((await call('/api/notifications','GET',undefined,guide)).body.items.length,0);
 assert.equal((await call('/api/logout','POST',{}, {cookie:admin.cookie,csrf:'bad'})).status,403);
 assert.equal((await fetch(base+'/students.json')).status,404);assert.ok(!(await (await fetch(base+'/students.json')).text()).includes('123456782'));
 const guides=await call('/api/guides','GET',undefined,admin);await call('/api/guides/'+guides.body.guides[0].id,'DELETE',undefined,admin);assert.equal((await call('/api/students','GET',undefined,guide)).status,401);
 }finally{child.kill();await new Promise(r=>child.once('exit',r));rmSync(dir,{recursive:true,force:true});}
});
