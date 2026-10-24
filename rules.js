'use strict';
const crypto=require('node:crypto');
function normalizeIdentity(value){return String(value??'').trim().replace(/[٠-٩]/g,c=>String(c.charCodeAt(0)-1632)).replace(/[۰-۹]/g,c=>String(c.charCodeAt(0)-1776));}
function validIdentity(value){
 const v=normalizeIdentity(value);
 if(!/^\d{9}$/.test(v)||/^0+$/.test(v))return false;
 return [...v].reduce((sum,c,i)=>{const n=Number(c)*(i%2?2:1);return sum+(n>9?n-9:n);},0)%10===0;
}
function validDay(d){return /^\d{4}-\d{2}-\d{2}$/.test(d)&&!isNaN(Date.parse(d))&&new Date(d+'T12:00:00Z').toISOString().slice(0,10)===d;}
function buildNotifications(students,records,today){
 const byId=new Map(students.map(s=>[s.id,s]));const identities=new Map();const dates=new Map();const attendance=new Map();
 for(const s of students){const v=normalizeIdentity(s.national_id);if(v){if(!identities.has(v))identities.set(v,[]);identities.get(v).push(s);}}
 for(const r of records){const s=byId.get(r.student_id);if(!s||r.date>today)continue;if(!dates.has(s.group_id))dates.set(s.group_id,new Set());dates.get(s.group_id).add(r.date);attendance.set(s.id+':'+r.date,r.status);}
 const out=[];
 function add(s,type,title,detail,version){out.push({key:crypto.createHash('sha256').update(JSON.stringify([s.id,type,version])).digest('hex'),studentId:s.id,name:s.name,nationalId:s.national_id,groupId:s.group_id,type,title,detail});}
 for(const s of students){
  const id=normalizeIdentity(s.national_id);
  if(!validIdentity(id))add(s,'invalid_id','رقم هوية غير صالح',id?'الرقم لا يجتاز فحص الطول أو رقم التحقق؛ راجع الاستمارة الأصلية.':'رقم الهوية غير موجود.',s.national_id);
  if(id&&identities.get(id).length>1)add(s,'duplicate_id','رقم هوية مكرر','الرقم مسجل لطلاب: '+identities.get(id).map(x=>x.name).join('، '),identities.get(id).map(x=>x.id));
  if(!s.id_reviewed)add(s,'unreviewed_id','هوية بانتظار المراجعة','الفحص الحسابي لا يثبت أن الرقم يخص الطالب. راجع مستند الطالب ثم اعتمد الهوية.',[s.national_id,s.id_reviewed]);
  if(!s.parent_phone)add(s,'missing_phone','هاتف ولي الأمر غير موجود','أضف رقمًا للتواصل من صفحة تعديل الطالب.',s.parent_phone);
  const latest=[...(dates.get(s.group_id)||[])].sort().reverse();let streak=0;
  for(const day of latest){if(attendance.get(s.id+':'+day)!=='absent')break;streak++;}
  if(streak>=3)add(s,'absence','غياب '+streak+' لقاءات متتالية','آخر لقاء: '+latest[0]+' — تواصل مع ولي الأمر لمتابعة سبب الغياب.',[latest[0],streak]);
 }
 return out;
}
module.exports={validIdentity,normalizeIdentity,validDay,buildNotifications};
