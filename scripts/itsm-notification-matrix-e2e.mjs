import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'
const BASE=process.env.E2E_BASE_URL||'http://127.0.0.1:3001'
const ORIGIN=process.env.E2E_ORIGIN||'https://itsm.cutover.hi5central.com'
const OWNER='danielsuttonsamsung@gmail.com'
const REQUESTER='danieljamessutton18@outlook.com'
const classes=[
 ['recordCreated','incident.created','Incident'],
 ['statusChanges','service_request.status_changed','Service Request'],
 ['customerUpdates','problem.customer_update_added','Problem'],
 ['approvals','change.approval_required','Change'],
 ['taskUpdates','project.task_assigned','Project'],
 ['systemUpdates','system.audit','Platform'],
]
function pass(x){console.log('PASS ',x)}
async function api(token,path,{method='GET',body,portal=false}={}){
 const res=await fetch(BASE+path,{method,headers:{Origin:ORIGIN,...(portal?{Referer:`${ORIGIN}/portal`}:{}),Cookie:`${portal?'hi5central_portal_session':'hi5central_session'}=${token}`,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body)})
 const text=await res.text();const payload=text?JSON.parse(text):{}
 assert(res.ok,`${method} ${path} -> ${res.status}: ${text}`);return payload
}
async function emit(tenantId,userId,eventType,targetType,targetRef){
 const event=(await pool.query(`INSERT INTO domain_events(tenant_id,event_type,aggregate_type,aggregate_reference,payload) VALUES($1,$2,$3,$4,'{}'::jsonb) RETURNING id`,[tenantId,eventType,targetType,targetRef])).rows[0]
 const row=(await pool.query(`SELECT hi5_insert_notification($1,$2,$3,$4,$5,$6,$7,$8,'{}'::jsonb) id`,[tenantId,userId,event.id,eventType,`Matrix ${eventType}`,'matrix',targetType,targetRef])).rows[0]
 return row.id
}
async function main(){
 const tenant=(await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1',['test2'])).rows[0]
 const users=await pool.query(`SELECT u.id,u.email FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1 WHERE lower(u.email)=ANY($2::text[])`,[tenant.id,[OWNER,REQUESTER]])
 const owner=users.rows.find(r=>r.email.toLowerCase()===OWNER),requester=users.rows.find(r=>r.email.toLowerCase()===REQUESTER)
 assert(owner?.id&&requester?.id)
 const ot=await createSession(pool,{tenantId:tenant.id,userId:owner.id,mfaVerified:true,ttlSeconds:3600,surface:'workspace'})
 const rt=await createSession(pool,{tenantId:tenant.id,userId:requester.id,mfaVerified:true,ttlSeconds:3600,surface:'portal'})
 const prior=(await api(ot,'/api/v1/notification-settings')).settings
 await api(rt,'/api/v1/notification-preferences',{method:'PATCH',portal:true,body:{preferences:{channels:{inApp:true,email:true,browser:true},requesterEvents:{customerUpdates:true,statusChanges:true,recordCreated:true,approvals:true,taskUpdates:true,systemUpdates:true}}}})
 try{
  for(const [key,eventType,targetType] of classes){
   const enabled=Object.fromEntries(classes.map(([k])=>[k,k===key]))
   const settings={...prior,channels:{...prior.channels,inApp:true,email:true,browser:true},categories:Object.fromEntries(Object.keys(prior.categories||{}).map(k=>[k,true])),requesterEvents:enabled}
   await api(ot,'/api/v1/notification-settings',{method:'PATCH',body:{settings}})
   const onRef=`MATRIX-${key}-ON-${Date.now()}`,onId=await emit(tenant.id,requester.id,eventType,targetType,onRef)
   const onDeliveries=await pool.query('SELECT channel FROM notification_deliveries WHERE notification_id=$1 ORDER BY channel',[onId])
   assert.deepEqual(onDeliveries.rows.map(r=>r.channel),['browser','email'])
   const bell=await api(rt,'/api/v1/notifications?limit=250',{portal:true})
   assert(bell.items.some(i=>i.id===onId),`${key} enabled must appear in bell`)
   pass(`${targetType} ${key} enabled => bell + browser/email delivery`)

   const offSettings={...settings,requesterEvents:{...enabled,[key]:false}}
   await api(ot,'/api/v1/notification-settings',{method:'PATCH',body:{settings:offSettings}})
   const offRef=`MATRIX-${key}-OFF-${Date.now()}`,offId=await emit(tenant.id,requester.id,eventType,targetType,offRef)
   const offDeliveries=await pool.query('SELECT channel FROM notification_deliveries WHERE notification_id=$1',[offId])
   assert.equal(offDeliveries.rowCount,0)
   const bellOff=await api(rt,'/api/v1/notifications?limit=250',{portal:true})
   assert(!bellOff.items.some(i=>i.id===offId),`${key} disabled must be hidden from bell`)
   const audit=await pool.query('SELECT id FROM platform_notifications WHERE id=$1',[offId])
   assert.equal(audit.rowCount,1)
   pass(`${targetType} ${key} disabled => audit retained, bell/email suppressed`)
  }
 }finally{
  await api(ot,'/api/v1/notification-settings',{method:'PATCH',body:{settings:prior}})
 }
 console.log('SUMMARY',JSON.stringify({classes:classes.length,checks:classes.length*2}))
}
main().catch(e=>{console.error('FAIL',e.stack||e);process.exitCode=1}).finally(async()=>pool.end())