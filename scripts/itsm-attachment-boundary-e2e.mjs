import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'
const BASE=process.env.E2E_BASE_URL||'http://127.0.0.1:3001'
const ORIGIN=process.env.E2E_ORIGIN||'https://itsm.cutover.hi5central.com'
const OWNER='danielsuttonsamsung@gmail.com'
const REQUESTER='danieljamessutton18@outlook.com'
function pass(x){console.log('PASS ',x)}
async function call(token,path,{method='GET',body,expect=200,portal=false,raw=false}={}){
 const res=await fetch(BASE+path,{method,headers:{Origin:ORIGIN,...(portal?{Referer:`${ORIGIN}/portal`}:{}),Cookie:`${portal?'hi5central_portal_session':'hi5central_session'}=${token}`,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body)})
 if(raw){assert.equal(res.status,expect);return res}
 const text=await res.text();let payload={};try{payload=text?JSON.parse(text):{}}catch{payload=text}
 assert.equal(res.status,expect,`${method} ${path} expected ${expect}, got ${res.status}: ${text}`);return payload
}
async function ctx(slug,email){
 const tenant=(await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1',[slug])).rows[0]
 const row=(await pool.query(`SELECT u.id,p.external_key,p.email FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1 LEFT JOIN organisation_people p ON p.user_id=u.id AND p.tenant_id=$1 AND lower(p.email)=lower($2) WHERE lower(u.email)=lower($2) LIMIT 1`,[tenant.id,email])).rows[0]
 return{tenant,row}
}
async function main(){
 const o=await ctx('test2',OWNER),r=await ctx('test2',REQUESTER),x=await ctx('testcustomer',REQUESTER)
 const ot=await createSession(pool,{tenantId:o.tenant.id,userId:o.row.id,mfaVerified:true,ttlSeconds:3600,surface:'workspace'})
 const rt=await createSession(pool,{tenantId:r.tenant.id,userId:r.row.id,mfaVerified:true,ttlSeconds:3600,surface:'portal'})
 const xt=await createSession(pool,{tenantId:x.tenant.id,userId:x.row.id,mfaVerified:true,ttlSeconds:3600,surface:'workspace'})
 const stamp=new Date().toISOString()
 const inc=await call(ot,'/api/v1/itsm-records',{method:'POST',expect:201,body:{type:'Incident',title:`Attachment boundary ${stamp}`,requesterId:r.row.external_key}})
 const created=await call(ot,`/api/v1/itsm-lifecycle/${inc.id}/attachments`,{method:'POST',expect:201,body:{fileName:'folder-name-test.txt',mimeType:'text/plain',contentBase64:Buffer.from('safe').toString('base64')}})
 const att=created.attachments[0];assert(att?.id)
 const download=await call(ot,`/api/v1/itsm-lifecycle/${inc.id}/attachments/${att.id}`,{raw:true})
 assert.equal(Buffer.from(await download.arrayBuffer()).toString(),'safe')
 pass('generic attachment round-trips')
 await call(xt,`/api/v1/itsm-lifecycle/${inc.id}/attachments/${att.id}`,{expect:404})
 await call(rt,`/api/v1/itsm-lifecycle/${inc.id}/attachments/${att.id}`,{expect:403,portal:true})
 pass('generic attachment blocks cross-tenant and requester direct access')
 const oversized=Buffer.alloc(5*1024*1024+1,1).toString('base64')
 await call(ot,`/api/v1/itsm-lifecycle/${inc.id}/attachments`,{method:'POST',expect:413,body:{fileName:'too-large.bin',contentBase64:oversized}})
 pass('generic attachment enforces 5 MB limit')
 await call(ot,`/api/v1/itsm-lifecycle/${inc.id}/attachments/remove`,{method:'POST',body:{attachmentId:att.id}})
 await call(ot,`/api/v1/itsm-lifecycle/${inc.id}/attachments/${att.id}`,{expect:404})
 pass('deleted generic attachment returns 404')

 const req=await call(ot,'/api/v1/service-requests',{method:'POST',expect:201,body:{catalogueItemId:'CAT-GENERAL',summary:`Attachment SR ${stamp}`,requesterPersonId:r.row.external_key,fields:{requestType:'Advice',requestDetails:'Attachment boundary validation.'},details:{text:'Attachment test.'}}})
 const internal=await call(ot,`/api/v1/service-requests/${req.id}/attachments`,{method:'POST',expect:201,body:{fileName:'internal.txt',mimeType:'text/plain',visibility:'internal',contentBase64:Buffer.from('secret').toString('base64')}})
 await call(rt,`/api/v1/service-requests/${req.id}/attachments/${internal.id}`,{expect:404,portal:true})
 pass('requester cannot read internal Service Request attachment')
 const customer=await call(rt,`/api/v1/service-requests/${req.id}/attachments`,{method:'POST',expect:201,portal:true,body:{fileName:'customer.txt',mimeType:'text/plain',visibility:'internal',contentBase64:Buffer.from('customer').toString('base64')}})
 assert.equal(customer.visibility,'customer')
 const customerDownload=await call(rt,`/api/v1/service-requests/${req.id}/attachments/${customer.id}`,{portal:true,raw:true})
 assert.equal(Buffer.from(await customerDownload.arrayBuffer()).toString(),'customer')
 pass('requester upload is forced customer-visible and remains downloadable')
 await call(xt,`/api/v1/service-requests/${req.id}/attachments/${customer.id}`,{expect:404})
 await call(ot,`/api/v1/service-requests/${req.id}/attachments/remove`,{method:'POST',body:{attachmentId:customer.id}})
 await call(ot,`/api/v1/service-requests/${req.id}/attachments/${customer.id}`,{expect:404})
 pass('Service Request attachment blocks cross-tenant access and stale URLs')
 console.log('SUMMARY',JSON.stringify({incident:inc.id,serviceRequest:req.id,checks:6}))
}
main().catch(e=>{console.error('FAIL',e.stack||e);process.exitCode=1}).finally(async()=>pool.end())