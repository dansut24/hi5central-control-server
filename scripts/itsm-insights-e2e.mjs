import assert from 'node:assert/strict'
import { pool } from '../src/db.js'
import { createSession } from '../src/session.js'

const ORIGIN = process.env.E2E_ORIGIN || 'https://itsm.cutover.hi5central.com'
const API = process.env.E2E_API || 'http://127.0.0.1:3001'
const SLUG = 'test2'

async function api(token, path, options = {}) {
  const response = await fetch(API + path, {
    method: options.method || 'GET',
    headers: {
      Origin: ORIGIN,
      Cookie: `hi5central_session=${token}`,
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  })
  const text = await response.text()
  const payload = text ? JSON.parse(text) : {}
  const expected = options.expect || 200
  if (response.status !== expected) throw new Error(`${options.method || 'GET'} ${path} -> ${response.status}: ${text}`)
  return payload
}
function pass(name) { console.log('PASS ', name) }

async function main() {
  const tenant = (await pool.query('SELECT id FROM tenants WHERE slug=$1 LIMIT 1', [SLUG])).rows[0]
  const users = await pool.query(
    `SELECT u.id,u.email,m.role FROM users u JOIN tenant_memberships m ON m.user_id=u.id AND m.tenant_id=$1
     WHERE lower(u.email)=ANY($2::text[])`,
    [tenant.id, ['danielsuttonsamsung@gmail.com','danieljamessutton18+user1@outlook.com','danieljamessutton18@outlook.com']],
  )
  const owner = users.rows.find((row) => row.email === 'danielsuttonsamsung@gmail.com')
  const analyst = users.rows.find((row) => row.email === 'danieljamessutton18+user1@outlook.com')
  const requester = users.rows.find((row) => row.email === 'danieljamessutton18@outlook.com')
  assert(owner && analyst && requester)
  const ownerToken = await createSession(pool,{tenantId:tenant.id,userId:owner.id,mfaVerified:true,ttlSeconds:3600,surface:'workspace'})
  const analystToken = await createSession(pool,{tenantId:tenant.id,userId:analyst.id,mfaVerified:true,ttlSeconds:3600,surface:'workspace'})
  const requesterToken = await createSession(pool,{tenantId:tenant.id,userId:requester.id,mfaVerified:true,ttlSeconds:3600,surface:'portal'})

  const view = await api(ownerToken,'/api/v1/itsm/saved-views',{method:'POST',expect:201,body:{
    recordType:'Incident',name:'E2E urgent incidents',query:'overnight',
    filters:{priority:'High',status:'All',team:'All',assignee:'All',service:'All',__view:'custom'},
    viewStyle:'table',columns:{hidden:['service']},
  }})
  assert(view.id && view.name === 'E2E urgent incidents')
  pass('owner saved a production ITSM view')

  const ownerViews = await api(ownerToken,'/api/v1/itsm/saved-views?type=Incident')
  assert(ownerViews.items.some((item) => item.id === view.id))
  pass('saved view persists and reloads from PostgreSQL')

  await api(analystToken,'/api/v1/itsm/saved-views',{method:'POST',expect:403,body:{
    recordType:'Incident',name:'Shared denied',visibility:'shared',filters:{},viewStyle:'table',
  }})
  pass('analyst cannot publish shared saved views')

  const shared = await api(ownerToken,'/api/v1/itsm/saved-views',{method:'POST',expect:201,body:{
    recordType:'Incident',name:'E2E shared incidents',visibility:'shared',filters:{status:'All'},viewStyle:'compact',
  }})
  const analystViews = await api(analystToken,'/api/v1/itsm/saved-views?type=Incident')
  assert(analystViews.items.some((item) => item.id === shared.id && item.visibility === 'shared'))
  pass('shared saved view is visible to another technician')

  const summary = await api(ownerToken,'/api/v1/itsm/reports/summary')
  assert(summary.total > 0)
  assert(summary.byType?.Incident >= 1)
  assert(Array.isArray(summary.workload) && Array.isArray(summary.trend))
  assert(summary.sla && Number.isInteger(summary.sla.breached))
  pass('server-side ITSM report summary returns production counts and SLA metrics')

  await api(requesterToken,'/api/v1/itsm/reports/summary',{expect:401})
  pass('requester portal session cannot access technician reporting')

  await api(ownerToken,`/api/v1/itsm/saved-views/${view.id}`,{method:'DELETE'})
  await api(ownerToken,`/api/v1/itsm/saved-views/${shared.id}`,{method:'DELETE'})
  const after = await api(ownerToken,'/api/v1/itsm/saved-views?type=Incident')
  assert(!after.items.some((item) => item.id === view.id || item.id === shared.id))
  pass('saved views delete cleanly')

  console.log('SUMMARY',JSON.stringify({checks:7,total:summary.total,sla:summary.sla}))
}
main().catch((error)=>{console.error('FAIL',error.stack||error);process.exitCode=1}).finally(()=>pool.end())