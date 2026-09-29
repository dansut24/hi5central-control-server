import { pool } from './db.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { resolveSession } from './session.js'

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function responseHeaders(response) {
  const headers = new Headers(response.headers)
  headers.set('content-type', 'application/json; charset=UTF-8')
  headers.delete('content-length')
  return headers
}

function replaceJsonResponse(c, payload) {
  c.res = new Response(JSON.stringify(payload), {
    status: c.res.status,
    statusText: c.res.statusText,
    headers: responseHeaders(c.res),
  })
}

function visibleField(field, values) {
  const condition = asObject(field?.showWhen)
  if (!condition.field) return true
  const current = values[condition.field]
  if (Object.prototype.hasOwnProperty.call(condition, 'equals')) return current === condition.equals
  if (Array.isArray(condition.oneOf)) return condition.oneOf.includes(current)
  return true
}

async function lookupMaps(tenantId) {
  const [people, departments, sites, teams, products] = await Promise.all([
    pool.query('SELECT external_key,name FROM organisation_people WHERE tenant_id=$1 AND active=true', [tenantId]),
    pool.query('SELECT external_key,name FROM organisation_departments WHERE tenant_id=$1 AND active=true', [tenantId]),
    pool.query('SELECT external_key,name FROM organisation_sites WHERE tenant_id=$1 AND active=true', [tenantId]),
    pool.query('SELECT external_key,name FROM organisation_teams WHERE tenant_id=$1 AND active=true', [tenantId]),
    pool.query("SELECT external_key,title FROM service_catalogue_items WHERE tenant_id=$1 AND active=true AND kind='product'", [tenantId]),
  ])
  return {
    people: new Map(people.rows.map((row) => [row.external_key, row.name])),
    departments: new Map(departments.rows.map((row) => [row.external_key, row.name])),
    sites: new Map(sites.rows.map((row) => [row.external_key, row.name])),
    teams: new Map(teams.rows.map((row) => [row.external_key, row.name])),
    'catalogue-products': new Map(products.rows.map((row) => [row.external_key, row.title])),
  }
}

function resolvedValue(field, raw, maps) {
  if (raw === undefined || raw === null || raw === '') return ''
  const source = text(field?.source, 80)
  const map = maps[source]
  if (!map) return Array.isArray(raw) ? raw.join(', ') : String(raw)
  if (Array.isArray(raw)) return raw.map((value) => map.get(String(value)) || String(value)).join(', ')
  return map.get(String(raw)) || String(raw)
}

async function resolvedInformation(tenantId, catalogueItemId, values) {
  const result = await pool.query(
    `SELECT form_schema
     FROM service_catalogue_items
     WHERE tenant_id=$1 AND external_key=$2
     LIMIT 1`,
    [tenantId, text(catalogueItemId, 100).toUpperCase()],
  )
  const schema = asArray(result.rows[0]?.form_schema)
  const maps = await lookupMaps(tenantId)
  return schema
    .filter((field) => field?.type !== 'section' && visibleField(field, values))
    .map((field) => {
      const value = resolvedValue(field, values[field.id], maps)
      return value ? { label: text(field.label || field.id, 180), value: text(value, 4000) } : null
    })
    .filter(Boolean)
}

async function resolveSubmittedLookupSnapshots(c, next) {
  if (c.req.method.toUpperCase() !== 'POST' || c.req.path !== '/api/v1/service-requests') return next()
  const session = await resolveSession(c)
  if (!session) return next()
  const origin = c.req.header('origin') || ''
  const referer = c.req.header('referer') || ''
  const workspaceOrigin = originMatchesTenant(origin, session.slug)
  const portalOrigin = origin.includes(`${session.slug}-portal.`) || referer.includes(`${session.slug}-portal.`)
  if (!workspaceOrigin && !portalOrigin) return next()

  let body = null
  try { body = await c.req.raw.clone().json() } catch { body = null }
  await next()
  if (!body || !c.res || c.res.status !== 201) return

  let payload = null
  try { payload = await c.res.clone().json() } catch { payload = null }
  if (!payload?.reference || !body.catalogueItemId) return

  const information = await resolvedInformation(session.tenant_id, body.catalogueItemId, asObject(body.fields))
  await pool.query(
    `UPDATE service_requests
     SET request_information=$3::jsonb, updated_at=updated_at
     WHERE tenant_id=$1 AND reference=$2`,
    [session.tenant_id, payload.reference, JSON.stringify(information)],
  )
  payload.requestInformation = information
  replaceJsonResponse(c, payload)
}

export function registerServiceRequestFieldResolutionRoutes(app) {
  app.use('/api/v1/service-requests', resolveSubmittedLookupSnapshots)
}
