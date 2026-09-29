import { hasPermission } from './access.js'
import { pool, withTransaction } from './db.js'
import { registerAssignmentRoutes } from './assignment.js'
import { registerItsmLifecycleRoutes } from './itsmLifecycle.js'
import { registerItsmQueueRoutes } from './itsmQueue.js'
import { registerItsmRecordRoutes } from './itsmRecords.js'
import { registerPortalAuthRoutes } from './portalAuth.js'
import { registerServiceRequestConditionalTaskRoutes } from './serviceRequestConditionalTasks.js'
import { registerServiceRequestFieldResolutionRoutes } from './serviceRequestFieldResolution.js'
import { registerServiceRequestFulfilmentRoutes } from './serviceRequestFulfilment.js'
import { registerServiceRequestOperationRoutes } from './serviceRequestOperations.js'
import { registerServiceRequestRoutes } from './serviceRequests.js'
import { registerServiceRequestStateRoutes } from './serviceRequestState.js'
import { registerTaskOwnershipRoutes } from './taskOwnership.js'
import { resolveSession } from './session.js'
import { originMatchesPortalTenant, originMatchesTenant } from './deploymentConfig.js'

const maxItems = 5000
const maxPayloadBytes = 4_000_000

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

function portalOrigin(c, slug) {
  return originMatchesPortalTenant(c.req.header('origin'), c.req.header('referer'), slug)
}

async function requireSession(c, write = false) {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesSession(c, session)) return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  if (write && !['owner', 'admin'].includes(session.tenant_role)) {
    return { error: c.json({ error: 'Tenant administrator access is required.' }, 403) }
  }
  return { session }
}

async function requirePortalCatalogueSession(c, slug) {
  const tenantSlug = validTenantSlug(slug)
  const session = await resolveSession(c)
  if (!tenantSlug || !session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (session.slug !== tenantSlug || !portalOrigin(c, tenantSlug)) return { error: c.json({ error: 'Portal session mismatch.' }, 403) }
  if (!hasPermission(session.access, 'portal.access')) return { error: c.json({ error: 'Requester Portal access is required.' }, 403) }
  if (!session.onboarding_completed_at) return { error: c.json({ error: 'This tenant has not completed setup.' }, 403) }
  return { session }
}

function text(value, max = 255) {
  return String(value ?? '').trim().slice(0, max)
}

function externalKey(value, fallback = 'CAT-ITEM') {
  const cleaned = text(value || fallback, 100)
    .toUpperCase()
    .replace(/[^A-Z0-9:_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
  return cleaned || fallback
}

function categoryKey(name) {
  return `CATEGORY-${externalKey(name, 'GENERAL').slice(0, 70)}`
}

function validTenantSlug(value) {
  const slug = String(value || '').trim().toLowerCase()
  return /^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/.test(slug) && !slug.includes('--') ? slug : ''
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function asSource(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value
  if (typeof value === 'string' && value.trim()) return { provider: value.trim() }
  return { provider: 'hi5central' }
}

function active(value) {
  return typeof value === 'boolean' ? value : true
}

function price(value) {
  const number = Number(value || 0)
  if (!Number.isFinite(number)) return 0
  return Math.max(0, Math.min(number, 999_999_999.99))
}

function nullablePrice(value) {
  if (value === '' || value === null || value === undefined) return null
  return price(value)
}

async function catalogueRows(tenantId, db = pool) {
  return db.query(
    `SELECT
       i.*,
       c.name AS category_name,
       t.name AS resolved_team_name
     FROM service_catalogue_items i
     LEFT JOIN service_catalogue_categories c ON c.id = i.category_id
     LEFT JOIN organisation_teams t ON t.id = i.fulfilment_team_id
     WHERE i.tenant_id = $1
     ORDER BY c.name NULLS LAST, i.title`,
    [tenantId],
  )
}

async function catalogueSnapshot(tenantId, db = pool) {
  const [categoryResult, itemResult] = await Promise.all([
    db.query(
      `SELECT id, external_key, name, sort_order, active
       FROM service_catalogue_categories
       WHERE tenant_id = $1
       ORDER BY sort_order, name`,
      [tenantId],
    ),
    catalogueRows(tenantId, db),
  ])

  return {
    initialized: categoryResult.rowCount > 0 || itemResult.rowCount > 0,
    categories: categoryResult.rows.filter((row) => row.active).map((row) => row.name),
    categoryRecords: categoryResult.rows.map((row) => ({
      id: row.external_key,
      databaseId: row.id,
      name: row.name,
      sortOrder: row.sort_order,
      active: row.active,
    })),
    items: itemResult.rows.map((row) => ({
      id: row.external_key,
      databaseId: row.id,
      title: row.title,
      category: row.category_name || 'Uncategorised',
      description: row.description,
      kind: row.kind,
      requestType: row.request_type,
      service: row.service,
      team: row.resolved_team_name || row.fulfilment_team_name,
      approval: row.approval_mode,
      approvalThreshold: row.approval_threshold === null ? null : Number(row.approval_threshold),
      visibility: row.visibility,
      vendor: row.vendor,
      sku: row.sku,
      priceMode: row.price_mode,
      oneOffPrice: Number(row.one_off_price || 0),
      monthlyPrice: Number(row.monthly_price || 0),
      currency: row.currency,
      workflow: row.workflow_key,
      formSchema: asArray(row.form_schema),
      options: asArray(row.options),
      source: row.source || {},
      active: row.active,
    })),
  }
}

function portalProductOption(option, productRows) {
  const itemId = externalKey(option?.itemId || '', '')
  if (!itemId) return option
  const product = productRows.get(itemId)
  if (!product || !product.active || product.visibility !== 'portal') return null

  const monthly = Number(product.monthly_price || 0)
  const oneOff = Number(product.one_off_price || 0)
  return {
    ...option,
    itemId: product.external_key,
    value: option?.value || product.title,
    label: product.title,
    category: product.category_name || option?.category || 'Uncategorised',
    cost: monthly > 0 ? monthly : oneOff,
    recurring: monthly > 0 ? 'monthly' : '',
  }
}

function portalFields(row, productRows) {
  return asArray(row.form_schema).map((rawField) => {
    const field = asObject(rawField)
    if (!['product', 'checkbox-products'].includes(field.type) || field.source === 'catalogue-products') return field
    return {
      ...field,
      options: asArray(field.options)
        .map((option) => portalProductOption(asObject(option), productRows))
        .filter(Boolean),
    }
  })
}

async function publicPortalCatalogue(slug) {
  const tenantSlug = validTenantSlug(slug)
  if (!tenantSlug) return null

  const tenantResult = await pool.query(
    `SELECT t.id, t.slug, t.company_name, ts.modules
     FROM tenants t
     JOIN tenant_settings ts ON ts.tenant_id = t.id
     WHERE t.slug = $1 AND t.status = 'active'
     LIMIT 1`,
    [tenantSlug],
  )
  if (!tenantResult.rowCount) return null

  const tenant = tenantResult.rows[0]
  if (!asObject(tenant.modules).itsm) return null

  const itemResult = await catalogueRows(tenant.id)
  const publicRows = itemResult.rows.filter((row) => row.active && row.visibility === 'portal')
  const productRows = new Map(
    publicRows
      .filter((row) => row.kind === 'product')
      .map((row) => [row.external_key, row]),
  )
  const requestRows = publicRows.filter((row) => row.kind === 'request-form')

  const items = requestRows.map((row) => ({
    id: row.external_key,
    title: row.title,
    category: row.category_name || 'Uncategorised',
    description: row.description,
    requestType: row.request_type || 'Service Request',
    service: row.service || 'Service Catalogue',
    team: row.resolved_team_name || row.fulfilment_team_name || 'Service Desk',
    basePriority: 'Medium',
    approval: row.approval_mode || 'none',
    approvalThreshold: row.approval_threshold === null ? null : Number(row.approval_threshold),
    fields: portalFields(row, productRows),
  }))

  return {
    managed: true,
    tenant: { slug: tenant.slug, companyName: tenant.company_name },
    categories: [...new Set(items.map((item) => item.category))],
    items,
  }
}

async function portalLookupOptions(tenantId) {
  const [people, departments, sites, teams, products] = await Promise.all([
    pool.query(
      `SELECT external_key, name, job_title
       FROM organisation_people
       WHERE tenant_id = $1 AND active = true
       ORDER BY name`,
      [tenantId],
    ),
    pool.query(
      `SELECT external_key, name
       FROM organisation_departments
       WHERE tenant_id = $1 AND active = true
       ORDER BY name`,
      [tenantId],
    ),
    pool.query(
      `SELECT external_key, name, type
       FROM organisation_sites
       WHERE tenant_id = $1 AND active = true
       ORDER BY name`,
      [tenantId],
    ),
    pool.query(
      `SELECT external_key, name
       FROM organisation_teams
       WHERE tenant_id = $1 AND active = true
       ORDER BY name`,
      [tenantId],
    ),
    pool.query(
      `SELECT i.external_key, i.title, i.one_off_price, i.monthly_price, i.currency, c.name AS category_name
       FROM service_catalogue_items i
       LEFT JOIN service_catalogue_categories c ON c.id = i.category_id
       WHERE i.tenant_id = $1 AND i.active = true AND i.visibility = 'portal' AND i.kind = 'product'
       ORDER BY c.name NULLS LAST, i.title`,
      [tenantId],
    ),
  ])

  return {
    people: people.rows.map((row) => ({ value: row.external_key, label: row.name, detail: row.job_title || '' })),
    departments: departments.rows.map((row) => ({ value: row.external_key, label: row.name })),
    sites: sites.rows.map((row) => ({ value: row.external_key, label: row.name, detail: row.type || '' })),
    teams: teams.rows.map((row) => ({ value: row.external_key, label: row.name })),
    products: products.rows.map((row) => ({
      value: row.external_key,
      itemId: row.external_key,
      label: row.title,
      category: row.category_name || 'Uncategorised',
      cost: Number(row.monthly_price || 0) > 0 ? Number(row.monthly_price) : Number(row.one_off_price || 0),
      recurring: Number(row.monthly_price || 0) > 0 ? 'monthly' : '',
      currency: row.currency || 'GBP',
    })),
  }
}

async function upsertCatalogue(client, tenantId, categories, items) {
  const names = [...new Set([
    ...categories.map((value) => text(value, 120)).filter(Boolean),
    ...items.map((item) => text(item?.category || 'Uncategorised', 120)).filter(Boolean),
  ])]

  for (let index = 0; index < names.length; index += 1) {
    const name = names[index]
    await client.query(
      `INSERT INTO service_catalogue_categories
         (tenant_id, external_key, name, sort_order, active, updated_at)
       VALUES ($1, $2, $3, $4, true, now())
       ON CONFLICT (tenant_id, external_key) DO UPDATE SET
         name = EXCLUDED.name,
         sort_order = EXCLUDED.sort_order,
         active = true,
         updated_at = now()`,
      [tenantId, categoryKey(name), name, index],
    )
  }

  if (names.length) {
    await client.query(
      `UPDATE service_catalogue_categories
       SET active = false, updated_at = now()
       WHERE tenant_id = $1 AND NOT (name = ANY($2::text[]))`,
      [tenantId, names],
    )
  }

  const [categoryRows, teamRows] = await Promise.all([
    client.query('SELECT id, name FROM service_catalogue_categories WHERE tenant_id = $1', [tenantId]),
    client.query('SELECT id, name FROM organisation_teams WHERE tenant_id = $1 AND active = true', [tenantId]),
  ])
  const categoryIds = new Map(categoryRows.rows.map((row) => [row.name, row.id]))
  const teamIds = new Map(teamRows.rows.map((row) => [row.name, row.id]))

  for (const item of items) {
    const id = externalKey(item?.id, `CAT-${Date.now()}`)
    const category = text(item?.category || 'Uncategorised', 120)
    const kind = item?.kind === 'request-form' ? 'request-form' : 'product'
    const visibility = ['portal', 'technicians', 'hidden'].includes(item?.visibility) ? item.visibility : 'portal'
    const priceMode = ['none', 'fixed', 'calculated'].includes(item?.priceMode) ? item.priceMode : 'none'
    const teamName = text(item?.team, 120)

    await client.query(
      `INSERT INTO service_catalogue_items (
         tenant_id, external_key, category_id, title, description, kind, request_type, service,
         fulfilment_team_id, fulfilment_team_name, approval_mode, approval_threshold, visibility,
         vendor, sku, price_mode, one_off_price, monthly_price, currency, workflow_key,
         form_schema, options, source, active, updated_at
       ) VALUES (
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
         $21::jsonb,$22::jsonb,$23::jsonb,$24,now()
       )
       ON CONFLICT (tenant_id, external_key) DO UPDATE SET
         category_id = EXCLUDED.category_id,
         title = EXCLUDED.title,
         description = EXCLUDED.description,
         kind = EXCLUDED.kind,
         request_type = EXCLUDED.request_type,
         service = EXCLUDED.service,
         fulfilment_team_id = EXCLUDED.fulfilment_team_id,
         fulfilment_team_name = EXCLUDED.fulfilment_team_name,
         approval_mode = EXCLUDED.approval_mode,
         approval_threshold = EXCLUDED.approval_threshold,
         visibility = EXCLUDED.visibility,
         vendor = EXCLUDED.vendor,
         sku = EXCLUDED.sku,
         price_mode = EXCLUDED.price_mode,
         one_off_price = EXCLUDED.one_off_price,
         monthly_price = EXCLUDED.monthly_price,
         currency = EXCLUDED.currency,
         workflow_key = EXCLUDED.workflow_key,
         form_schema = EXCLUDED.form_schema,
         options = EXCLUDED.options,
         source = EXCLUDED.source,
         active = EXCLUDED.active,
         updated_at = now()`,
      [
        tenantId,
        id,
        categoryIds.get(category) || null,
        text(item?.title, 180),
        text(item?.description, 5000),
        kind,
        text(item?.requestType || 'Service Request', 80),
        text(item?.service || 'Service Catalogue', 120),
        teamIds.get(teamName) || null,
        teamName,
        text(item?.approval || 'none', 80),
        nullablePrice(item?.approvalThreshold),
        visibility,
        text(item?.vendor, 160),
        text(item?.sku, 160),
        priceMode,
        price(item?.oneOffPrice),
        price(item?.monthlyPrice),
        text(item?.currency || 'GBP', 3).toUpperCase() || 'GBP',
        text(item?.workflow, 180),
        JSON.stringify(asArray(item?.formSchema)),
        JSON.stringify(asArray(item?.options)),
        JSON.stringify(asSource(item?.source)),
        active(item?.active),
      ],
    )
  }

  if (items.length) {
    await client.query(
      `UPDATE service_catalogue_items
       SET active = false, updated_at = now()
       WHERE tenant_id = $1 AND NOT (external_key = ANY($2::text[]))`,
      [tenantId, items.map((item) => externalKey(item?.id))],
    )
  }
}

export function registerCatalogueRoutes(app) {
  app.get('/api/v1/portal/catalogue/:slug', async (c) => {
    const payload = await publicPortalCatalogue(c.req.param('slug'))
    if (!payload) return c.json({ managed: false, items: [] }, 404)
    return c.json(payload)
  })

  app.get('/api/v1/portal/catalogue/:slug/options', async (c) => {
    const auth = await requirePortalCatalogueSession(c, c.req.param('slug'))
    if (auth.error) return auth.error
    return c.json(await portalLookupOptions(auth.session.tenant_id))
  })

  app.get('/api/v1/catalogue', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error
    return c.json(await catalogueSnapshot(auth.session.tenant_id))
  })

  app.put('/api/v1/catalogue', async (c) => {
    const auth = await requireSession(c, true)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const categories = asArray(body?.categories)
    const items = asArray(body?.items)
    if (categories.length > 1000 || items.length > maxItems) {
      return c.json({ error: 'Service catalogue snapshot is too large.' }, 413)
    }
    if (JSON.stringify({ categories, items }).length > maxPayloadBytes) {
      return c.json({ error: 'Service catalogue snapshot is too large.' }, 413)
    }

    await withTransaction(async (client) => {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1::text))', [`catalogue:${auth.session.tenant_id}`])
      await upsertCatalogue(client, auth.session.tenant_id, categories, items)
    })

    return c.json(await catalogueSnapshot(auth.session.tenant_id))
  })

  registerAssignmentRoutes(app)
  registerPortalAuthRoutes(app)
  registerServiceRequestConditionalTaskRoutes(app)
  registerServiceRequestFulfilmentRoutes(app)
  registerServiceRequestFieldResolutionRoutes(app)
  registerServiceRequestRoutes(app)
  registerServiceRequestOperationRoutes(app)
  registerServiceRequestStateRoutes(app)
  registerTaskOwnershipRoutes(app)
  registerItsmRecordRoutes(app)
  registerItsmLifecycleRoutes(app)
  registerItsmQueueRoutes(app)
}
