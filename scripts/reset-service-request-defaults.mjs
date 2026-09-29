import { pool, withTransaction } from '../src/db.js'
import { defaultCatalogueState } from '../../src/data/defaultCatalogueV2.js'

const tenantSlug = String(process.env.TENANT_SLUG || process.argv[2] || '').trim().toLowerCase()

if (!tenantSlug) {
  console.error('Usage: TENANT_SLUG=<tenant-slug> npm run reset:service-requests')
  process.exitCode = 1
} else {
  await resetTenant(tenantSlug)
}

async function resetTenant(slug) {
  try {
    const summary = await withTransaction(async (client) => {
      const tenantResult = await client.query(
        `SELECT id, slug, company_name
         FROM tenants
         WHERE slug = $1 AND status = 'active'
         LIMIT 1
         FOR UPDATE`,
        [slug],
      )
      if (!tenantResult.rowCount) throw new Error(`Active tenant not found: ${slug}`)
      const tenant = tenantResult.rows[0]
      const tenantId = tenant.id

      await client.query('SELECT pg_advisory_xact_lock(hashtext($1::text))', [`service-request-reset:${tenantId}`])

      const notificationsDeleted = (await client.query(
        `DELETE FROM platform_notifications
         WHERE tenant_id = $1 AND target_type = 'Service Request'`,
        [tenantId],
      )).rowCount

      const eventsDeleted = (await client.query(
        `DELETE FROM domain_events
         WHERE tenant_id = $1 AND aggregate_type = 'Service Request'`,
        [tenantId],
      )).rowCount

      const workflowApprovalsDeleted = (await client.query(
        `DELETE FROM workflow_approvals
         WHERE tenant_id = $1 AND record_type = 'Service Request'`,
        [tenantId],
      )).rowCount

      const requestsDeleted = (await client.query(
        'DELETE FROM service_requests WHERE tenant_id = $1',
        [tenantId],
      )).rowCount

      const flowsDeleted = (await client.query(
        'DELETE FROM service_catalogue_fulfilment_flows WHERE tenant_id = $1',
        [tenantId],
      )).rowCount

      const formsDeleted = (await client.query(
        `DELETE FROM service_catalogue_items
         WHERE tenant_id = $1
           AND kind = 'request-form'
           AND request_type = 'Service Request'`,
        [tenantId],
      )).rowCount

      await client.query(
        `DELETE FROM tenant_record_counters
         WHERE tenant_id = $1 AND record_type = 'service_request'`,
        [tenantId],
      )

      const teamResult = await client.query(
        `SELECT id, external_key, name
         FROM organisation_teams
         WHERE tenant_id = $1 AND active = true
         ORDER BY CASE WHEN lower(name) = 'service desk' THEN 0 ELSE 1 END, name`,
        [tenantId],
      )
      const teams = teamResult.rows
      const teamByName = new Map(teams.map((team) => [team.name.toLowerCase(), team]))
      const defaultTeam = teamByName.get('service desk') || teams[0] || null

      const defaults = defaultCatalogueState().items
        .filter((item) => item.kind === 'request-form' && item.requestType === 'Service Request')
        .map((item) => ({ ...item, visibility: 'portal', active: true }))

      const categoryNames = [...new Set(defaults.map((item) => item.category).filter(Boolean))]
      for (let index = 0; index < categoryNames.length; index += 1) {
        const name = categoryNames[index]
        const externalKey = `CATEGORY-${key(name).slice(0, 70)}`
        await client.query(
          `INSERT INTO service_catalogue_categories
             (tenant_id, external_key, name, sort_order, active, updated_at)
           VALUES ($1,$2,$3,$4,true,now())
           ON CONFLICT (tenant_id, external_key) DO UPDATE SET
             name = EXCLUDED.name,
             active = true,
             updated_at = now()`,
          [tenantId, externalKey, name, index],
        )
      }

      const categoryResult = await client.query(
        `SELECT id, name
         FROM service_catalogue_categories
         WHERE tenant_id = $1`,
        [tenantId],
      )
      const categoryByName = new Map(categoryResult.rows.map((row) => [row.name, row.id]))

      for (const item of defaults) {
        const requestedTeam = teamByName.get(String(item.team || '').toLowerCase()) || defaultTeam
        const teamName = requestedTeam?.name || item.team || 'Service Desk'

        await client.query(
          `INSERT INTO service_catalogue_items (
             tenant_id, external_key, category_id, title, description, kind, request_type, service,
             fulfilment_team_id, fulfilment_team_name, approval_mode, approval_threshold, visibility,
             vendor, sku, price_mode, one_off_price, monthly_price, currency, workflow_key,
             form_schema, options, source, active, updated_at
           ) VALUES (
             $1,$2,$3,$4,$5,'request-form','Service Request',$6,$7,$8,$9,$10,'portal',
             $11,$12,$13,$14,$15,$16,$17,$18::jsonb,$19::jsonb,$20::jsonb,true,now()
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
             visibility = 'portal',
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
             active = true,
             updated_at = now()`,
          [
            tenantId,
            item.id,
            categoryByName.get(item.category) || null,
            item.title,
            item.description || '',
            item.service || 'Service Catalogue',
            requestedTeam?.id || null,
            teamName,
            item.approval || 'none',
            item.approvalThreshold ?? null,
            item.vendor || '',
            item.sku || '',
            item.priceMode || 'none',
            Number(item.oneOffPrice || 0),
            Number(item.monthlyPrice || 0),
            item.currency || 'GBP',
            item.workflow || '',
            JSON.stringify(item.formSchema || []),
            JSON.stringify(item.options || []),
            JSON.stringify(item.source || { provider: 'hi5central' }),
          ],
        )

        const routedTasks = (item.workflowTasks || []).map((task) => {
          const taskTeam = teamByName.get(String(task.team || '').toLowerCase()) || requestedTeam || defaultTeam
          return {
            ...task,
            team: taskTeam?.name || task.team || teamName,
            teamId: taskTeam?.external_key || '',
          }
        })

        await client.query(
          `INSERT INTO service_catalogue_fulfilment_flows
             (tenant_id, catalogue_item_key, tasks, updated_by_user_id, updated_at)
           VALUES ($1,$2,$3::jsonb,NULL,now())
           ON CONFLICT (tenant_id, catalogue_item_key) DO UPDATE SET
             tasks = EXCLUDED.tasks,
             updated_by_user_id = NULL,
             updated_at = now()`,
          [tenantId, item.id, JSON.stringify(routedTasks)],
        )
      }

      return {
        tenant: `${tenant.company_name} (${tenant.slug})`,
        requestsDeleted,
        formsDeleted,
        flowsDeleted,
        workflowApprovalsDeleted,
        eventsDeleted,
        notificationsDeleted,
        defaultsAdded: defaults.length,
        defaultTeam: defaultTeam?.name || 'No active team available',
      }
    })

    console.log(JSON.stringify(summary, null, 2))
  } finally {
    await pool.end()
  }
}

function key(value) {
  return String(value || '')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9:_-]+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '') || 'GENERAL'
}
