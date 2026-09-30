import { pool } from './db.js'

function object(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

export async function itsmConfigurationFor(tenantId, db = pool) {
  const result = await db.query(
    'SELECT configuration,onboarding_data FROM tenant_settings WHERE tenant_id=$1 LIMIT 1',
    [tenantId],
  )
  const row = result.rows[0] || {}
  const configuration = row.configuration && Object.keys(row.configuration).length
    ? row.configuration
    : (row.onboarding_data || {})
  return object(object(configuration).itsm)
}

export async function attachmentPolicyFor(tenantId, db = pool) {
  const itsm = await itsmConfigurationFor(tenantId, db)
  const attachments = object(itsm.attachments)
  const configuredMax = Number(attachments.maxMb || 5)
  const maxMb = Number.isFinite(configuredMax)
    ? Math.max(1, Math.min(20, Math.round(configuredMax)))
    : 5
  return {
    maxMb,
    maxBytes: maxMb * 1024 * 1024,
    requesterUploads: attachments.requesterUploads !== false,
    internalAttachments: attachments.internalAttachments !== false,
  }
}