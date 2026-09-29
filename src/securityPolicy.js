const allowedSessionHours = new Set([8, 12, 24])
const MFA_GRACE_MINUTES = 15

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

export function effectiveConfiguration(row) {
  if (row?.configuration && Object.keys(row.configuration).length) return row.configuration
  return row?.onboarding_data || {}
}

export function securitySettings(row) {
  const security = asObject(effectiveConfiguration(row).security)
  const requestedHours = Number(security.sessionHours || 12)
  const sessionHours = allowedSessionHours.has(requestedHours) ? requestedHours : 12

  return {
    requireMfa: Boolean(security.requireMfa),
    sessionHours,
    passwordPolicy: security.passwordPolicy === 'standard' ? 'standard' : 'strong',
    auditRetention: ['90', '365', '730'].includes(String(security.auditRetention || '365'))
      ? String(security.auditRetention || '365')
      : '365',
    mfaEnforcedAt: security.mfaEnforcedAt || null,
  }
}

export function mfaRequiredFor(row) {
  if (!row?.onboarding_completed_at) return false
  const security = securitySettings(row)
  return security.requireMfa && ['owner', 'admin'].includes(row.tenant_role)
}

export function sessionTtlSeconds(row) {
  return securitySettings(row).sessionHours * 60 * 60
}

export function mfaGraceEndsAt(row) {
  if (!mfaRequiredFor(row)) return null
  const security = securitySettings(row)
  const enforcedAt = security.mfaEnforcedAt || row.onboarding_completed_at
  if (!enforcedAt) return null
  const timestamp = new Date(enforcedAt).getTime()
  if (!Number.isFinite(timestamp)) return null
  return new Date(timestamp + MFA_GRACE_MINUTES * 60 * 1000)
}

export function sessionNeedsMfa(row, now = new Date()) {
  if (!mfaRequiredFor(row)) return false
  if (row?.mfa_verified_at) return false

  const graceEndsAt = mfaGraceEndsAt(row)
  if (!graceEndsAt) return true

  const sessionCreatedAt = row?.session_created_at || row?.created_at
  const enforcedAt = securitySettings(row).mfaEnforcedAt || row.onboarding_completed_at
  const createdBeforeEnforcement = sessionCreatedAt && enforcedAt
    ? new Date(sessionCreatedAt).getTime() <= new Date(enforcedAt).getTime()
    : false

  return !(createdBeforeEnforcement && now.getTime() < graceEndsAt.getTime())
}
