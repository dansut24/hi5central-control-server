import { originMatchesTenant } from './deploymentConfig.js'
import { pool } from './db.js'
import { resolveSession } from './session.js'

const ALLOWED_THEME = new Set(['system', 'light', 'dark'])
const ALLOWED_ACCENT = new Set(['amber', 'cyan', 'blue', 'violet', 'emerald', 'rose'])
const ALLOWED_DENSITY = new Set(['comfortable', 'compact'])
const ALLOWED_SIDE = new Set(['left', 'right'])
const ALLOWED_STYLE = new Set(['floating', 'clean'])
const ALLOWED_MODE = new Set(['expanded', 'collapsed', 'hidden'])

function originMatchesSession(c, session) {
  return originMatchesTenant(c.req.header('origin'), session.slug)
}

async function requireSession(c) {
  const session = await resolveSession(c)
  if (!session) {
    return { error: c.json({ error: 'Authentication required.' }, 401) }
  }
  if (!originMatchesSession(c, session)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  return { session }
}

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function normalisePreferences(input = {}) {
  const data = asObject(input)
  const appearance = asObject(data.appearance)
  const navigation = asObject(data.navigation)
  const guidance = asObject(data.guidance)

  return {
    appearance: {
      theme: ALLOWED_THEME.has(appearance.theme) ? appearance.theme : 'system',
      accentMode: appearance.accentMode === 'personal' ? 'personal' : 'tenant',
      accent: ALLOWED_ACCENT.has(appearance.accent) ? appearance.accent : 'amber',
      density: ALLOWED_DENSITY.has(appearance.density) ? appearance.density : 'comfortable',
    },
    navigation: {
      desktopSide: ALLOWED_SIDE.has(navigation.desktopSide) ? navigation.desktopSide : 'left',
      mobileSide: ALLOWED_SIDE.has(navigation.mobileSide) ? navigation.mobileSide : 'left',
      sidebarStyle: ALLOWED_STYLE.has(navigation.sidebarStyle) ? navigation.sidebarStyle : 'floating',
      sidebarMode: ALLOWED_MODE.has(navigation.sidebarMode) ? navigation.sidebarMode : 'expanded',
    },
    guidance: {
      coachMarks: guidance.coachMarks !== false,
    },
  }
}

async function readPreferenceRow(session) {
  const result = await pool.query(
    `SELECT
       preferences,
       first_login_completed_at,
       coachmarks_completed_at,
       getting_started_dismissed_at
     FROM user_preferences
     WHERE tenant_id = $1
       AND user_id = $2
     LIMIT 1`,
    [session.tenant_id, session.user_id],
  )

  return result.rows[0] || null
}

function responsePayload(session, row) {
  return {
    user: {
      id: session.user_id,
      name: session.name,
      email: session.email,
      tenantRole: session.tenant_role,
    },
    tenant: {
      id: session.tenant_id,
      slug: session.slug,
      companyName: session.company_name,
      modules: session.modules || {},
    },
    preferences: row ? normalisePreferences(row.preferences || {}) : null,
    firstLoginCompletedAt: row?.first_login_completed_at || null,
    coachmarksCompletedAt: row?.coachmarks_completed_at || null,
    gettingStartedDismissedAt: row?.getting_started_dismissed_at || null,
  }
}

export function registerUserPreferenceRoutes(app) {
  app.get('/api/v1/user-preferences', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    const row = await readPreferenceRow(auth.session)
    return c.json(responsePayload(auth.session, row))
  })

  app.patch('/api/v1/user-preferences', async (c) => {
    const auth = await requireSession(c)
    if (auth.error) return auth.error

    let body
    try {
      body = await c.req.json()
    } catch {
      return c.json({ error: 'A valid JSON request body is required.' }, 400)
    }

    const preferences = normalisePreferences(body?.preferences || {})
    const encoded = JSON.stringify(preferences)

    if (encoded.length > 20_000) {
      return c.json({ error: 'User preferences are too large.' }, 413)
    }

    await pool.query(
      `INSERT INTO user_preferences (
         tenant_id,
         user_id,
         preferences,
         first_login_completed_at,
         coachmarks_completed_at,
         getting_started_dismissed_at,
         updated_at
       ) VALUES (
         $1,
         $2,
         $3::jsonb,
         CASE WHEN $4::boolean THEN now() ELSE NULL END,
         CASE WHEN $5::boolean THEN now() ELSE NULL END,
         CASE WHEN $6::boolean THEN now() ELSE NULL END,
         now()
       )
       ON CONFLICT (tenant_id, user_id)
       DO UPDATE SET
         preferences = EXCLUDED.preferences,
         first_login_completed_at = CASE
           WHEN $4::boolean THEN COALESCE(user_preferences.first_login_completed_at, now())
           ELSE user_preferences.first_login_completed_at
         END,
         coachmarks_completed_at = CASE
           WHEN $5::boolean THEN COALESCE(user_preferences.coachmarks_completed_at, now())
           ELSE user_preferences.coachmarks_completed_at
         END,
         getting_started_dismissed_at = CASE
           WHEN $6::boolean THEN COALESCE(user_preferences.getting_started_dismissed_at, now())
           ELSE user_preferences.getting_started_dismissed_at
         END,
         updated_at = now()`,
      [
        auth.session.tenant_id,
        auth.session.user_id,
        encoded,
        Boolean(body?.firstLoginComplete),
        Boolean(body?.coachmarksComplete),
        Boolean(body?.gettingStartedDismissed),
      ],
    )

    const row = await readPreferenceRow(auth.session)
    return c.json(responsePayload(auth.session, row))
  })
}
