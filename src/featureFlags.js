import { pool } from './db.js'
import { deployment } from './deploymentConfig.js'
import { resolveSession } from './session.js'

export async function featureEnabled(featureKey, tenantId = null) {
  const key = String(featureKey || '').trim().toLowerCase()
  if (!key) return false
  if (deployment.featureMode === 'all_enabled') return true
  const result = await pool.query(
    `SELECT COALESCE(tf.enabled,f.enabled,d.default_enabled,false) AS enabled
       FROM platform_feature_definitions d
       LEFT JOIN platform_environment_feature_flags f
         ON f.feature_key=d.feature_key AND f.environment=$2
       LEFT JOIN tenant_environment_feature_overrides tf
         ON tf.feature_key=d.feature_key AND tf.environment=$2 AND tf.tenant_id=$3
      WHERE d.feature_key=$1 AND d.status='active'
      LIMIT 1`,
    [key,deployment.runtimeEnvironment,tenantId],
  )
  return Boolean(result.rows[0]?.enabled)
}

export async function effectiveFeatures(tenantId = null) {
  const result = await pool.query(
    `SELECT d.feature_key,d.title,d.description,d.component,d.default_enabled,
            f.enabled AS environment_enabled,tf.enabled AS tenant_enabled
       FROM platform_feature_definitions d
       LEFT JOIN platform_environment_feature_flags f
         ON f.feature_key=d.feature_key AND f.environment=$1
       LEFT JOIN tenant_environment_feature_overrides tf
         ON tf.feature_key=d.feature_key AND tf.environment=$1 AND tf.tenant_id=$2
      WHERE d.status='active'
      ORDER BY d.component,d.title`,
    [deployment.runtimeEnvironment,tenantId],
  )
  return result.rows.map((row) => ({
    key: row.feature_key,
    title: row.title,
    description: row.description || '',
    component: row.component,
    enabled: deployment.featureMode === 'all_enabled'
      ? true
      : Boolean(row.tenant_enabled ?? row.environment_enabled ?? row.default_enabled),
  }))
}

export function registerFeatureFlagRoutes(app) {
  app.get('/api/v1/system/features', async (c) => {
    const session = await resolveSession(c).catch(() => null)
    const features = await effectiveFeatures(session?.tenant_id || null)
    return c.json({
      environment: deployment.runtimeEnvironment,
      mode: deployment.featureMode,
      allFeaturesEnabled: deployment.featureMode === 'all_enabled',
      features,
    })
  })
}
