import { qualificationFailureGroups } from './rmmQualificationFailureGroups.js'
import { hasPermission } from './access.js'
import { originMatchesTenant } from './deploymentConfig.js'
import { pool, withTransaction } from './db.js'
import { agentSocketForDevice, authenticateAgent, sendAgentMessage } from './rmmAgent.js'
import { recordRmmActivity } from './rmmActivity.js'
import { auditCatalogueVulnerabilityIdentities, recentVulnerabilities, vulnerabilitySummary } from './rmmVulnerabilityIntel.js'
import {
  prepareQualificationBaselineForCatalogue,
  softwareVendorSummary,
  syncSoftwareVendorSource,
} from './rmmSoftwareVendorIntel.js'
import {
  qualificationQueueSummary,
  promoteAutomaticAdmissionReady,
  queueRollbackQualification,
  queueUpgradeQualification,
  retrySoftwareQualification,
} from './rmmSoftwareQualification.js'
import { queueVendorArtifactInspectionForCatalogue } from './rmmVendorReleaseEnrichment.js'
import { wingetRepositoryAllSearch, wingetRepositorySearch } from './rmmWingetFallback.js'
import { normalizeCatalogueVersion, verificationVersionForRelease } from './rmmSoftwareVersioning.js'
import {
  approveTenantVendorSource,
  archiveTenantVendorSource,
  createTenantVendorSource,
  listTenantVendorSources,
  tenantVendorVerificationRecommendation,
  testTenantVendorSource,
  updateTenantVendorSource,
} from './rmmTenantVendorSources.js'
import { recalculateTenantVulnerabilityExposures, syncGithubRepositoryAdvisoriesForCatalogue, vulnerabilityExposureByInstallation, vulnerabilityExposureRows, vulnerabilityExposureSummary } from './rmmVulnerabilityExposure.js'
import { resolveSession } from './session.js'
import { dispatchWindowsUpdateRollback, evaluateWindowsUpdatePolicies, setWindowsUpdateControl, windowsMaintenanceWindow, windowsUpdateBundle } from './rmmWindowsUpdates.js'

function clean(value = '') { return String(value ?? '').trim() }
function lower(value = '') { return clean(value).toLowerCase() }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function array(value) { return Array.isArray(value) ? value : [] }
function vulnerabilityIdentityLimited(value) {
  const audit = object(value)
  const state = clean(audit.state)
  if (state === 'no_published_identity') return true
  if (state !== 'needs_review') return false
  return !clean(audit.error) && clean(audit.method) !== 'transient_identity_source_error'
}
function stableJson(value) {
  if (Array.isArray(value)) return '[' + value.map(stableJson).join(',') + ']'
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + stableJson(value[key])).join(',') + '}'
  }
  return JSON.stringify(value ?? null)
}
function normalizedVendorResponseFile(value) {
  const response = object(value)
  const fileName = clean(response.fileName)
  const content = typeof response.content === 'string' ? response.content : ''
  return fileName || content ? { fileName, content } : null
}
function safeVendorResponseFileName(value = '') {
  const name = clean(value)
  return /^[A-Za-z0-9._-]{1,128}$/.test(name)
    && !['.', '..'].includes(name)
    && /\.(xml|iss|ini|txt|json|config|rsp)$/i.test(name)
}
function normalizeGithubRepository(value = '') {
  const raw = clean(value).replace(/\.git$/i, '')
  if (!raw) return ''
  const urlMatch = raw.match(/^https:\/\/github\.com\/([^/\s]+)\/([^/#?\s]+)(?:[/?#].*)?$/i)
  if (urlMatch) return urlMatch[1] + '/' + urlMatch[2].replace(/\.git$/i, '')
  const shortMatch = raw.match(/^([^/\s]+)\/([^/\s]+)$/)
  return shortMatch ? shortMatch[1] + '/' + shortMatch[2] : ''
}
function identityPhraseMatches(value, pattern) {
  const haystack = lower(value)
  const needle = lower(pattern)
  if (!needle) return true
  if (!haystack || haystack.length < needle.length) return false
  let from = 0
  while (from <= haystack.length - needle.length) {
    const index = haystack.indexOf(needle, from)
    if (index < 0) return false
    const before = index > 0 ? haystack[index - 1] : ''
    const after = index + needle.length < haystack.length ? haystack[index + needle.length] : ''
    if ((!before || !/[a-z0-9]/.test(before)) && (!after || !/[a-z0-9]/.test(after))) return true
    from = index + 1
  }
  return false
}

async function requirePatchAccess(c, mode = 'view') {
  const session = await resolveSession(c)
  if (!session) return { error: c.json({ error: 'Authentication required.' }, 401) }
  if (!originMatchesTenant(c.req.header('origin'), session.slug)) {
    return { error: c.json({ error: 'Tenant session mismatch.' }, 403) }
  }
  const permissions = mode === 'software'
    ? ['rmm.software.manage']
    : mode === 'policy'
      ? ['rmm.policies.manage']
      : ['rmm.devices.view', 'rmm.policies.view', 'rmm.policies.manage', 'rmm.software.manage']
  if (!permissions.some((permission) => hasPermission(session.access, permission))) {
    return { error: c.json({ error: 'You do not have permission to access patching.' }, 403) }
  }
  return { session }
}
async function audit(session, eventType, summary, detail = '', metadata = {}) {
  return recordRmmActivity({
    tenantId: session.tenant_id,
    agentDeviceId: metadata.agentDeviceId || null,
    inventoryId: metadata.inventoryId || null,
    actorUserId: session.user_id,
    actorType: 'technician',
    actorLabel: session.name || session.email || 'Technician',
    eventType,
    category: 'patching',
    summary,
    detail,
    outcome: 'success',
    metadata,
  }).catch(() => null)
}

function psSingleQuote(value = '') {
  return "'" + clean(value).replaceAll("'", "''") + "'"
}

function safeVerificationFilePath(value = '') {
  const filePath = clean(value)
  return Boolean(filePath
    && /^(?:[A-Za-z]:\\|%ProgramFiles%\\|%ProgramFiles\(x86\)%\\|%ProgramData%\\)/i.test(filePath)
    && !filePath.includes('..')
    && !/["\r\n]/.test(filePath)
    && /\.(?:exe|dll)$/i.test(filePath))
}

function fileVersionProbeScript(filePath) {
  return [
    "$ErrorActionPreference = 'Stop'",
    '$path = [Environment]::ExpandEnvironmentVariables(' + psSingleQuote(filePath) + ')',
    "if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('Verification file was not found: ' + $path) }",
    '$info = (Get-Item -LiteralPath $path).VersionInfo',
    '[pscustomobject]@{',
    "  status = 'ok'",
    '  path = $path',
    '  file_version = [string]$info.FileVersion',
    '  product_version = [string]$info.ProductVersion',
    '  file_description = [string]$info.FileDescription',
    '  product_name = [string]$info.ProductName',
    '  original_filename = [string]$info.OriginalFilename',
    '} | ConvertTo-Json -Compress',
  ].join('\n')
}

export async function queueVendorVerificationProbe({ tenantId, userId = null, actorLabel = 'Technician', initiatedBy = 'technician', sourceId, agentDeviceId = '' }) {
  const selected = await pool.query(
    `SELECT s.id AS source_id,s.display_name,s.status,s.verification_config,
            a.id AS agent_device_id,a.inventory_id,a.websocket_status,a.last_telemetry_at,
            i.name AS device_name,i.reference AS device_reference
       FROM rmm_tenant_vendor_sources s
       JOIN rmm_agent_devices a ON a.tenant_id=s.tenant_id AND a.disabled_at IS NULL
       JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true
      WHERE s.tenant_id=$1 AND s.id=$2 AND s.status IN ('tested','active')
        AND (
          ($3<>'' AND a.id::text=$3)
          OR
          ($3='' AND EXISTS (
            SELECT 1
              FROM jsonb_array_elements(
                CASE WHEN jsonb_typeof(i.source_payload->'software'->'items')='array'
                  THEN i.source_payload->'software'->'items'
                  ELSE '[]'::jsonb END
              ) item
             WHERE lower(COALESCE(item->>'name','')) LIKE '%' || lower(COALESCE(NULLIF(s.name_pattern,''),s.canonical_name)) || '%'
               AND (
                 COALESCE(NULLIF(s.publisher_pattern,''),s.publisher,'')=''
                 OR lower(COALESCE(item->>'publisher','')) LIKE '%' || lower(COALESCE(NULLIF(s.publisher_pattern,''),s.publisher)) || '%'
               )
          ))
        )
      ORDER BY
        (a.websocket_status='Connected' AND a.last_telemetry_at > now()-interval '90 seconds') DESC,
        a.last_telemetry_at DESC NULLS LAST
      LIMIT 1`,
    [tenantId, sourceId, clean(agentDeviceId)],
  )
  const row = selected.rows[0]
  if (!row) return { error: 'Vendor source or managed endpoint was not found.', status: 404 }

  const verification = object(row.verification_config)
  const filePath = clean(verification.filePath)
  if (!safeVerificationFilePath(filePath)) {
    return { error: 'The configured verification file path is not allowed.', status: 409 }
  }
  const telemetryFresh = row.last_telemetry_at && Date.now() - new Date(row.last_telemetry_at).getTime() <= 90_000
  if (row.websocket_status !== 'Connected' || !telemetryFresh) {
    return { error: 'This device is offline. No verification probe was queued.', status: 409, offline: true }
  }

  const existing = await pool.query(
    `SELECT id,status FROM rmm_agent_jobs
      WHERE tenant_id=$1 AND agent_device_id=$2 AND job_type='custom.command'
        AND request_metadata->>'source'='vendor_verification_probe'
        AND request_metadata->>'vendor_source_id'=$3
        AND status IN ('queued','claimed')
      ORDER BY created_at DESC LIMIT 1`,
    [tenantId, row.agent_device_id, sourceId],
  )
  if (existing.rowCount) return { error: 'A verification probe is already running for this source and device.', status: 409, jobId: existing.rows[0].id }

  const command = fileVersionProbeScript(filePath)
  const inserted = await pool.query(
    `INSERT INTO rmm_agent_jobs
      (tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,request_metadata)
     VALUES ($1,$2,'custom.command',$3::jsonb,$4,$5,$6,$7::jsonb)
     RETURNING id,status,created_at`,
    [
      tenantId,
      row.agent_device_id,
      JSON.stringify({ command, timeout_seconds: 30 }),
      userId,
      ['system','technician'].includes(clean(initiatedBy)) ? clean(initiatedBy) : 'technician',
      clean(actorLabel || 'Technician').slice(0, 255),
      JSON.stringify({
        source: 'vendor_verification_probe',
        vendor_source_id: sourceId,
        verification_method: 'file_version',
        verification_file_path: filePath,
        device_name: row.device_name,
        device_reference: row.device_reference,
      }),
    ],
  )
  await recordRmmActivity({
    tenantId,
    agentDeviceId: row.agent_device_id,
    inventoryId: row.inventory_id,
    actorUserId: userId,
    actorType: clean(initiatedBy) === 'system' ? 'system' : 'technician',
    actorLabel: clean(actorLabel || 'Technician').slice(0, 255),
    eventType: 'patch.vendor_verification_probe.requested',
    category: 'patching',
    summary: clean(actorLabel || 'Technician') + ' started vendor verification probe “' + row.display_name + '”',
    detail: 'Read-only file VERSIONINFO probe · ' + filePath,
    outcome: 'requested',
    jobId: inserted.rows[0].id,
    metadata: { sourceId, method: 'file_version', filePath },
  }).catch(() => null)
  return { success: true, job: inserted.rows[0], filePath, deviceName: row.device_name }
}

async function queueAutomaticVendorVerificationProbes(tenantId) {
  const candidates = await pool.query(
    `SELECT s.id
       FROM rmm_tenant_vendor_sources s
      WHERE s.tenant_id=$1
        AND s.status IN ('tested','active')
        AND COALESCE(s.verification_config->>'filePath','')<>''
        AND EXISTS (
          SELECT 1
            FROM rmm_agent_devices a
            JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true
           WHERE a.tenant_id=s.tenant_id
             AND a.disabled_at IS NULL
             AND a.websocket_status='Connected'
             AND a.last_telemetry_at > now()-interval '90 seconds'
             AND EXISTS (
               SELECT 1
                 FROM jsonb_array_elements(
                   CASE WHEN jsonb_typeof(i.source_payload->'software'->'items')='array'
                     THEN i.source_payload->'software'->'items'
                     ELSE '[]'::jsonb END
                 ) item
                WHERE lower(COALESCE(item->>'name','')) LIKE '%' || lower(COALESCE(NULLIF(s.name_pattern,''),s.canonical_name)) || '%'
                  AND (
                    COALESCE(NULLIF(s.publisher_pattern,''),s.publisher,'')=''
                    OR lower(COALESCE(item->>'publisher','')) LIKE '%' || lower(COALESCE(NULLIF(s.publisher_pattern,''),s.publisher)) || '%'
                  )
             )
        )
        AND NOT EXISTS (
          SELECT 1
            FROM rmm_agent_jobs j
           WHERE j.tenant_id=s.tenant_id
             AND j.job_type='custom.command'
             AND j.request_metadata->>'source'='vendor_verification_probe'
             AND j.request_metadata->>'vendor_source_id'=s.id::text
             AND j.request_metadata->>'verification_file_path'=s.verification_config->>'filePath'
             AND j.status IN ('queued','claimed','completed','failed')
        )
      ORDER BY s.updated_at
      LIMIT 5`,
    [tenantId],
  )
  const queued = []
  for (const candidate of candidates.rows) {
    const result = await queueVendorVerificationProbe({
      tenantId,
      sourceId: candidate.id,
      actorLabel: 'SYSTEM',
      initiatedBy: 'system',
    })
    if (result?.success) queued.push({ sourceId: candidate.id, jobId: result.job?.id, deviceName: result.deviceName })
  }
  return queued
}

function versionParts(value) {
  const matches = clean(value).match(/\d+/g)
  if (!matches?.length) return null
  return matches.map((part) => Number(part))
}

function compareVersions(installed, target) {
  const installedText = clean(installed)
  const targetText = clean(target)
  const left = versionParts(installedText)
  const right = versionParts(targetText)
  if (!left || !right) return null
  const size = Math.max(left.length, right.length)
  for (let index = 0; index < size; index += 1) {
    const a = left[index] || 0
    const b = right[index] || 0
    if (a < b) return -1
    if (a > b) return 1
  }

  // WinGet can report an installed version as "< X" when the exact installed
  // version is not known but is known to be lower than the available package.
  // Preserve that ordering instead of flattening both values to the same digits.
  if (/^\s*</.test(installedText) && !/^\s*<=/.test(installedText)) return -1
  if (/^\s*>/.test(installedText) && !/^\s*>=/.test(installedText)) return 1

  return 0
}
async function patchDeviceRows(tenantId) {
  const result = await pool.query(
    `SELECT i.id AS inventory_id,i.reference,i.name,i.source_payload,
            a.id AS agent_device_id,a.agent_version,a.websocket_status,a.last_telemetry_at,
            a.patch_capabilities,a.patch_capabilities_at,a.patch_discovery_at,
            p.name AS assigned_person_name,p.email AS assigned_person_email,
            s.external_key AS site_id,s.name AS site_name,
            CASE WHEN a.websocket_status='Connected' AND a.last_telemetry_at>now()-interval '90 seconds'
                 THEN true ELSE false END AS online
       FROM rmm_agent_devices a
       JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true
       LEFT JOIN organisation_people p ON p.tenant_id=i.tenant_id AND p.id=i.assigned_person_id
       LEFT JOIN organisation_sites s ON s.tenant_id=i.tenant_id AND s.id=p.site_id
      WHERE a.tenant_id=$1 AND a.disabled_at IS NULL
      ORDER BY i.name`,
    [tenantId],
  )
  return result.rows
}

async function catalogueRows(tenantId) {
  const result = await pool.query(
    `SELECT c.id,c.tenant_id,c.canonical_name,c.publisher,c.name_pattern,c.publisher_pattern,c.platform,c.provider,
            c.provider_package_id,c.target_version,c.release_channel,c.installer_type,c.detection,c.execution,c.verification,c.status,
            c.catalogue_source,c.external_key,c.source_metadata,c.qualification_state,c.qualification_version,
            c.qualification_evidence,c.qualification_notes,c.qualified_at,c.created_at,c.updated_at,
            COALESCE(qi.install_test_passed,false) AS install_test_passed,
            qi.install_tested_at,qi.install_test_version,
            COALESCE(qt.upgrade_test_passed,false) AS upgrade_test_passed,
            qt.upgrade_tested_at,qt.upgrade_test_version,
            COALESCE(vi.identity_count,0)::int AS vulnerability_identity_count,
            s.last_success_at AS qualification_source_last_success_at,
            s.last_error AS qualification_source_error,
            s.metadata AS qualification_source_metadata,
            qq.state AS qualification_queue_state,
            qq.last_error AS qualification_queue_error,
            qq.updated_at AS qualification_queue_updated_at
       FROM rmm_software_catalogue c
       LEFT JOIN LATERAL (
         SELECT
           bool_or(q.state='passed') AS install_test_passed,
           max(q.completed_at) FILTER (WHERE q.state='passed') AS install_tested_at,
           max(c.target_version) FILTER (WHERE q.state='passed') AS install_test_version
         FROM rmm_software_qualification_queue q
        WHERE q.catalogue_id=c.id AND q.test_type='clean_install'
       ) qi ON true
       LEFT JOIN LATERAL (
         SELECT
           bool_or(
             d.status='succeeded'
             AND lower(COALESCE(d.result->>'verificationPassed',d.result->'verification'->>'meetsTarget','false'))='true'
             AND COALESCE(NULLIF(d.result->>'intent',''),CASE WHEN COALESCE(d.installed_version,'')='' THEN 'install' ELSE 'update' END)='update'
           ) AS upgrade_test_passed,
           max(d.completed_at) FILTER (
             WHERE d.status='succeeded'
               AND lower(COALESCE(d.result->>'verificationPassed',d.result->'verification'->>'meetsTarget','false'))='true'
               AND COALESCE(NULLIF(d.result->>'intent',''),CASE WHEN COALESCE(d.installed_version,'')='' THEN 'install' ELSE 'update' END)='update'
           ) AS upgrade_tested_at,
           max(d.target_version) FILTER (
             WHERE d.status='succeeded'
               AND lower(COALESCE(d.result->>'verificationPassed',d.result->'verification'->>'meetsTarget','false'))='true'
               AND COALESCE(NULLIF(d.result->>'intent',''),CASE WHEN COALESCE(d.installed_version,'')='' THEN 'install' ELSE 'update' END)='update'
           ) AS upgrade_test_version
         FROM rmm_patch_deployments d
         JOIN rmm_agent_devices a ON a.inventory_id=d.inventory_id AND a.disabled_at IS NULL
         JOIN rmm_software_vendor_qualification_runners qr ON qr.agent_device_id=a.id AND qr.enabled=true
        WHERE d.catalogue_id=c.id
       ) qt ON true
       LEFT JOIN LATERAL (
         SELECT count(*)::int AS identity_count
           FROM rmm_software_vulnerability_identities vi
          WHERE vi.catalogue_id=c.id AND vi.enabled=true
       ) vi ON true
       LEFT JOIN LATERAL (
         SELECT state,last_error,updated_at
           FROM rmm_software_qualification_queue qq
          WHERE qq.catalogue_id=c.id AND qq.test_type='clean_install'
          ORDER BY qq.updated_at DESC
          LIMIT 1
       ) qq ON true
       LEFT JOIN rmm_software_vendor_sources s
         ON s.source_key=c.source_metadata->>'latestSource'
      WHERE c.status<>'archived' AND (c.tenant_id=$1 OR c.tenant_id IS NULL)
      ORDER BY c.tenant_id NULLS FIRST,lower(c.canonical_name)`,
    [tenantId],
  )

  return result.rows.map((row) => {
    const sourceMetadata = object(row.source_metadata)
    const sourceLiveMetadata = object(row.qualification_source_metadata)
    const qualificationEvidence = object(row.qualification_evidence)
    const identityAudit = object(sourceMetadata.vulnerabilityIdentityAudit)
    const deploymentMode = clean(sourceMetadata.deploymentMode)
    const trustState = clean(sourceMetadata.trustState)
    const installerType = lower(row.installer_type)
    const officialWinget = clean(sourceMetadata.wingetPackageSource) === 'https://cdn.winget.microsoft.com/cache/source2.msix'
      || trustState === 'winget_ready'
      || (row.provider === 'winget' && clean(row.provider_package_id))
    const artifactVerified = Boolean(
      (deploymentMode === 'vendor_direct'
        && trustState === 'direct_ready'
        && ['msi','exe'].includes(installerType)
        && clean(qualificationEvidence.vendorReleaseId)
        && clean(qualificationEvidence.artifactVerificationVersion) === clean(row.target_version)
        && qualificationEvidence.sha256Verified === true
        && qualificationEvidence.authenticodeVerified === true)
      || officialWinget,
    )
    const latestSource = clean(sourceMetadata.latestSource)
    const sourceHealthy = latestSource
      ? Boolean(row.qualification_source_last_success_at) && !clean(row.qualification_source_error)
      : officialWinget
    const vulnerabilityCovered = clean(identityAudit.state) === 'covered'
      && Number(row.vulnerability_identity_count || 0) > 0
    const vulnerabilityLimited = vulnerabilityIdentityLimited(identityAudit)
    const historyLimited = clean(sourceLiveMetadata.baselinePreparationState) === 'previous_stable_installer_unavailable'
      && clean(sourceLiveMetadata.baselinePreparationTargetVersion) === clean(row.target_version)
    const targetVersion = clean(row.target_version)
    const cleanInstallVersion = clean(qualificationEvidence.cleanInstallVersion)
    const installTestPassed = qualificationEvidence.cleanInstallVerified === true
      && Boolean(targetVersion)
      && cleanInstallVersion === targetVersion
    const uninstallTestPassed = qualificationEvidence.uninstallVerified === true
      && installTestPassed
    const rawInstallExecutionPassed = row.install_test_passed === true
      && clean(row.install_test_version) === targetVersion
    const upgradeTestPassed = row.upgrade_test_passed === true
      && clean(row.upgrade_test_version) === targetVersion
    const rollbackTestPassed = qualificationEvidence.rollbackVerified === true
      && clean(qualificationEvidence.rollbackRestoredVersion) === targetVersion
    const queueState = clean(row.qualification_queue_state)
    const installTestState = installTestPassed
      ? 'passed'
      : ['running','cleanup_pending','cleanup_running','queued','review_required'].includes(queueState)
        ? queueState
        : rawInstallExecutionPassed
          ? 'cleanup_pending'
          : 'not_tested'
    const uninstallTestState = uninstallTestPassed
      ? 'passed'
      : ['cleanup_pending','cleanup_running','review_required'].includes(queueState)
        ? queueState
        : queueState === 'passed'
          ? 'pending'
          : 'not_tested'
    const automaticAdmissionReady = Boolean(
      sourceHealthy
      && artifactVerified
      && installTestPassed
      && uninstallTestPassed,
    )
    const limitedAdmissionReady = false
    const capabilityAdmissionReady = automaticAdmissionReady
    const blockers = []
    if (!sourceHealthy) blockers.push('source_health')
    if (!artifactVerified) blockers.push('artifact_verification')
    if (!installTestPassed) blockers.push('clean_install_test')
    if (!uninstallTestPassed) blockers.push('uninstall_test')

    return {
      ...row,
      qualification_readiness: {
        state: automaticAdmissionReady ? 'ready' : limitedAdmissionReady ? 'limited' : 'pending',
        automaticAdmissionReady,
        limitedAdmissionReady,
        capabilityAdmissionReady,
        blockers,
        limitations: {
          historicalInstaller: historyLimited ? {
            state: 'unavailable_upstream',
            reason: clean(sourceLiveMetadata.baselinePreparationReason),
            previousVersion: clean(sourceLiveMetadata.baselinePreparationPreviousVersion),
          } : null,
          vulnerabilityIdentity: vulnerabilityLimited ? {
            state: clean(identityAudit.state) === 'no_published_identity' ? 'no_published_identity' : 'identity_unresolved',
            auditState: clean(identityAudit.state),
            method: clean(identityAudit.method),
            note: clean(identityAudit.dispositionNote || sourceMetadata.vulnerabilityIdentityNote)
              || (clean(identityAudit.state) === 'needs_review'
                ? 'No unambiguous authoritative vulnerability identity is currently available; NVD/CVE/EPSS coverage remains limited until identity resolution succeeds.'
                : ''),
          } : null,
        },
        source: {
          state: sourceHealthy ? 'healthy' : 'attention',
          lastSuccessAt: row.qualification_source_last_success_at || null,
          error: clean(row.qualification_source_error),
        },
        artifact: {
          state: artifactVerified ? 'verified' : 'pending',
          deploymentMode,
          trustState,
          sha256Verified: qualificationEvidence.sha256Verified === true,
          authenticodeVerified: qualificationEvidence.authenticodeVerified === true,
        },
        installTest: {
          state: installTestState,
          testedAt: clean(qualificationEvidence.cleanInstallVerifiedAt) || row.install_tested_at || null,
          version: cleanInstallVersion || clean(row.install_test_version),
          executionPassed: rawInstallExecutionPassed,
          queueState,
          error: clean(row.qualification_queue_error),
          queueUpdatedAt: row.qualification_queue_updated_at || null,
        },
        uninstallTest: {
          state: uninstallTestState,
          testedAt: clean(qualificationEvidence.uninstallVerifiedAt) || null,
          version: cleanInstallVersion,
          queueState,
          error: clean(row.qualification_queue_error),
        },
        upgradeTest: {
          state: upgradeTestPassed ? 'passed' : historyLimited ? 'unavailable' : 'not_tested',
          testedAt: row.upgrade_tested_at || null,
          version: clean(row.upgrade_test_version),
        },
        rollbackTest: {
          state: rollbackTestPassed ? 'passed' : historyLimited ? 'unavailable' : 'not_tested',
          testedAt: clean(qualificationEvidence.rollbackVerifiedAt) || null,
          version: clean(qualificationEvidence.rollbackRestoredVersion),
        },
        vulnerability: {
          state: vulnerabilityCovered ? 'covered' : (clean(identityAudit.state) || 'needs_review'),
          identityCount: Number(row.vulnerability_identity_count || 0),
          checkedAt: clean(identityAudit.checkedAt),
          method: clean(identityAudit.method),
          resolvedSource: clean(identityAudit.resolvedSource),
        },
      },
    }
  })
}
async function qualificationLabPayload(tenantId, catalogueId) {
  const appResult = await pool.query(
    `SELECT c.id,c.tenant_id,c.canonical_name,c.publisher,c.target_version,c.installer_type,
            c.qualification_state,c.qualification_version,c.qualification_evidence,c.qualification_notes,
            c.qualified_at,c.external_key,c.catalogue_source,c.source_metadata,c.verification,c.execution,
            s.source_key,s.source_type,s.source_url,s.enabled AS source_enabled,s.last_success_at,
            s.last_attempt_at,s.last_error,s.metadata AS source_metadata_live,s.poll_minutes
       FROM rmm_software_catalogue c
       LEFT JOIN rmm_software_vendor_sources s
         ON s.source_key=c.source_metadata->>'latestSource'
      WHERE c.id=$1 AND c.status<>'archived'
        AND (c.tenant_id=$2 OR c.tenant_id IS NULL)
      LIMIT 1`,
    [catalogueId,tenantId],
  )
  const app=appResult.rows[0]
  if(!app) return null

  const globalVendor=!app.tenant_id && clean(app.catalogue_source)==='vendor' && clean(app.source_key)
  const [releaseResult,queueResult,jobResult,identityResult,runnerResult]=await Promise.all([
    globalVendor
      ? pool.query(
          `SELECT id,version,release_date,installer_url,installer_sha256,installer_type,release_url,asset_name,
                  trust_state,trust_evidence,source_payload,asset_health_state,asset_last_checked_at,
                  asset_http_status,asset_content_type,asset_content_length,last_seen_at
             FROM rmm_software_vendor_releases
            WHERE source_key=$1 AND provider_package_id=$2
            ORDER BY COALESCE(release_date,last_seen_at) DESC,last_seen_at DESC`,
          [app.source_key,app.external_key],
        )
      : Promise.resolve({rows:[]}),
    pool.query(
      `SELECT id,test_type,state,priority,attempt_count,runner_agent_device_id,agent_job_id,deployment_id,
              cleanup_job_id,last_error,evidence,started_at,completed_at,created_at,updated_at
         FROM rmm_software_qualification_queue
        WHERE catalogue_id=$1
        ORDER BY CASE test_type WHEN 'clean_install' THEN 0 WHEN 'upgrade' THEN 1 ELSE 2 END,updated_at DESC`,
      [catalogueId],
    ),
    pool.query(
      `SELECT j.id,j.job_type,j.status,j.error_message,j.request_metadata,j.created_at,j.claimed_at,j.completed_at,
              COALESCE(j.result->>'provider','') AS result_provider,
              COALESCE(j.result->>'error','') AS result_error,
              COALESCE(j.result->>'verifiedVersion',j.result->'verification'->>'installedVersion','') AS verified_version,
              COALESCE(j.result->>'verificationPassed',j.result->'verification'->>'meetsTarget','') AS verification_passed
         FROM rmm_agent_jobs j
         JOIN rmm_software_qualification_queue q
           ON q.id::text=j.request_metadata->>'qualification_queue_id'
        WHERE q.catalogue_id=$1
        ORDER BY j.created_at DESC
        LIMIT 30`,
      [catalogueId],
    ),
    pool.query(
      `SELECT id,source AS source_type,vendor,product,ecosystem,package_name,enabled,confidence,metadata AS evidence,created_at,updated_at
         FROM rmm_software_vulnerability_identities
        WHERE catalogue_id=$1 AND enabled=true
        ORDER BY confidence DESC,source_type,vendor,product`,
      [catalogueId],
    ),
    pool.query(
      `SELECT a.id AS agent_device_id,i.name AS device_name,a.agent_version,a.websocket_status,
              a.last_telemetry_at,a.patch_capabilities
         FROM rmm_software_vendor_qualification_runners q
         JOIN rmm_agent_devices a ON a.id=q.agent_device_id AND a.disabled_at IS NULL
         JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true
        WHERE q.enabled=true AND a.tenant_id=$1
        ORDER BY a.last_telemetry_at DESC
        LIMIT 1`,
      [tenantId],
    ),
  ])

  const evidence=object(app.qualification_evidence)
  const qualificationLimitations=object(evidence.qualificationLimitations)
  const manualLimitation=object(qualificationLimitations.manual)
  const unsupportedCapabilities=new Set(array(manualLimitation.unsupportedCapabilities).map((value)=>clean(value)).filter(Boolean))
  const catalogueSource=object(app.source_metadata)
  const sourceLive=object(app.source_metadata_live)
  const identityAudit=object(catalogueSource.vulnerabilityIdentityAudit)
  const releases=releaseResult.rows.map((release)=>({
    id:release.id,
    version:clean(release.version),
    releaseDate:release.release_date || null,
    installerType:clean(release.installer_type),
    assetName:clean(release.asset_name),
    installerHost:(()=>{try{return new URL(clean(release.installer_url)).hostname}catch{return ''}})(),
    releaseHost:(()=>{try{return new URL(clean(release.release_url)).hostname}catch{return ''}})(),
    trustState:clean(release.trust_state),
    trustReason:clean(object(release.trust_evidence).reason || object(release.source_payload).artifactInspectionError || object(release.source_payload).artifactTrustReason),
    assetHealthState:clean(release.asset_health_state || 'unknown'),
    assetLastCheckedAt:release.asset_last_checked_at || null,
    assetHttpStatus:release.asset_http_status || null,
    contentType:clean(release.asset_content_type),
    contentLength:Number(release.asset_content_length || 0) || null,
    publishedSha256Present:/^[a-f0-9]{64}$/i.test(clean(release.installer_sha256)),
    sha256Verified:Boolean(
      /^[a-f0-9]{64}$/i.test(clean(release.installer_sha256))
      && /^[a-f0-9]{64}$/i.test(clean(object(release.trust_evidence).sha256))
      && clean(release.installer_sha256).toLowerCase()===clean(object(release.trust_evidence).sha256).toLowerCase()
    ),
    signatureVerified:object(release.trust_evidence).signatureVerified === true,
    expectedSigner:clean(
      object(release.source_payload).expectedSigner
      || object(release.trust_evidence).signerBaseline
    ),
    verifiedSigner:object(release.trust_evidence).signatureVerified === true
      ? clean(object(release.trust_evidence).signer)
      : '',
    historical:object(release.source_payload).historicalReleaseCandidate === true,
    historicalRole:clean(object(release.source_payload).historicalRole),
    lastSeenAt:release.last_seen_at || null,
  }))

  const stableOlder=releases
    .filter((release)=>!/(alpha|beta|preview|nightly|canary|rc|eap|dev)/i.test(release.version)
      && compareVersions(release.version,app.target_version)===-1)
    .sort((left,right)=>compareVersions(right.version,left.version) || 0)
  const previousReady=stableOlder.find((release)=>release.trustState==='direct_ready') || null
  const terminalHistoricalReasons=new Set(['vendor_checksum_mismatch','sha256_mismatch','vendor_download_failed','artifact_download_failed'])
  const previousPending=stableOlder.find((release)=>['asset_candidate','winget_ready'].includes(release.trustState)
    && !terminalHistoricalReasons.has(release.trustReason)) || null
  const baselinePreparationState=clean(sourceLive.baselinePreparationState)
  const previousUnavailable=Boolean(!previousReady && !previousPending
    && clean(sourceLive.baselinePreparationTargetVersion)===clean(app.target_version)
    && (baselinePreparationState==='previous_stable_installer_unavailable'
      || stableOlder.some((release)=>release.trustState==='rejected' || terminalHistoricalReasons.has(release.trustReason))))
  const previousUnavailableRelease=previousUnavailable
    ? stableOlder.find((release)=>release.trustState==='rejected' || terminalHistoricalReasons.has(release.trustReason)) || stableOlder[0] || null
    : null
  const currentRelease=releases.find((release)=>release.version===clean(app.target_version)) || null
  const queues=Object.fromEntries(queueResult.rows.map((queue)=>[queue.test_type,{
    id:queue.id,
    testType:clean(queue.test_type),
    state:clean(queue.state),
    priority:Number(queue.priority || 0),
    attemptCount:Number(queue.attempt_count || 0),
    runnerAgentDeviceId:queue.runner_agent_device_id || '',
    agentJobId:queue.agent_job_id || '',
    deploymentId:queue.deployment_id || '',
    cleanupJobId:queue.cleanup_job_id || '',
    lastError:clean(queue.last_error),
    evidence:object(queue.evidence),
    startedAt:queue.started_at || null,
    completedAt:queue.completed_at || null,
    updatedAt:queue.updated_at || null,
  }]))

  const cleanQueue=queues.clean_install || null
  const upgradeQueue=queues.upgrade || null
  const rollbackQueue=queues.rollback || null
  const sourceHealthy=Boolean(app.source_enabled && app.last_success_at && !clean(app.last_error))
  const currentArtifactReady=Boolean(currentRelease?.trustState==='direct_ready'
    && currentRelease?.publishedSha256Present
    && currentRelease?.sha256Verified
    && currentRelease?.signatureVerified
    && currentRelease?.verifiedSigner)
  const vulnerabilityCovered=clean(identityAudit.state)==='covered' && identityResult.rows.length>0
  const vulnerabilityLimited=vulnerabilityIdentityLimited(identityAudit)
  const cleanPassed=evidence.cleanInstallVerified===true
    && clean(evidence.cleanInstallVersion)===clean(app.target_version)
  const uninstallPassed=evidence.uninstallVerified===true && cleanPassed
  const upgradePassed=evidence.upgradeVerified===true
    && clean(evidence.upgradeVersion)===clean(app.target_version)
  const detectionPassed=evidence.upgradePatchDetectionVerified===true
    && clean(evidence.upgradePatchDetectionTargetVersion)===clean(app.target_version)
  const rollbackPassed=evidence.rollbackVerified===true
    && clean(evidence.rollbackRestoredVersion)===clean(app.target_version)

  const queueLayerState=(queue,fallback='not_tested')=>{
    const state=clean(queue?.state)
    return ['queued','running','cleanup_pending','cleanup_running','review_required','passed','cancelled'].includes(state)
      ? state : fallback
  }

  return {
    application:{
      id:app.id,
      name:clean(app.canonical_name),
      publisher:clean(app.publisher),
      targetVersion:clean(app.target_version),
      installerType:clean(app.installer_type),
      qualificationState:clean(app.qualification_state),
      qualificationVersion:clean(app.qualification_version),
      qualificationNotes:clean(app.qualification_notes),
      qualifiedAt:app.qualified_at || null,
      qualificationCapabilities:object(evidence.qualificationCapabilities),
      qualificationLimitations:object(evidence.qualificationLimitations),
      deploymentMode:clean(catalogueSource.deploymentMode),
      trustState:clean(catalogueSource.trustState),
      sourceKey:clean(app.source_key),
      sourceType:clean(app.source_type),
      sourceHost:(()=>{try{return new URL(clean(app.source_url)).hostname}catch{return ''}})(),
    },
    runner:runnerResult.rows[0] ? {
      agentDeviceId:runnerResult.rows[0].agent_device_id,
      deviceName:runnerResult.rows[0].device_name,
      agentVersion:runnerResult.rows[0].agent_version,
      websocketStatus:runnerResult.rows[0].websocket_status,
      lastTelemetryAt:runnerResult.rows[0].last_telemetry_at,
      online:clean(runnerResult.rows[0].websocket_status)==='Connected',
    } : null,
    source:{
      state:sourceHealthy?'healthy':app.source_enabled?'attention':'disabled',
      enabled:Boolean(app.source_enabled),
      sourceKey:clean(app.source_key),
      sourceType:clean(app.source_type),
      sourceHost:(()=>{try{return new URL(clean(app.source_url)).hostname}catch{return ''}})(),
      lastSuccessAt:app.last_success_at || null,
      lastAttemptAt:app.last_attempt_at || null,
      error:clean(app.last_error),
      pollMinutes:Number(app.poll_minutes || 0) || null,
      automationPolicy:object(sourceLive.automationPolicy),
    },
    vulnerability:{
      state:vulnerabilityCovered?'covered':clean(identityAudit.state || 'needs_review'),
      limited:vulnerabilityLimited,
      limitationState:vulnerabilityLimited
        ? (clean(identityAudit.state)==='no_published_identity'?'no_published_identity':'identity_unresolved')
        : '',
      checkedAt:clean(identityAudit.checkedAt),
      method:clean(identityAudit.method),
      resolvedSource:clean(identityAudit.resolvedSource),
      disposition:clean(identityAudit.disposition || catalogueSource.vulnerabilityIdentityDisposition),
      dispositionNote:clean(identityAudit.dispositionNote || catalogueSource.vulnerabilityIdentityNote),
      identities:identityResult.rows.map((identity)=>({
        id:identity.id,
        sourceType:clean(identity.source_type),
        vendor:clean(identity.vendor),
        product:clean(identity.product),
        ecosystem:clean(identity.ecosystem),
        packageName:clean(identity.package_name),
        confidence:clean(identity.confidence),
      })),
    },
    releases:{
      current:currentRelease,
      previous:previousReady || previousPending || previousUnavailableRelease,
      previousReady:Boolean(previousReady),
      previousPending:Boolean(!previousReady && previousPending),
      previousUnavailable,
      previousUnavailableReason:clean(sourceLive.baselinePreparationReason || previousUnavailableRelease?.trustReason || 'historical_artifact_not_retrievable'),
      all:releases.slice(0,20),
    },
    tests:{
      cleanInstall:{
        state:unsupportedCapabilities.has('clean_install')?'unsupported':cleanPassed?'passed':queueLayerState(cleanQueue),
        version:clean(evidence.cleanInstallVersion),
        verifiedAt:clean(evidence.cleanInstallVerifiedAt),
        error:clean(cleanQueue?.lastError),
        queue:cleanQueue,
      },
      verification:{
        state:unsupportedCapabilities.has('clean_install')?'unsupported':cleanPassed?'passed':cleanPassed===false && clean(cleanQueue?.state)==='review_required'?'review_required':'pending',
        version:clean(evidence.cleanInstallVersion),
      },
      uninstall:{
        state:unsupportedCapabilities.has('uninstall')?'unsupported':uninstallPassed?'passed':queueLayerState(cleanQueue,'not_tested'),
        verifiedAt:clean(evidence.uninstallVerifiedAt),
        residueCleanupVerified:evidence.residueCleanupVerified===true,
        error:clean(cleanQueue?.lastError),
      },
      upgrade:{
        state:unsupportedCapabilities.has('upgrade')?'unsupported':['queued','running','cleanup_pending','cleanup_running','review_required'].includes(clean(upgradeQueue?.state))
          ? clean(upgradeQueue.state)
          : upgradePassed && detectionPassed?'passed'
            :upgradePassed?'legacy_pass'
            :previousUnavailable?'unavailable'
            :queueLayerState(upgradeQueue),
        fromVersion:clean(evidence.upgradeFromVersion),
        targetVersion:clean(evidence.upgradeVersion || app.target_version),
        verifiedAt:clean(evidence.upgradeVerifiedAt),
        patchDetectionVerified:detectionPassed,
        patchDetectionInstalledVersion:clean(evidence.upgradePatchDetectionInstalledVersion),
        patchDetectionTargetVersion:clean(evidence.upgradePatchDetectionTargetVersion),
        error:clean(upgradeQueue?.lastError),
        queue:upgradeQueue,
      },
      rollback:{
        state:unsupportedCapabilities.has('rollback')?'unsupported':['queued','running','cleanup_pending','cleanup_running','review_required'].includes(clean(rollbackQueue?.state))
          ? clean(rollbackQueue.state)
          : rollbackPassed?'passed'
            :previousUnavailable?'unavailable'
            :queueLayerState(rollbackQueue),
        supported:!previousUnavailable && !unsupportedCapabilities.has('rollback'),
        fromVersion:clean(evidence.rollbackFromVersion || app.target_version),
        previousVersion:clean(evidence.rollbackPreviousVersion || previousReady?.version || previousPending?.version),
        restoredVersion:clean(evidence.rollbackRestoredVersion),
        verifiedAt:clean(evidence.rollbackVerifiedAt),
        currentInstallVerified:evidence.rollbackCurrentInstallVerified===true,
        currentUninstallVerified:evidence.rollbackCurrentUninstallVerified===true,
        previousInstallVerified:evidence.rollbackPreviousInstallVerified===true,
        previousInventoryVerified:evidence.rollbackPreviousInventoryVerified===true,
        restorePatchDetectionVerified:evidence.rollbackRestorePatchDetectionVerified===true,
        restorePatchDetectionInstalledVersion:clean(evidence.rollbackRestorePatchDetectionInstalledVersion),
        restorePatchDetectionTargetVersion:clean(evidence.rollbackRestorePatchDetectionTargetVersion),
        restoreVerified:evidence.rollbackRestoreVerified===true,
        finalUninstallVerified:evidence.rollbackFinalUninstallVerified===true,
        residueCleanupVerified:evidence.rollbackResidueCleanupVerified===true,
        error:clean(rollbackQueue?.lastError),
        queue:rollbackQueue,
      },
    },
    layers:[
      {id:'source',label:'Source & trust',state:sourceHealthy && currentArtifactReady?'passed':sourceHealthy?'pending':'attention'},
      {id:'vulnerability',label:'Vulnerability identity',state:unsupportedCapabilities.has('vulnerability_coverage')?'limited':vulnerabilityCovered?'passed':vulnerabilityLimited?'limited':'attention'},
      {id:'clean',label:'Install / verify / uninstall',state:unsupportedCapabilities.has('clean_install') || unsupportedCapabilities.has('uninstall')?'limited':cleanPassed && uninstallPassed?'passed':queueLayerState(cleanQueue)},
      {id:'history',label:'Previous stable',state:previousReady?'passed':previousPending?'pending':previousUnavailable?'unavailable':'missing'},
      {id:'upgrade',label:'Patch upgrade',state:unsupportedCapabilities.has('upgrade')?'limited':['queued','running','cleanup_pending','cleanup_running','review_required'].includes(clean(upgradeQueue?.state))
        ? clean(upgradeQueue.state)
        : upgradePassed && detectionPassed?'passed':upgradePassed?'legacy_pass':previousUnavailable?'unavailable':queueLayerState(upgradeQueue)},
      {id:'rollback',label:'Rollback',state:unsupportedCapabilities.has('rollback')?'limited':['queued','running','cleanup_pending','cleanup_running','review_required'].includes(clean(rollbackQueue?.state))
        ? clean(rollbackQueue.state)
        : rollbackPassed?'passed':previousUnavailable?'unavailable':queueLayerState(rollbackQueue)},
    ],
    actions:{
      canRevalidate:Boolean(globalVendor && app.source_key),
      canPreparePrevious:Boolean(globalVendor && ['github_releases','winget_manifest','vendor_json','vendor_html'].includes(clean(app.source_type)) && !previousReady),
      canRunClean:Boolean(globalVendor && sourceHealthy && currentArtifactReady && !unsupportedCapabilities.has('clean_install') && !unsupportedCapabilities.has('uninstall')),
      canRunUpgrade:Boolean(globalVendor && cleanPassed && uninstallPassed && currentArtifactReady && previousReady && !unsupportedCapabilities.has('upgrade')),
      canRunFull:Boolean(globalVendor && sourceHealthy && currentArtifactReady && unsupportedCapabilities.size===0),
      canRunRollback:Boolean(globalVendor && cleanPassed && uninstallPassed && upgradePassed && detectionPassed && currentArtifactReady && previousReady && !unsupportedCapabilities.has('rollback')),
      rollbackAvailable:Boolean(globalVendor && cleanPassed && uninstallPassed && upgradePassed && detectionPassed && currentArtifactReady && previousReady && !unsupportedCapabilities.has('rollback')),
    },
    recentJobs:jobResult.rows.map((job)=>({
      id:job.id,
      jobType:clean(job.job_type),
      status:clean(job.status),
      error:clean(job.error_message || job.result_error),
      source:clean(object(job.request_metadata).source),
      stage:clean(object(job.request_metadata).stage),
      resultProvider:clean(job.result_provider),
      verifiedVersion:clean(job.verified_version),
      verificationPassed:clean(job.verification_passed),
      createdAt:job.created_at,
      claimedAt:job.claimed_at,
      completedAt:job.completed_at,
    })),
  }
}

async function patchDiscoveryRows(tenantId) {
  const [observations, candidates] = await Promise.all([
    pool.query(
      `SELECT o.inventory_id,o.catalogue_id,o.application_name,o.display_name,o.publisher,o.installed_version,
              o.provider,o.provider_package_id,o.available_version,o.patch_status,o.evidence,o.source_name,
              o.discovery_method,o.match_confidence,o.observed_at,
              i.reference AS device_reference,i.name AS device_name
         FROM rmm_software_patch_observations o
         JOIN rmm_device_inventory i ON i.id=o.inventory_id
        WHERE o.tenant_id=$1
        ORDER BY o.patch_status='update_available' DESC,lower(o.application_name),lower(i.name)`,
      [tenantId],
    ),
    pool.query(
      `SELECT id,provider,provider_package_id,display_name,publisher,latest_observed_version,
              devices_seen,updates_seen,first_seen_at,last_seen_at,state,metadata
         FROM rmm_patch_catalogue_candidates
        WHERE tenant_id=$1
        ORDER BY updates_seen DESC,devices_seen DESC,lower(display_name),lower(provider_package_id)`,
      [tenantId],
    ),
  ])
  return { observations: observations.rows, candidates: candidates.rows }
}

async function policyRows(tenantId) {
  const result = await pool.query(
    `SELECT id,name,description,software_enabled,windows_enabled,approval_mode,deployment_delay_days,
            maintenance_window,reboot_policy,max_retries,software_rules,windows_rules,status,created_at,updated_at
       FROM rmm_patch_policies
      WHERE tenant_id=$1 AND status<>'archived'
      ORDER BY lower(name)`,
    [tenantId],
  )
  return result.rows
}

async function assignmentRows(tenantId) {
  const result = await pool.query(
    `SELECT id,policy_id,scope_type,scope_id,scope_name,priority,enabled,created_at,updated_at
       FROM rmm_patch_assignments
      WHERE tenant_id=$1
      ORDER BY priority DESC,created_at`,
    [tenantId],
  )
  return result.rows
}

function catalogueDeployabilityWeight(entry) {
  const metadata = object(entry?.source_metadata)
  const mode = clean(metadata.deploymentMode)
  const wingetPackageId = clean(metadata.wingetPackageId || (entry?.provider === 'winget' ? entry?.provider_package_id : ''))
  const wingetReady = entry?.provider === 'winget' || metadata.wingetFallbackReady === true
  if (clean(entry?.qualification_state) === 'blocked') return -100
  if (mode === 'vendor_direct' && clean(metadata.trustState) === 'direct_ready') return 50
  if (mode === 'winget_preferred' && wingetPackageId && wingetReady) return 45
  if (entry?.provider === 'winget' && clean(entry?.provider_package_id)) return 40
  if (mode === 'intelligence_only' || clean(entry?.qualification_state) === 'intelligence_only') return 0
  return 10
}

function catalogueMatch(app, catalogue) {
  const candidates = catalogue.filter((entry) => (
    entry.status === 'active'
    && identityPhraseMatches(app.name, entry.name_pattern)
    && identityPhraseMatches(app.publisher, entry.publisher_pattern)
  ))
  return candidates.sort((a, b) => {
    const deployabilityDelta = catalogueDeployabilityWeight(b) - catalogueDeployabilityWeight(a)
    if (deployabilityDelta) return deployabilityDelta
    const sourceWeight = (entry) => {
      if (entry.catalogue_source === 'tenant_vendor') return 30
      if (entry.catalogue_source === 'vendor') return 25
      if (entry.catalogue_source === 'patchhost') return 10
      return 20
    }
    const sourceDelta = sourceWeight(b) - sourceWeight(a)
    if (sourceDelta) return sourceDelta
    const tenantWeight = Number(Boolean(b.tenant_id)) - Number(Boolean(a.tenant_id))
    if (tenantWeight) return tenantWeight
    const patternDelta = clean(b.name_pattern).length - clean(a.name_pattern).length
    if (patternDelta) return patternDelta
    return new Date(b.updated_at || 0).getTime() - new Date(a.updated_at || 0).getTime()
  })[0] || null
}
function classifyInstallation(app, catalogue) {
  const match = catalogueMatch(app, catalogue)
  if (!match) return { patchStatus: 'unmapped', catalogue: null, targetVersion: '' }
  const targetVersion = clean(match.target_version)
  if (!targetVersion) return { patchStatus: 'detection_pending', catalogue: match, targetVersion: '' }
  const comparison = compareVersions(normalizeCatalogueVersion(app.version, match, 'installed'), targetVersion)
  if (comparison == null) return { patchStatus: 'detection_pending', catalogue: match, targetVersion }
  return {
    patchStatus: comparison < 0 ? 'update_available' : 'current',
    catalogue: match,
    targetVersion,
  }
}

function targetVersionInstalledForCatalogue(items, catalogue) {
  const targetVersion = clean(catalogue?.target_version)
  if (!targetVersion) return false
  return items.some((item) => {
    if (!identityPhraseMatches(item?.name, catalogue?.name_pattern)
      || !identityPhraseMatches(item?.publisher, catalogue?.publisher_pattern)) return false
    const comparison = compareVersions(
      normalizeCatalogueVersion(item?.version, catalogue, 'installed'),
      targetVersion,
    )
    return comparison != null && comparison >= 0
  })
}

function targetProductCodeInstalled(items, catalogue) {
  const verification = object(catalogue?.verification)
  if (clean(verification.method) !== 'uninstall_registry') return false
  const productCode = lower(verification.productCode)
  const targetVersion = clean(catalogue?.target_version)
  if (!productCode || !targetVersion) return false
  return items.some((item) => lower(item?.registry_key) === productCode
    && (compareVersions(normalizeCatalogueVersion(item?.version, catalogue, 'installed'), targetVersion) ?? -1) >= 0)
}

function softwareItems(row) {
  return array(object(object(row.source_payload).software).items)
    .filter((item) => clean(item?.name))
}

function appIdentity(app) {
  return lower(app.name) + '|' + lower(app.publisher)
}

function publicCatalogue(entry) {
  if (!entry) return null
  const sourceMetadata = object(entry.source_metadata)
  const deploymentMode = clean(sourceMetadata.deploymentMode)
  const wingetPackageId = clean(sourceMetadata.wingetPackageId || (entry.provider === 'winget' ? entry.provider_package_id : ''))
  const wingetFallbackReady = entry.provider === 'winget' || sourceMetadata.wingetFallbackReady === true
  const installable = Boolean(
    clean(entry.target_version)
    && clean(entry.qualification_state) !== 'blocked'
    && sourceMetadata.sourceEnabled !== false
    && (
      (deploymentMode === 'winget_preferred' && wingetPackageId && wingetFallbackReady)
      || (deploymentMode === 'vendor_direct' && clean(sourceMetadata.trustState) === 'direct_ready')
      || (entry.provider === 'winget' && clean(entry.provider_package_id))
    )
  )
  return {
    id: entry.id,
    builtIn: !entry.tenant_id,
    canonicalName: entry.canonical_name,
    publisher: entry.publisher,
    namePattern: entry.name_pattern,
    publisherPattern: entry.publisher_pattern,
    provider: entry.provider,
    packageId: entry.provider_package_id,
    executionPackageId: wingetPackageId,
    targetVersion: entry.target_version,
    releaseChannel: entry.release_channel,
    installerType: entry.installer_type,
    deploymentMode,
    trustState: clean(sourceMetadata.trustState || 'version_only'),
    trustEvidence: object(sourceMetadata.trustEvidence),
    releaseUrl: clean(sourceMetadata.releaseUrl),
    selectedAsset: clean(sourceMetadata.selectedAsset),
    expectedSigner: clean(sourceMetadata.expectedSigner || sourceMetadata.signerBaseline),
    verification: object(entry.verification),
    execution: object(entry.execution),
    installable,
    qualificationState: clean(entry.qualification_state || 'intelligence_only'),
    qualificationVersion: clean(entry.qualification_version),
    qualificationEvidence: object(entry.qualification_evidence),
    qualificationReadiness: object(entry.qualification_readiness),
    qualificationNotes: clean(entry.qualification_notes),
    qualifiedAt: entry.qualified_at || null,
    versionNormalization: object(sourceMetadata.versionNormalization),
    vulnerabilityIdentity: {
      nvdVendor: clean(sourceMetadata.nvdVendor),
      nvdProduct: clean(sourceMetadata.nvdProduct),
      osvEcosystem: clean(sourceMetadata.osvEcosystem),
      osvPackage: clean(sourceMetadata.osvPackage),
      githubRepository: clean(sourceMetadata.githubRepository),
      disposition: clean(sourceMetadata.vulnerabilityIdentityDisposition),
      note: clean(sourceMetadata.vulnerabilityIdentityNote),
    },
    vulnerabilityIdentityAudit: object(sourceMetadata.vulnerabilityIdentityAudit),
    status: entry.status,
    catalogueSource: clean(entry.catalogue_source),
    sourceKey: clean(sourceMetadata.latestSource),
    sourceType: clean(sourceMetadata.sourceType),
    registry: clean(sourceMetadata.registry),
    sourceEnabled: sourceMetadata.sourceEnabled !== false,
  }
}
async function vulnerabilityHydrationRows(deviceSoftware = []) {
  const mapped = deviceSoftware.filter((item) => item.catalogue?.id)
  const catalogueIds = [...new Set(mapped.map((item) => item.catalogue.id))]
  if (!catalogueIds.length) return []

  const result = await pool.query(
    `SELECT catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,metadata,updated_at
       FROM rmm_software_vulnerability_identities
      WHERE enabled=true AND catalogue_id=ANY($1::uuid[])
      ORDER BY catalogue_id,updated_at DESC`,
    [catalogueIds],
  )
  const identities = new Map()
  for (const row of result.rows) {
    if (!identities.has(row.catalogue_id)) identities.set(row.catalogue_id, [])
    identities.get(row.catalogue_id).push(row)
  }
  const hydration = new Map()

  for (const item of mapped) {
    const catalogueId = item.catalogue.id
    const rawVersion = clean(item.installedVersion)
    const version = normalizeCatalogueVersion(rawVersion, item.catalogue, 'installed')
    const key = [item.inventoryId, catalogueId, version].join('|')
    if (hydration.has(key)) continue

    const catalogueIdentities = identities.get(catalogueId) || []
    const checks = catalogueIdentities.map((identity) => {
      const metadata = object(identity?.metadata)
      const hydratedVersions = new Set(array(metadata.hydratedVersions).map(clean).filter(Boolean))
      const versionResult = object(object(metadata.versionResults)[version])
      const checked = Boolean(version && hydratedVersions.has(version))
      return { identity, metadata, versionResult, checked }
    })
    const checkedRows = checks.filter((entry) => entry.checked)
    const nvd = catalogueIdentities.find((identity) => identity.source === 'nvd')
    const osv = catalogueIdentities.find((identity) => identity.source === 'osv')
    const latestChecked = checkedRows
      .map((entry) => clean(entry.versionResult.hydratedAt || entry.metadata.hydratedAt))
      .filter(Boolean)
      .sort()
      .at(-1) || ''

    hydration.set(key, {
      inventory_id: item.inventoryId,
      catalogue_id: catalogueId,
      application_name: item.name,
      installed_version: rawVersion,
      evaluated_version: version,
      status: checkedRows.length ? 'checked' : catalogueIdentities.length ? 'pending_version' : 'pending_identity',
      checked: checkedRows.length > 0,
      applicable_cves: checkedRows.length
        ? checkedRows.reduce((sum, entry) => sum + Number(entry.versionResult.applicableCves || 0), 0)
        : null,
      family_total: checkedRows.length
        ? checkedRows.reduce((sum, entry) => sum + Number(entry.versionResult.familyTotal || 0), 0)
        : null,
      checked_at: latestChecked,
      sources: catalogueIdentities.map((identity) => identity.source),
      nvd_vendor: clean(nvd?.vendor),
      nvd_product: clean(nvd?.product),
      nvd_cpe: clean(nvd?.cpe),
      osv_ecosystem: clean(osv?.ecosystem),
      osv_package_name: clean(osv?.package_name),
    })
  }

  return [...hydration.values()]
}

function buildSoftware(devices, catalogue, observations = []) {
  const applications = new Map()
  const deviceSoftware = []
  const observationMap = new Map(
    observations.map((item) => [
      item.inventory_id + '|' + lower(item.provider_package_id),
      item,
    ]),
  )
  for (const device of devices) {
    const items = softwareItems(device)
    for (const app of items) {
      const state = classifyInstallation(app, catalogue)
      if (state.catalogue && (
        targetVersionInstalledForCatalogue(items, state.catalogue)
        || targetProductCodeInstalled(items, state.catalogue)
      )) {
        const verification = object(state.catalogue.verification)
        const targetCode = lower(verification.productCode)
        const appCode = lower(app?.registry_key)
        const comparison = compareVersions(normalizeCatalogueVersion(app?.version, state.catalogue, 'installed'), state.targetVersion)
        state.patchStatus = (targetCode && appCode === targetCode) || (comparison != null && comparison >= 0)
          ? 'current'
          : 'older_version_present'
      }
      const observation = state.catalogue?.provider_package_id
        ? observationMap.get(device.inventory_id + '|' + lower(state.catalogue.provider_package_id))
        : null
      if (state.patchStatus === 'update_available' && observation?.patch_status === 'provider_blocked') {
        state.patchStatus = 'provider_blocked'
      }
      const key = appIdentity(app)
      const row = {
        key,
        deviceId: device.reference,
        inventoryId: device.inventory_id,
        agentDeviceId: device.agent_device_id,
        deviceName: device.name,
        online: device.online,
        name: clean(app.name),
        publisher: clean(app.publisher),
        installedVersion: clean(app.version),
        scope: clean(app.scope),
        registryKey: clean(app.registry_key),
        patchStatus: state.patchStatus,
        targetVersion: state.targetVersion,
        providerBlockedReason: state.patchStatus === 'provider_blocked'
          ? clean(object(observation?.evidence).providerBlockedDetail || object(observation?.evidence).providerBlockedReason)
          : '',
        catalogue: publicCatalogue(state.catalogue),
      }
      deviceSoftware.push(row)
      const grouped = applications.get(key) || {
        key,
        name: row.catalogue?.canonicalName || row.name,
        publisher: row.catalogue?.publisher || row.publisher,
        installs: 0,
        deviceIds: new Set(),
        versions: new Map(),
        updateAvailable: 0,
        providerBlocked: 0,
        olderVersionPresent: 0,
        current: 0,
        detectionPending: 0,
        unmapped: 0,
        catalogue: row.catalogue,
      }
      grouped.installs += 1
      grouped.deviceIds.add(row.deviceId)
      grouped.versions.set(row.installedVersion || 'Not reported', (grouped.versions.get(row.installedVersion || 'Not reported') || 0) + 1)
      if (state.patchStatus === 'update_available') grouped.updateAvailable += 1
      else if (state.patchStatus === 'provider_blocked') grouped.providerBlocked += 1
      else if (state.patchStatus === 'older_version_present') grouped.olderVersionPresent += 1
      else if (state.patchStatus === 'current') grouped.current += 1
      else if (state.patchStatus === 'detection_pending') grouped.detectionPending += 1
      else grouped.unmapped += 1
      applications.set(key, grouped)
    }
  }
  return {
    applications: [...applications.values()].map((item) => ({
      ...item,
      deviceCount: item.deviceIds.size,
      deviceIds: [...item.deviceIds],
      versions: [...item.versions.entries()]
        .map(([version, count]) => ({ version, count }))
        .sort((a, b) => compareVersions(a.version, b.version) ?? a.version.localeCompare(b.version)),
    })).sort((a, b) => a.name.localeCompare(b.name)),
    deviceSoftware,
  }
}

async function reconcileTerminalPatchDeployments(tenantId) {
  await pool.query(
    `UPDATE rmm_patch_deployments d
        SET status=CASE
              WHEN j.status='completed'
                AND lower(COALESCE(j.result->>'rebootRequired',j.result->>'reboot_required','false'))='true'
                THEN 'reboot_required'
              WHEN j.status='completed' THEN 'succeeded'
              WHEN j.status='cancelled' THEN 'cancelled'
              WHEN j.status='failed'
                AND lower(COALESCE(j.result->>'verificationFailed',j.result->>'verification_failed','false'))='true'
                THEN 'verification_failed'
              ELSE 'failed'
            END,
            result=COALESCE(j.result,'{}'::jsonb),
            completed_at=COALESCE(d.completed_at,j.completed_at,now()),
            updated_at=now()
       FROM rmm_agent_jobs j
      WHERE d.tenant_id=$1
        AND d.agent_job_id=j.id
        AND j.job_type<>'patch.software.bulk'
        AND d.status IN ('eligible','running')
        AND j.status IN ('completed','failed','cancelled')`,
    [tenantId],
  )
}



function sideBySidePolicy(catalogue) {
  const configured = clean(object(catalogue?.source_metadata).sideBySidePolicy)
  if (['replace','allow','require_clean'].includes(configured)) return configured
  const evidence = object(catalogue?.qualification_evidence)
  if (
    evidence.upgradeVerified === true
    && evidence.rollbackVerified === true
    && evidence.uninstallVerified === true
  ) return 'replace'
  return 'require_clean'
}

function supersededInventoryInstances(sourcePayload, catalogue, targetVersion) {
  return softwareItems({ source_payload: sourcePayload })
    .filter((item) => identityPhraseMatches(item?.name, catalogue.name_pattern)
      && identityPhraseMatches(item?.publisher, catalogue.publisher_pattern))
    .filter((item) => {
      const version = normalizeCatalogueVersion(item?.version, catalogue, 'installed')
      const comparison = compareVersions(version, targetVersion)
      return comparison != null && comparison < 0
    })
}

async function dispatchSupersededRemediation(tenantId, deployment) {
  if (sideBySidePolicy(deployment) !== 'replace') return { dispatched: 0, policy: sideBySidePolicy(deployment) }
  const liveSocket = agentSocketForDevice(deployment.agent_device_id)
  if (!liveSocket || liveSocket.readyState !== 1) return { dispatched: 0, policy: 'replace', offline: true }
  const oldInstances = supersededInventoryInstances(deployment.source_payload, deployment, deployment.target_version)
  let dispatched = 0
  for (const instance of oldInstances) {
    const payload = { name: clean(instance.name), registry_key: clean(instance.registry_key), scope: clean(instance.scope), user_profile: clean(instance.user_profile) }
    if (!payload.name && !payload.registry_key) continue
    const duplicate = await pool.query(
      `SELECT id FROM rmm_agent_jobs WHERE tenant_id=$1 AND agent_device_id=$2 AND job_type='software.uninstall'
        AND request_metadata->>'source'='patch_superseded_remediation' AND request_metadata->>'parent_deployment_id'=$3
        AND payload=$4::jsonb AND status IN ('queued','claimed','completed') LIMIT 1`,
      [tenantId, deployment.agent_device_id, clean(deployment.id), JSON.stringify(payload)])
    if (duplicate.rowCount) continue
    const inserted = await pool.query(
      `INSERT INTO rmm_agent_jobs (tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,request_metadata)
       VALUES ($1,$2,'software.uninstall',$3::jsonb,$4,'system','SYSTEM',$5::jsonb) RETURNING id,created_at`,
      [tenantId, deployment.agent_device_id, JSON.stringify(payload), deployment.requested_by_user_id || null,
       JSON.stringify({ source: 'patch_superseded_remediation', parent_deployment_id: clean(deployment.id), catalogue_id: clean(deployment.catalogue_id), target_version: clean(deployment.target_version) })])
    const job = inserted.rows[0]
    const claimed = await pool.query(`UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now() WHERE id=$1 AND tenant_id=$2 AND status='queued' RETURNING id`, [job.id, tenantId])
    if (!claimed.rowCount) continue
    const pushed = sendAgentMessage(deployment.agent_device_id, { type: 'job_execute', job: { id: job.id, job_type: 'software.uninstall', payload, created_at: job.created_at } })
    if (!pushed) { await pool.query(`UPDATE rmm_agent_jobs SET status='cancelled',claimed_at=NULL,completed_at=now(),error_message='Device went offline before superseded-version remediation could dispatch.',updated_at=now() WHERE id=$1`, [job.id]); continue }
    dispatched += 1
  }
  return { dispatched, policy: 'replace', supersededCount: oldInstances.length }
}

async function reconcileSupersededPatchDeployments(tenantId) {
  const result = await pool.query(
    `SELECT d.id,d.catalogue_id,d.inventory_id,d.agent_job_id,d.target_version,d.requested_by_user_id,
            c.canonical_name,c.name_pattern,c.publisher_pattern,c.source_metadata,c.qualification_evidence,i.source_payload,a.id AS agent_device_id
       FROM rmm_patch_deployments d JOIN rmm_software_catalogue c ON c.id=d.catalogue_id
       JOIN rmm_device_inventory i ON i.id=d.inventory_id
       JOIN rmm_agent_devices a ON a.inventory_id=i.id AND a.tenant_id=d.tenant_id AND a.disabled_at IS NULL
      WHERE d.tenant_id=$1 AND d.status='remediation_required' ORDER BY d.created_at`, [tenantId])
  for (const deployment of result.rows) {
    const matches = softwareItems({ source_payload: deployment.source_payload }).filter((item) => identityPhraseMatches(item?.name, deployment.name_pattern) && identityPhraseMatches(item?.publisher, deployment.publisher_pattern))
    const targetPresent = matches.some((item) => { const comparison = compareVersions(normalizeCatalogueVersion(item?.version, deployment, 'installed'), deployment.target_version); return comparison != null && comparison >= 0 })
    const superseded = supersededInventoryInstances(deployment.source_payload, deployment, deployment.target_version)
    if (targetPresent && superseded.length === 0) {
      await pool.query(`UPDATE rmm_patch_deployments SET status='succeeded',result=(result-'error') || $3::jsonb,updated_at=now() WHERE tenant_id=$1 AND id=$2 AND status='remediation_required'`, [tenantId, deployment.id, JSON.stringify({ success: true, verificationPassed: true, supersededRemediationPassed: true, remediatedAt: new Date().toISOString() })])
    } else if (targetPresent && superseded.length && sideBySidePolicy(deployment) === 'replace') await dispatchSupersededRemediation(tenantId, deployment)
  }
}

async function reconcileBulkPatchDeployments(tenantId) {
  const result = await pool.query(
    `SELECT d.id,d.catalogue_id,d.inventory_id,d.agent_job_id,d.application_name,d.provider_package_id,d.target_version,d.status,d.requested_by_user_id,
            j.status AS job_status,j.result AS job_result,j.error_message,j.completed_at,
            c.canonical_name,c.name_pattern,c.publisher_pattern,c.source_metadata,c.qualification_evidence,i.source_payload,a.id AS agent_device_id
       FROM rmm_patch_deployments d
       JOIN rmm_agent_jobs j ON j.id=d.agent_job_id AND j.tenant_id=d.tenant_id
       LEFT JOIN rmm_software_catalogue c ON c.id=d.catalogue_id
       JOIN rmm_device_inventory i ON i.id=d.inventory_id
       JOIN rmm_agent_devices a ON a.inventory_id=i.id AND a.tenant_id=d.tenant_id AND a.disabled_at IS NULL
      WHERE d.tenant_id=$1
        AND j.job_type='patch.software.bulk'
        AND d.status IN ('eligible','running')
        AND j.status IN ('completed','failed','cancelled')
      ORDER BY d.created_at`,
    [tenantId],
  )

  for (const deployment of result.rows) {
    const jobResult = object(deployment.job_result)
    const items = array(jobResult.items)
    const catalogueId = clean(deployment.catalogue_id)
    const packageId = clean(deployment.provider_package_id)
    const item = (catalogueId
      ? items.find((entry) => clean(entry?.catalogueId) === catalogueId)
      : null)
      || (packageId
        ? items.find((entry) => lower(entry?.packageId) === lower(packageId))
        : null)
      || items.find((entry) => clean(entry?.applicationName) === clean(deployment.application_name)
        && clean(entry?.targetVersion) === clean(deployment.target_version))
      || null

    const inventorySuperseded = catalogueId
      ? supersededInventoryInstances(deployment.source_payload, deployment, deployment.target_version)
      : []
    const verificationVersions = array(object(item?.verification).installedVersions).map((value) => clean(value)).filter(Boolean)
    const targetObserved = verificationVersions.some((version) => compareVersions(version, deployment.target_version) >= 0)
      || (catalogueId && softwareItems({ source_payload: deployment.source_payload }).some((installed) => identityPhraseMatches(installed?.name, deployment.name_pattern)
        && identityPhraseMatches(installed?.publisher, deployment.publisher_pattern)
        && compareVersions(normalizeCatalogueVersion(installed?.version, deployment, 'installed'), deployment.target_version) >= 0))
    let status = 'failed'
    if (deployment.job_status === 'cancelled') status = 'cancelled'
    else if (item?.success === true && inventorySuperseded.length === 0) {
      status = item.rebootRequired === true || item.reboot_required === true ? 'reboot_required' : 'succeeded'
    } else if (targetObserved && inventorySuperseded.length > 0 && sideBySidePolicy(deployment) !== 'allow') {
      status = 'remediation_required'
    } else if (
      item?.verificationFailed === true
      || item?.verification_failed === true
      || clean(item?.error) === 'target_version_not_verified'
      || clean(item?.error) === 'target_version_not_verified_after_successful_installer'
    ) {
      status = 'verification_failed'
    }

    const deploymentResult = item
      ? { ...item, bulk: { mode: clean(jobResult.mode), attemptedCount: Number(jobResult.attemptedCount || 0), succeededCount: Number(jobResult.succeededCount || 0), failedCount: Number(jobResult.failedCount || 0) } }
      : { bulk: jobResult, error: clean(deployment.error_message) || 'Bulk job did not return an item result for this deployment.' }

    await pool.query(
      `UPDATE rmm_patch_deployments
          SET status=$3,result=$4::jsonb,completed_at=COALESCE(completed_at,$5,now()),updated_at=now()
        WHERE tenant_id=$1 AND id=$2 AND status IN ('eligible','running')`,
      [tenantId, deployment.id, status, JSON.stringify(deploymentResult), deployment.completed_at],
    )

    if (status === 'remediation_required') {
      const remediation = await dispatchSupersededRemediation(tenantId, deployment)
      await pool.query(`UPDATE rmm_patch_deployments SET result=result || $3::jsonb,updated_at=now() WHERE tenant_id=$1 AND id=$2`,
        [tenantId, deployment.id, JSON.stringify({ supersededRemediation: remediation, supersededInstances: inventorySuperseded.map((entry) => ({ name: clean(entry.name), version: clean(entry.version), scope: clean(entry.scope), registryKey: clean(entry.registry_key) })) })])
    }

    if (catalogueId && ['failed','verification_failed','cancelled'].includes(status)) {
      await pool.query(
        `UPDATE rmm_vulnerability_exposures
            SET remediation_state='available',last_seen_at=now()
          WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id=$3
            AND status='open' AND remediation_state='in_progress'`,
        [tenantId, deployment.inventory_id, catalogueId],
      )
    }
  }
}

async function reconcileVendorProductCodeDeployments(tenantId) {
  const result = await pool.query(
    `SELECT d.id,d.agent_job_id,d.inventory_id,d.application_name,d.installed_version,d.target_version,d.provider,
            c.verification,i.source_payload,
            COALESCE(NULLIF(j.initiated_by_label,''),'Technician') AS actor_label
       FROM rmm_patch_deployments d
       JOIN rmm_software_catalogue c ON c.id=d.catalogue_id
       JOIN rmm_device_inventory i ON i.id=d.inventory_id
       LEFT JOIN rmm_agent_jobs j ON j.id=d.agent_job_id
      WHERE d.tenant_id=$1
        AND d.status='verification_failed'
        AND d.provider='vendor_direct'
        AND COALESCE(c.verification->>'method','')='uninstall_registry'
        AND COALESCE(c.verification->>'productCode','')<>''
        AND d.completed_at>now()-interval '24 hours'
      ORDER BY d.created_at DESC`,
    [tenantId],
  )

  for (const deployment of result.rows) {
    if (!targetProductCodeInstalled(
      softwareItems({ source_payload: deployment.source_payload }),
      { verification: deployment.verification, target_version: deployment.target_version },
    )) continue

    const reconciliation = {
      success: true,
      verificationPassed: true,
      verificationFailed: false,
      lateVerification: true,
      lateVerifiedVersion: clean(deployment.target_version),
      lateVerifiedAt: new Date().toISOString(),
      reconciliationSource: 'target_product_code_inventory',
      targetProductCode: clean(object(deployment.verification).productCode),
    }

    await withTransaction(async (client) => {
      await client.query(
        `UPDATE rmm_patch_deployments
            SET status='succeeded',
                result=(result - 'error') || $3::jsonb,
                updated_at=now()
          WHERE tenant_id=$1 AND id=$2 AND status='verification_failed'`,
        [tenantId, deployment.id, JSON.stringify(reconciliation)],
      )
      if (deployment.agent_job_id) {
        await client.query(
          `UPDATE rmm_agent_jobs
              SET status='completed',
                  result=(result - 'error') || $3::jsonb,
                  error_message=NULL,
                  updated_at=now()
            WHERE tenant_id=$1 AND id=$2 AND status='failed'`,
          [tenantId, deployment.agent_job_id, JSON.stringify(reconciliation)],
        )
        await client.query(
          `UPDATE rmm_activity_events
              SET outcome='success',
                  severity='info',
                  summary=$3,
                  detail=$4,
                  metadata=metadata || $5::jsonb
            WHERE tenant_id=$1 AND job_id=$2 AND event_type='patch.software'`,
          [
            tenantId,
            deployment.agent_job_id,
            deployment.actor_label + ' patched “' + deployment.application_name + '”',
            [
              clean(deployment.installed_version) && clean(deployment.target_version)
                ? clean(deployment.installed_version) + ' → ' + clean(deployment.target_version)
                : '',
              'Provider: vendor_direct',
              'Verified by target MSI ProductCode after inventory refresh',
              'Job successful · See details',
            ].filter(Boolean).join(' · '),
            JSON.stringify(reconciliation),
          ],
        )
      }
    })
  }
}

async function vulnerabilityCatalogueCoverage() {
  const result = await pool.query(
    `SELECT c.id,c.canonical_name,c.platform,c.provider,c.provider_package_id,c.catalogue_source,
            c.source_metadata,c.updated_at,
            count(vi.id)::int AS identity_count,
            bool_or(vi.source='nvd') FILTER (WHERE vi.id IS NOT NULL) AS has_nvd,
            bool_or(vi.source='osv') FILTER (WHERE vi.id IS NOT NULL) AS has_osv,
            max(vi.updated_at) AS identity_updated_at,
            s.last_success_at AS source_last_success_at,s.last_error AS source_last_error
       FROM rmm_software_catalogue c
       LEFT JOIN rmm_software_vulnerability_identities vi
         ON vi.catalogue_id=c.id AND vi.enabled=true
       LEFT JOIN rmm_software_vendor_sources s
         ON s.source_key=c.source_metadata->>'latestSource'
      WHERE c.status='active'
      GROUP BY c.id,s.last_success_at,s.last_error
      ORDER BY lower(c.canonical_name),c.platform`,
  )
  const rows = result.rows.map((row) => {
    const identityCount = Number(row.identity_count || 0)
    const sourceMetadata = object(row.source_metadata)
    const identityAudit = object(sourceMetadata.vulnerabilityIdentityAudit)
    const sourceConfigured = Boolean(clean(sourceMetadata.latestSource))
    const audited = Boolean(clean(identityAudit.checkedAt))
    const state = clean(identityAudit.state) === 'covered'
      ? 'covered'
      : identityCount > 0
        ? 'validation_pending'
        : sourceConfigured && !row.source_last_success_at
          ? 'source_pending'
          : 'needs_identity'
    return {
      id: row.id,
      canonicalName: row.canonical_name,
      platform: row.platform,
      provider: row.provider,
      packageId: row.provider_package_id,
      catalogueSource: row.catalogue_source,
      identityCount,
      audited,
      auditState: clean(identityAudit.state),
      auditCheckedAt: clean(identityAudit.checkedAt),
      hasNvd: row.has_nvd === true,
      hasOsv: row.has_osv === true,
      identityUpdatedAt: row.identity_updated_at,
      sourceLastSuccessAt: row.source_last_success_at,
      sourceError: clean(row.source_last_error),
      state,
    }
  })
  return {
    total: rows.length,
    covered: rows.filter((row) => row.state === 'covered').length,
    audited: rows.filter((row) => row.audited).length,
    unchecked: rows.filter((row) => !row.audited).length,
    nvd: rows.filter((row) => row.hasNvd).length,
    osv: rows.filter((row) => row.hasOsv).length,
    validationPending: rows.filter((row) => row.state === 'validation_pending').length,
    sourcePending: rows.filter((row) => row.state === 'source_pending').length,
    needsIdentity: rows.filter((row) => row.state === 'needs_identity').length,
    reviewedAt: new Date().toISOString(),
    needsReview: rows.filter((row) => row.state !== 'covered').slice(0, 250),
  }
}

async function devicePatchRejectionRows(tenantId) {
  const result = await pool.query(
    `SELECT r.id,r.agent_device_id,r.catalogue_id,r.target_version,r.reason,r.rejected_by_label,r.created_at,
            c.canonical_name AS application_name
       FROM rmm_device_patch_rejections r
       JOIN rmm_software_catalogue c ON c.id=r.catalogue_id
      WHERE r.tenant_id=$1 AND r.revoked_at IS NULL
      ORDER BY r.created_at DESC`,
    [tenantId],
  )
  return result.rows
}

export async function reconcilePatchDeployments(tenantId) {
  await reconcileBulkPatchDeployments(tenantId)
  await reconcileSupersededPatchDeployments(tenantId)
  await reconcileTerminalPatchDeployments(tenantId)
  await reconcileVendorProductCodeDeployments(tenantId)
}

async function patchBundle(tenantId) {
  await reconcilePatchDeployments(tenantId)
  const [devices, catalogue, policies, assignments, vulnerabilities, discovery, vendorIntel, tenantVendorSources, exposureSummary, softwareVulnerabilityExposures, vulnerabilityExposureRowsData, deployments, vulnerabilityCatalogue, devicePatchRejections, qualificationQueue, windowsUpdates] = await Promise.all([
    patchDeviceRows(tenantId),
    catalogueRows(tenantId),
    policyRows(tenantId),
    assignmentRows(tenantId),
    vulnerabilitySummary(),
    patchDiscoveryRows(tenantId),
    softwareVendorSummary(),
    listTenantVendorSources(tenantId),
    vulnerabilityExposureSummary(tenantId),
    vulnerabilityExposureByInstallation(tenantId),
    vulnerabilityExposureRows(tenantId, 250),
    patchDeploymentRows(tenantId),
    vulnerabilityCatalogueCoverage(),
    devicePatchRejectionRows(tenantId),
    qualificationQueueSummary(tenantId),
    windowsUpdateBundle(tenantId),
  ])
  const software = buildSoftware(devices, catalogue, discovery.observations)
  const vulnerabilityHydration = await vulnerabilityHydrationRows(software.deviceSoftware)
  const updateAvailable = software.deviceSoftware.filter((item) => item.patchStatus === 'update_available').length
  const mapped = software.deviceSoftware.filter((item) => item.catalogue).length
  return {
    overview: {
      agentDevices: devices.length,
      softwareInstallations: software.deviceSoftware.length,
      mappedInstallations: mapped,
      updateAvailable,
      unmappedInstallations: software.deviceSoftware.length - mapped,
      autoDiscoveredPackages: discovery.candidates.length,
      autoDiscoveredUpdates: discovery.observations.filter((item) => item.patch_status === 'update_available').length,
      qualifiedCatalogue: catalogue.filter((item) => ['qualified','qualified_limited'].includes(item.qualification_state)).length,
      fullyQualifiedCatalogue: catalogue.filter((item) => item.qualification_state === 'qualified').length,
      limitedQualifiedCatalogue: catalogue.filter((item) => item.qualification_state === 'qualified_limited').length,
      automaticAdmissionReadyCatalogue: catalogue.filter((item) => object(item.qualification_readiness).automaticAdmissionReady === true).length,
      capabilityAdmissionReadyCatalogue: catalogue.filter((item) => object(item.qualification_readiness).capabilityAdmissionReady === true).length,
      candidateCatalogue: catalogue.filter((item) => item.qualification_state === 'deployment_candidate').length,
      blockedCatalogue: catalogue.filter((item) => item.qualification_state === 'blocked').length,
      intelligenceOnlyCatalogue: catalogue.filter((item) => item.qualification_state === 'intelligence_only').length,
    },
    catalogue: catalogue.map(publicCatalogue),
    catalogueCandidates: discovery.candidates,
    patchObservations: discovery.observations,
    applications: software.applications,
    deviceSoftware: software.deviceSoftware,
    policies,
    assignments,
    deployments,
    windowsUpdates,
    vulnerabilities,
    vulnerabilityExposures: exposureSummary,
    softwareVulnerabilityExposures,
    vulnerabilityHydration,
    vulnerabilityExposureRows: vulnerabilityExposureRowsData,
    vulnerabilityCatalogue,
    devicePatchRejections,
    qualificationQueue,
    qualificationProgress: {
      cleanInstallPassed: new Set(qualificationQueue.filter(q => q.test_type === 'clean_install' && q.state === 'passed').map(q => q.catalogue_id)).size,
      upgradePassed: new Set(qualificationQueue.filter(q => q.test_type === 'upgrade' && q.state === 'passed').map(q => q.catalogue_id)).size,
      rollbackPassed: new Set(qualificationQueue.filter(q => q.test_type === 'rollback' && q.state === 'passed').map(q => q.catalogue_id)).size,
      fullyQualified: catalogue.filter(c => c.qualification_state === 'qualified').length,
      limitedQualified: catalogue.filter(c => c.qualification_state === 'qualified_limited').length,
      failureGroups: qualificationFailureGroups(qualificationQueue),
    },
    vendorIntel: { ...vendorIntel, tenantSources: tenantVendorSources },
    devices: devices.map((device) => ({
      id: device.reference,
      inventoryId: device.inventory_id,
      agentDeviceId: device.agent_device_id,
      name: device.name,
      online: device.online,
      siteId: device.site_id || '',
      site: device.site_name || '',
      agentVersion: device.agent_version || '',
      patchCapabilities: object(device.patch_capabilities),
      patchCapabilitiesAt: device.patch_capabilities_at,
      patchDiscoveryAt: device.patch_discovery_at,
    })),
  }
}
function normalizePatchDiscoveryPackage(value = {}) {
  const packageId = clean(value.packageId || value.id)
  if (!packageId || packageId.length > 240) return null
  const installedVersion = clean(value.installedVersion || value.version).slice(0, 120)
  const availableVersion = clean(value.availableVersion).slice(0, 120)
  const installedInstances = array(value.installedInstances)
    .map((version) => clean(version).slice(0, 120))
    .filter(Boolean)
    .slice(0, 50)
  return {
    packageId,
    name: clean(value.name || value.displayName || packageId).slice(0, 320),
    publisher: clean(value.publisher).slice(0, 240),
    installedVersion,
    installedInstances,
    availableVersion,
    source: clean(value.source || 'winget').slice(0, 80),
    scope: clean(value.scope).slice(0, 80),
    architecture: clean(value.architecture).slice(0, 80),
  }
}

async function reconcilePatchDeploymentFromDiscovery(client, agent, catalogue, item, targetVersion) {
  const catalogueId = catalogue?.id
  const installedVersion = normalizeCatalogueVersion(item.installedVersion, catalogue, 'installed')
  if (!catalogueId || !targetVersion || compareVersions(installedVersion, targetVersion) < 0) return null

  const result = await client.query(
    `SELECT d.id,d.agent_job_id,d.application_name,d.installed_version,d.target_version,d.provider,
            COALESCE(NULLIF(j.initiated_by_label,''),'Technician') AS actor_label
       FROM rmm_patch_deployments d
       LEFT JOIN rmm_agent_jobs j ON j.id=d.agent_job_id
      WHERE d.tenant_id=$1 AND d.inventory_id=$2 AND d.catalogue_id=$3
        AND d.target_version=$4
        AND d.provider='winget'
        AND d.status='verification_failed'
        AND COALESCE(d.result->>'error','')='target_version_not_verified'
        AND d.completed_at>now()-interval '6 hours'
      ORDER BY d.created_at DESC
      LIMIT 1
      FOR UPDATE OF d`,
    [agent.tenant_id, agent.inventory_id, catalogueId, targetVersion],
  )
  const deployment = result.rows[0]
  if (!deployment) return null

  const reconciliation = {
    success: true,
    verificationPassed: true,
    verificationFailed: false,
    lateVerification: true,
    lateVerifiedVersion: item.installedVersion,
    lateVerifiedAt: new Date().toISOString(),
    reconciliationSource: 'patchhost_discovery',
  }

  await client.query(
    `UPDATE rmm_patch_deployments
        SET status='succeeded',
            result=(result - 'error') || $4::jsonb,
            updated_at=now()
      WHERE tenant_id=$1 AND inventory_id=$2 AND id=$3`,
    [agent.tenant_id, agent.inventory_id, deployment.id, JSON.stringify(reconciliation)],
  )
  await client.query(
    `UPDATE rmm_agent_jobs
        SET status='completed',
            result=(result - 'error') || $3::jsonb,
            error_message=NULL,
            updated_at=now()
      WHERE tenant_id=$1 AND id=$2`,
    [agent.tenant_id, deployment.agent_job_id, JSON.stringify(reconciliation)],
  )

  const detail = [
    clean(deployment.installed_version) && clean(deployment.target_version)
      ? clean(deployment.installed_version) + ' → ' + clean(deployment.target_version)
      : '',
    clean(deployment.provider) ? 'Provider: ' + clean(deployment.provider) : '',
    'Verified after inventory refresh',
    'Job successful · See details',
  ].filter(Boolean).join(' · ')

  await client.query(
    `UPDATE rmm_activity_events
        SET outcome='success',
            severity='info',
            summary=$3,
            detail=$4,
            metadata=metadata || $5::jsonb
      WHERE tenant_id=$1 AND job_id=$2 AND event_type='patch.software'`,
    [
      agent.tenant_id,
      deployment.agent_job_id,
      deployment.actor_label + ' patched “' + deployment.application_name + '”',
      detail,
      JSON.stringify({
        lateVerification: true,
        lateVerifiedVersion: item.installedVersion,
        reconciliationSource: 'patchhost_discovery',
      }),
    ],
  )

  return deployment.id
}

async function ingestPatchDiscovery(agent, body = {}) {
  const packages = array(body.packages)
    .slice(0, 2500)
    .map(normalizePatchDiscoveryPackage)
    .filter(Boolean)
  const capabilities = object(body.capabilities)
  const hostVersion = clean(capabilities.patchHostVersion || capabilities.version).slice(0, 80)
  let reconciledDeployments = 0

  await withTransaction(async (client) => {
    await client.query(
      `UPDATE rmm_agent_devices
          SET patch_capabilities=$2::jsonb,patch_capabilities_at=now(),patch_discovery_at=now(),updated_at=now()
        WHERE id=$1`,
      [agent.id, JSON.stringify({ ...capabilities, patchHostVersion: hostVersion })],
    )

    await client.query(
      `DELETE FROM rmm_software_patch_observations
        WHERE tenant_id=$1 AND inventory_id=$2 AND discovery_method='patchhost_winget'`,
      [agent.tenant_id, agent.inventory_id],
    )

    for (const item of packages) {
      const applicationKey = 'winget|' + lower(item.packageId)
      let catalogue = await client.query(
        `SELECT id,target_version,tenant_id,catalogue_source,source_metadata
           FROM rmm_software_catalogue
          WHERE status='active'
            AND (
              (provider='winget' AND lower(provider_package_id)=lower($2))
              OR lower(COALESCE(source_metadata->>'wingetPackageId',''))=lower($2)
              OR lower(COALESCE(source_metadata->>'autoWingetPackageId',''))=lower($2)
            )
            AND (tenant_id=$1 OR tenant_id IS NULL)
          ORDER BY tenant_id NULLS LAST,
                   CASE WHEN source_metadata->>'deploymentMode'='vendor_direct' THEN 0 ELSE 1 END
          LIMIT 1`,
        [agent.tenant_id, item.packageId],
      )

      // WinGet discovery remains a repository/observation layer. It no longer
      // manufactures catalogue rows for every package seen on an endpoint.
      // Only explicitly curated or user-added catalogue entries are attached.

      const catalogueEntry = catalogue.rows[0] || {}
      const targetVersion = clean(catalogueEntry.target_version)
      const availableVersion = item.availableVersion || targetVersion
      const installedForComparison = normalizeCatalogueVersion(item.installedVersion, catalogueEntry, 'installed')
      const availableForComparison = item.availableVersion
        ? normalizeCatalogueVersion(item.availableVersion, catalogueEntry, 'provider')
        : targetVersion
      const comparison = availableForComparison
        ? compareVersions(installedForComparison, availableForComparison)
        : null
      const patchStatus = availableVersion && comparison != null
        ? (comparison < 0 ? 'update_available' : 'current')
        : 'current'

      await client.query(
        `INSERT INTO rmm_software_patch_observations
          (tenant_id,inventory_id,catalogue_id,application_key,application_name,display_name,publisher,
           installed_version,provider,provider_package_id,available_version,patch_status,evidence,
           source_name,discovery_method,match_confidence,observed_at,updated_at)
         VALUES ($1,$2,$3,$4,$5,$5,$6,$7,'winget',$8,$9,$10,$11::jsonb,$12,'patchhost_winget','source',now(),now())
         ON CONFLICT (tenant_id,inventory_id,application_key) DO UPDATE SET
           catalogue_id=EXCLUDED.catalogue_id,application_name=EXCLUDED.application_name,display_name=EXCLUDED.display_name,
           publisher=EXCLUDED.publisher,installed_version=EXCLUDED.installed_version,provider=EXCLUDED.provider,
           provider_package_id=EXCLUDED.provider_package_id,available_version=EXCLUDED.available_version,
           patch_status=CASE
             WHEN rmm_software_patch_observations.patch_status='provider_blocked'
               AND rmm_software_patch_observations.available_version=EXCLUDED.available_version
               AND rmm_software_patch_observations.evidence->'installedInstances'=EXCLUDED.evidence->'installedInstances'
             THEN 'provider_blocked'
             ELSE EXCLUDED.patch_status
           END,
           evidence=CASE
             WHEN rmm_software_patch_observations.patch_status='provider_blocked'
               AND rmm_software_patch_observations.available_version=EXCLUDED.available_version
               AND rmm_software_patch_observations.evidence->'installedInstances'=EXCLUDED.evidence->'installedInstances'
             THEN EXCLUDED.evidence || jsonb_build_object(
               'providerBlockedReason',rmm_software_patch_observations.evidence->>'providerBlockedReason',
               'providerBlockedAt',rmm_software_patch_observations.evidence->>'providerBlockedAt',
               'providerBlockedJobId',rmm_software_patch_observations.evidence->>'providerBlockedJobId',
               'providerBlockedDetail',rmm_software_patch_observations.evidence->>'providerBlockedDetail'
             )
             ELSE EXCLUDED.evidence
           END,
           source_name=EXCLUDED.source_name,
           discovery_method=EXCLUDED.discovery_method,match_confidence=EXCLUDED.match_confidence,
           observed_at=now(),updated_at=now()`,
        [
          agent.tenant_id,
          agent.inventory_id,
          catalogue.rows[0]?.id || null,
          applicationKey,
          item.name,
          item.publisher,
          item.installedVersion,
          item.packageId,
          availableVersion,
          patchStatus,
          JSON.stringify({
            scope: item.scope,
            architecture: item.architecture,
            patchHostVersion: hostVersion,
            installedInstances: item.installedInstances,
          }),
          item.source,
        ],
      )

      if (patchStatus === 'current' && catalogue.rows[0]?.id && targetVersion) {
        const reconciled = await reconcilePatchDeploymentFromDiscovery(
          client,
          agent,
          catalogue.rows[0],
          item,
          targetVersion,
        )
        if (reconciled) reconciledDeployments += 1
      }
    }

    await client.query(
      `INSERT INTO rmm_patch_catalogue_candidates
        (tenant_id,provider,provider_package_id,display_name,publisher,latest_observed_version,devices_seen,updates_seen,last_seen_at,metadata)
       SELECT tenant_id,'winget',provider_package_id,
              COALESCE(max(NULLIF(display_name,'')),provider_package_id),
              COALESCE(max(NULLIF(publisher,'')),''),
              COALESCE(max(NULLIF(available_version,'')),max(NULLIF(installed_version,'')),''),
              count(DISTINCT inventory_id)::int,
              count(*) FILTER (WHERE patch_status='update_available')::int,
              now(),jsonb_build_object('discovery','patchhost_winget')
         FROM rmm_software_patch_observations
        WHERE tenant_id=$1 AND provider='winget' AND provider_package_id<>''
        GROUP BY tenant_id,provider_package_id
       ON CONFLICT (tenant_id,provider,provider_package_id) DO UPDATE SET
         display_name=EXCLUDED.display_name,publisher=EXCLUDED.publisher,
         latest_observed_version=EXCLUDED.latest_observed_version,devices_seen=EXCLUDED.devices_seen,
         updates_seen=EXCLUDED.updates_seen,last_seen_at=now(),
         metadata=rmm_patch_catalogue_candidates.metadata || EXCLUDED.metadata`,
      [agent.tenant_id],
    )

    await client.query(
      `UPDATE rmm_patch_catalogue_candidates c
          SET state=CASE WHEN EXISTS (
                SELECT 1 FROM rmm_software_catalogue s
                 WHERE s.status='active' AND s.provider=c.provider
                   AND lower(s.provider_package_id)=lower(c.provider_package_id)
                   AND (s.tenant_id=c.tenant_id OR s.tenant_id IS NULL)
              ) THEN 'mapped' ELSE CASE WHEN c.state='mapped' THEN 'observed' ELSE c.state END END,
              last_seen_at=now()
        WHERE c.tenant_id=$1`,
      [agent.tenant_id],
    )
  })

  return { packages: packages.length, patchHostVersion: hostVersion, reconciledDeployments }
}

async function patchDeploymentRows(tenantId) {
  const result = await pool.query(
    `SELECT d.id,d.inventory_id,d.catalogue_id,d.policy_id,d.agent_job_id,d.application_name,
            d.provider,d.provider_package_id,d.installed_version,d.target_version,d.status,d.result,
            d.created_at,d.started_at,d.completed_at,
            i.reference AS device_reference,i.name AS device_name
       FROM rmm_patch_deployments d
       JOIN rmm_device_inventory i ON i.id=d.inventory_id
      WHERE d.tenant_id=$1
      ORDER BY d.created_at DESC
      LIMIT 100`,
    [tenantId],
  )
  return result.rows
}

function installerTechnologyFamily(value = '') {
  const technology = lower(value)
  if (!technology) return ''
  if (technology === 'msi' || technology === 'windows_installer') return 'msi'
  if (['exe', 'inno', 'nullsoft', 'nsis', 'burn', 'installshield', 'squirrel', 'install4j', 'office_odt_sfx', 'generic'].includes(technology)) return 'exe'
  return ''
}

function inventoryInstallerTechnology(item = {}) {
  const uninstall = lower(item?.uninstall_string || item?.quiet_uninstall_string)
  const registryKey = clean(item?.registry_key)
  if (/\bmsiexec(?:\.exe)?\b/i.test(uninstall) || /^\{[0-9a-f-]{36}\}$/i.test(registryKey)) return 'msi'
  if (/\.exe(?:"|\s|$)/i.test(clean(item?.uninstall_string || item?.quiet_uninstall_string))) return 'exe'
  return ''
}

function installedInstallerTechnology(installed = null) {
  if (!installed) return ''
  const direct = inventoryInstallerTechnology(installed)
  if (direct) return direct
  const technologies = [...new Set(array(installed.matchingInstances)
    .map((item) => installerTechnologyFamily(item?.installerTechnology) || inventoryInstallerTechnology(item))
    .filter(Boolean))]
  return technologies.length === 1 ? technologies[0] : ''
}

function continuityInstallerForVendor(vendor = null, installedTechnology = '') {
  const wanted = installerTechnologyFamily(installedTechnology)
  if (!vendor || !wanted) return null
  const github = object(object(vendor.source_payload).github)
  const candidates = array(github.installers)
  return candidates.find((candidate) => {
    const family = installerTechnologyFamily(candidate?.installerTechnology || candidate?.installerType)
    return family === wanted
      && /^https:\/\//i.test(clean(candidate?.url))
      && /^[a-f0-9]{64}$/i.test(clean(candidate?.sha256))
      && ['msi', 'exe'].includes(lower(candidate?.installerType))
  }) || null
}

function installedSoftwareForCatalogue(sourcePayload, catalogue) {
  const matches = array(object(sourcePayload).software?.items)
    .filter((item) => identityPhraseMatches(item?.name, catalogue.name_pattern)
      && identityPhraseMatches(item?.publisher, catalogue.publisher_pattern))
  if (!matches.length) return null

  const ordered = [...matches].sort((a, b) => {
    const comparison = compareVersions(clean(a?.version), clean(b?.version))
    if (comparison == null) return clean(a?.version).localeCompare(clean(b?.version))
    return comparison
  })
  // Planning must represent the best installed instance. If an upgrade leaves an
  // older registration beside the new one, using the oldest instance makes a
  // completed upgrade look perpetually outdated and can trigger repeat installs.
  return {
    ...ordered[ordered.length - 1],
    matchingInstances: ordered.map((item) => ({
      version: clean(item?.version),
      scope: clean(item?.scope),
      registryKey: clean(item?.registry_key),
      uninstallString: clean(item?.uninstall_string),
      quietUninstallString: clean(item?.quiet_uninstall_string),
      installerTechnology: inventoryInstallerTechnology(item),
    })),
  }
}

export async function softwarePatchPlan(tenantId, agentDeviceId, catalogueId, options = {}) {
  const intent = clean(options.intent) === 'install' ? 'install' : 'update'
  const result = await pool.query(
    `SELECT a.id AS agent_device_id,a.inventory_id,a.architecture,a.agent_version,a.websocket_status,
            a.last_telemetry_at,a.patch_capabilities,
            i.reference,i.name AS device_name,i.source_payload,
            c.id AS catalogue_id,c.canonical_name,c.publisher,c.name_pattern,c.publisher_pattern,
            c.provider,c.provider_package_id,c.target_version,c.release_channel,c.installer_type,
            c.execution,c.verification,c.catalogue_source,c.external_key,c.source_metadata,
            c.qualification_state,c.qualification_version,
            c.tenant_id AS catalogue_tenant_id
       FROM rmm_agent_devices a
       JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true
       JOIN rmm_software_catalogue c ON c.id=$3 AND c.status='active'
         AND (c.tenant_id=$1 OR c.tenant_id IS NULL)
      WHERE a.tenant_id=$1 AND a.id::text=$2 AND a.disabled_at IS NULL
      LIMIT 1`,
    [tenantId, agentDeviceId, catalogueId],
  )
  const row = result.rows[0]
  if (!row) return { error: 'Device or software catalogue entry was not found.', status: 404 }
  if (clean(row.qualification_state) === 'blocked') {
    return {
      error: 'This software catalogue entry is blocked and cannot be deployed.',
      status: 409,
      qualificationBlocked: true,
    }
  }

  const liveSocket = agentSocketForDevice(row.agent_device_id)
  const telemetryFresh = row.last_telemetry_at && Date.now() - new Date(row.last_telemetry_at).getTime() <= 90_000
  if (!liveSocket || liveSocket.readyState !== 1 || !telemetryFresh) {
    return { error: 'This device is offline. No patch job was queued.', status: 409, offline: true }
  }

  const capabilities = object(row.patch_capabilities)
  if (capabilities.softwareInstall !== true) {
    return { error: 'This device has not reported PatchHost software-install capability yet.', status: 409, capabilityMissing: true }
  }
  const hostVersion = clean(capabilities.patchHostVersion || capabilities.version)
  const catalogueInstallerTechnology = lower(
    object(row.source_metadata).installerTechnology || row.installer_type,
  )
  if (catalogueInstallerTechnology === 'office_odt_sfx') {
    const officeC2rReady = object(capabilities.vendorDirect).officeClickToRun === true
    const officeHostComparison = compareVersions(hostVersion, '0.2.18')
    if (!officeC2rReady || !hostVersion || officeHostComparison == null || officeHostComparison < 0) {
      return {
        error: 'Microsoft 365 Apps deployment requires PatchHost 0.2.18 or newer with Office Click-to-Run support.',
        status: 409,
        capabilityMissing: true,
        requiredPatchHostVersion: '0.2.18',
        requiredCapability: 'vendorDirect.officeClickToRun',
      }
    }
  }
  if (intent === 'install') {
    const installHostComparison = compareVersions(hostVersion, '0.2.5')
    if (!hostVersion || installHostComparison == null || installHostComparison < 0) {
      return {
        error: 'Installing software from the catalogue requires PatchHost 0.2.5 or newer on the endpoint.',
        status: 409,
        capabilityMissing: true,
        requiredPatchHostVersion: '0.2.5',
      }
    }
  }
  const verificationMethod = clean(object(row.verification).method || object(row.verification).provider || 'winget')
  if (verificationMethod !== 'winget') {
    const hostComparison = compareVersions(hostVersion, '0.2.4')
    if (!hostVersion || hostComparison == null || hostComparison < 0) {
      return {
        error: 'This verification method requires PatchHost 0.2.4 or newer on the endpoint.',
        status: 409,
        capabilityMissing: true,
        requiredPatchHostVersion: '0.2.4',
      }
    }
  }

  const sourceItems = softwareItems(row)
  if (targetProductCodeInstalled(sourceItems, row)) {
    return { error: 'The target MSI identity is already installed at or above the approved version.', status: 409, current: true }
  }

  const installed = installedSoftwareForCatalogue(row.source_payload, row)
  if (intent === 'install' && installed) {
    return { error: 'The selected application is already detected on this device. Use Patch for an existing installation.', status: 409, current: true }
  }
  if (intent !== 'install' && !installed) {
    return { error: 'The selected application is not currently detected on this device.', status: 409 }
  }

  const installedVersion = installed ? clean(installed.version) : ''
  const targetVersion = clean(row.target_version)
  if (!targetVersion) return { error: 'The software catalogue does not have an approved target version.', status: 409 }

  if (installed && clean(row.provider_package_id)) {
    const blocked = await pool.query(
      `SELECT patch_status,available_version,evidence
         FROM rmm_software_patch_observations
        WHERE tenant_id=$1 AND inventory_id=$2
          AND lower(provider_package_id)=lower($3)
        ORDER BY observed_at DESC
        LIMIT 1`,
      [tenantId, row.inventory_id, clean(row.provider_package_id)],
    )
    const observation = blocked.rows[0]
    if (observation?.patch_status === 'provider_blocked'
      && normalizeCatalogueVersion(observation.available_version, row, 'provider') === targetVersion) {
      return {
        error: clean(object(observation.evidence).providerBlockedDetail)
          || 'The selected deployment provider cannot currently remediate this detected update.',
        status: 409,
        providerBlocked: true,
      }
    }
  }

  if (installed) {
    const comparison = compareVersions(normalizeCatalogueVersion(installedVersion, row, 'installed'), targetVersion)
    if (comparison != null && comparison >= 0) {
      return { error: 'The application is already at or above the approved target version.', status: 409, current: true }
    }
  }

  if (intent !== 'install') {
    const ignored = await pool.query(
      `SELECT id FROM rmm_device_patch_rejections
        WHERE tenant_id=$1 AND agent_device_id=$2 AND catalogue_id=$3 AND target_version=$4
          AND revoked_at IS NULL LIMIT 1`,
      [tenantId, row.agent_device_id, row.catalogue_id, targetVersion],
    )
    if (ignored.rowCount) return { error: 'This exact update is ignored for this device. Restore it before patching.', status: 409, ignored: true }
  }

  const activeDeployment = await pool.query(
    `SELECT agent_job_id
       FROM rmm_patch_deployments
      WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id=$3
        AND status IN ('eligible','running')
      ORDER BY created_at DESC LIMIT 1`,
    [tenantId, row.inventory_id, row.catalogue_id],
  )
  if (activeDeployment.rowCount) {
    return { error: 'A software deployment for this application is already running on the device.', status: 409, duplicateJobId: activeDeployment.rows[0].agent_job_id }
  }

  const sourceMetadata = object(row.source_metadata)
  const tenantVendorSourceId = clean(sourceMetadata.tenantVendorSourceId)
  const sourceMode = clean(sourceMetadata.deploymentMode)
  const wingetFallbackReady = row.provider === 'winget' || sourceMetadata.wingetFallbackReady === true
  const learnedWingetFallback = wingetFallbackReady ? clean(sourceMetadata.wingetPackageId) : ''
  if (sourceMode === 'intelligence_only' && !learnedWingetFallback) {
    return { error: 'This vendor source is configured for version intelligence only and has no verified fallback transport.', status: 409 }
  }

  let vendor = null
  if (tenantVendorSourceId) {
    const tenantRelease = await pool.query(
      `SELECT 'tenant_' || s.source_type AS source_key,r.version,r.release_date,r.installer_url,r.installer_sha256,
              r.installer_type,1000 AS source_priority,r.trust_state,s.expected_signer,s.deployment_mode
         FROM rmm_tenant_vendor_releases r
         JOIN rmm_tenant_vendor_sources s ON s.id=r.source_id AND s.tenant_id=$1 AND s.status='active'
        WHERE r.source_id=$2 AND r.version=$3
        ORDER BY COALESCE(r.release_date,r.last_seen_at) DESC LIMIT 1`,
      [tenantId, tenantVendorSourceId, targetVersion],
    )
    vendor = tenantRelease.rows[0] || null
  } else {
    const release = await pool.query(
      `SELECT r.source_key,r.version,r.release_date,r.installer_url,r.installer_sha256,r.installer_type,r.source_priority,
              r.source_payload,r.asset_health_state,r.asset_last_checked_at,r.asset_http_status,r.asset_health_error,
              COALESCE(NULLIF(r.trust_state,''),NULLIF(b.metadata->>'trustState',''),'') AS trust_state,
              COALESCE(NULLIF(b.metadata->>'expectedSigner',''),NULLIF(r.source_payload->>'expectedSigner',''),NULLIF(s.metadata->>'expectedSigner',''),'') AS expected_signer,
              COALESCE(NULLIF(b.metadata->>'deploymentMode',''),NULLIF(r.source_payload->>'deploymentMode',''),'winget_preferred') AS deployment_mode,
              COALESCE(NULLIF(b.metadata->>'installerTechnology',''),NULLIF(r.source_payload->>'installerTechnology',''),'') AS installer_technology,
              COALESCE(NULLIF(b.metadata->>'wingetPackageId',''),'') AS winget_package_id
         FROM rmm_software_vendor_releases r
         JOIN rmm_software_vendor_sources s ON s.source_key=r.source_key AND s.enabled=true
         LEFT JOIN rmm_software_vendor_bindings b
           ON b.source_key=r.source_key
          AND b.provider_package_id=r.provider_package_id
          AND b.channel=r.channel
          AND b.platform=r.platform
          AND b.architecture=r.architecture
          AND b.enabled=true
        WHERE r.provider_package_id=$1 AND r.version=$2
        ORDER BY r.source_priority DESC,COALESCE(r.release_date,r.last_seen_at) DESC
        LIMIT 1`,
      [clean(row.provider_package_id), targetVersion],
    )
    vendor = release.rows[0] || null
  }

  const deploymentMode = clean(vendor?.deployment_mode || sourceMetadata.deploymentMode || (row.provider === 'winget' ? 'winget_preferred' : ''))
  let effectiveVendor = vendor
  let vendorDirect = Boolean(vendor
    && deploymentMode === 'vendor_direct'
    && clean(vendor.trust_state) === 'direct_ready'
    && clean(vendor.asset_health_state) !== 'dead'
    && /^https:\/\//i.test(clean(vendor.installer_url))
    && /^[a-f0-9]{64}$/i.test(clean(vendor.installer_sha256))
    && clean(vendor.expected_signer || row.publisher))

  const installedTechnology = intent === 'update' ? installedInstallerTechnology(installed) : ''
  let selectedTechnology = vendorDirect
    ? installerTechnologyFamily(vendor?.installer_technology || vendor?.installer_type)
    : ''
  let continuitySelected = false

  if (vendorDirect && installedTechnology && selectedTechnology && installedTechnology !== selectedTechnology) {
    const continuity = continuityInstallerForVendor(vendor, installedTechnology)
    if (!continuity) {
      return {
        error: 'Installer technology migration required: this endpoint has a '
          + installedTechnology.toUpperCase() + ' installation, but the approved target is '
          + selectedTechnology.toUpperCase()
          + '. Hi5Central will not silently cross installer technologies without a qualified migration path.',
        status: 409,
        providerBlocked: true,
        installerTechnologyMigrationRequired: true,
        installedInstallerTechnology: installedTechnology,
        targetInstallerTechnology: selectedTechnology,
      }
    }
    effectiveVendor = {
      ...vendor,
      installer_url: clean(continuity.url),
      installer_sha256: clean(continuity.sha256),
      installer_type: clean(continuity.installerType),
      installer_technology: clean(continuity.installerTechnology || (lower(continuity.installerType) === 'msi' ? 'msi' : 'generic')),
    }
    selectedTechnology = installedTechnology
    continuitySelected = true
  }

  const globalWingetFallback = wingetFallbackReady
    ? clean(vendor?.winget_package_id || sourceMetadata.wingetPackageId)
    : ''
  const fallbackPackageId = tenantVendorSourceId
    ? clean(row.provider_package_id)
    : (globalWingetFallback || (deploymentMode === 'winget_preferred' && row.provider === 'winget' ? clean(row.provider_package_id) : ''))
  if (!vendorDirect && !fallbackPackageId) {
    return { error: 'No safe deployment provider is available for this catalogue entry.', status: 409 }
  }
  const executionPackageId = vendorDirect ? (fallbackPackageId || clean(row.provider_package_id)) : fallbackPackageId
  const provider = vendorDirect ? 'vendor_direct' : 'winget'
  const continuitySensitiveUpdate = intent === 'update' && Boolean(installedTechnology)

  return {
    device: row,
    installed,
    provider,
    installerContinuity: {
      installedTechnology,
      targetTechnology: selectedTechnology,
      continuitySelected,
    },
    manifest: {
      protocolVersion: 1,
      action: 'software.install',
      intent,
      catalogueId: row.catalogue_id,
      applicationName: row.canonical_name,
      publisher: row.publisher,
      packageId: executionPackageId,
      installedVersion,
      targetVersion,
      provider,
      vendorSource: vendorDirect ? clean(effectiveVendor?.source_key) : '',
      downloadUrl: vendorDirect ? clean(effectiveVendor?.installer_url) : '',
      sha256: vendorDirect ? clean(effectiveVendor?.installer_sha256).toUpperCase() : '',
      installerType: vendorDirect ? clean(effectiveVendor?.installer_type || row.installer_type) : '',
      installerTechnology: vendorDirect ? clean(effectiveVendor?.installer_technology || effectiveVendor?.installer_type) : '',
      installedInstallerTechnology: installedTechnology,
      installerContinuitySelected: continuitySelected,
      allowGenericStrategyFallback: continuitySelected && clean(effectiveVendor?.installer_type).toLowerCase() === 'exe',
      installArguments: clean(object(row.execution).installArguments),
      responseFile: normalizedVendorResponseFile(object(row.execution).responseFile),
      expectedSigner: clean(effectiveVendor?.expected_signer || row.publisher),
      fallbackProvider: vendorDirect && fallbackPackageId && !continuitySensitiveUpdate ? 'winget' : '',
      verification: {
        ...object(row.verification),
        method: clean(object(row.verification).method || object(row.verification).provider || 'winget'),
        packageId: clean(object(row.verification).packageId || executionPackageId),
        targetVersion: verificationVersionForRelease(targetVersion, object(row.verification)),
      },
    },
  }
}

async function createAndDispatchSoftwarePatch(session, plan, context = {}) {
  const label = clean(session.name || session.email || 'Technician').slice(0, 255)
  const cveId = clean(context.cveId)
  const exposureId = clean(context.exposureId)
  const requestSource = clean(context.source) || 'rmm_patching'
  const created = await withTransaction(async (client) => {
    const jobResult = await client.query(
      `INSERT INTO rmm_agent_jobs
        (tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,request_metadata)
       VALUES ($1,$2,'patch.software',$3::jsonb,$4,'technician',$5,$6::jsonb)
       RETURNING id,status,correlation_id,created_at`,
      [
        session.tenant_id,
        plan.device.agent_device_id,
        JSON.stringify(plan.manifest),
        session.user_id,
        label,
        JSON.stringify({
          source: requestSource,
          device_name: plan.device.device_name,
          device_reference: plan.device.reference,
          catalogue_id: plan.device.catalogue_id,
          provider: plan.provider,
          intent: plan.manifest.intent || 'update',
          ...(cveId ? { cve_id: cveId } : {}),
          ...(exposureId ? { vulnerability_exposure_id: exposureId } : {}),
        }),
      ],
    )
    const job = jobResult.rows[0]
    const deploymentResult = await client.query(
      `INSERT INTO rmm_patch_deployments
        (tenant_id,inventory_id,catalogue_id,agent_job_id,application_name,provider,provider_package_id,
         installed_version,target_version,status,requested_by_user_id,result)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'eligible',$10,$11::jsonb)
       RETURNING *`,
      [
        session.tenant_id,
        plan.device.inventory_id,
        plan.device.catalogue_id,
        job.id,
        plan.manifest.applicationName,
        plan.provider,
        plan.manifest.packageId,
        plan.manifest.installedVersion,
        plan.manifest.targetVersion,
        session.user_id,
        JSON.stringify({ requestedProvider: plan.provider, vendorSource: plan.manifest.vendorSource || '' }),
      ],
    )
    return { job, deployment: deploymentResult.rows[0] }
  })

  const claimed = await pool.query(
    `UPDATE rmm_agent_jobs
        SET status='claimed',claimed_at=now(),updated_at=now()
      WHERE id=$1 AND tenant_id=$2 AND status='queued'
      RETURNING status,claimed_at,updated_at`,
    [created.job.id, session.tenant_id],
  )
  if (!claimed.rowCount) throw new Error('Patch job could not be claimed for immediate dispatch.')

  await withTransaction(async (client) => {
    await client.query(
      `UPDATE rmm_patch_deployments
          SET status='running',started_at=now(),updated_at=now()
        WHERE id=$1 AND tenant_id=$2`,
      [created.deployment.id, session.tenant_id],
    )
    await client.query(
      `UPDATE rmm_vulnerability_exposures
          SET remediation_state='in_progress',last_seen_at=now()
        WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id=$3
          AND status='open' AND remediation_state='available'`,
      [session.tenant_id, plan.device.inventory_id, plan.device.catalogue_id],
    )
  })

  const pushed = sendAgentMessage(plan.device.agent_device_id, {
    type: 'job_execute',
    job: {
      id: created.job.id,
      job_type: 'patch.software',
      payload: plan.manifest,
      created_at: created.job.created_at,
    },
  })

  if (!pushed) {
    await withTransaction(async (client) => {
      await client.query(
        `UPDATE rmm_agent_jobs
            SET status='cancelled',claimed_at=NULL,completed_at=now(),
                error_message='Device went offline before the patch could be dispatched. The job was not retained for reconnect.',
                updated_at=now()
          WHERE id=$1 AND tenant_id=$2 AND status='claimed'`,
        [created.job.id, session.tenant_id],
      )
      await client.query(
        `UPDATE rmm_patch_deployments
            SET status='cancelled',completed_at=now(),updated_at=now(),
                result=result || '{"reason":"device_offline_before_dispatch"}'::jsonb
          WHERE id=$1 AND tenant_id=$2`,
        [created.deployment.id, session.tenant_id],
      )
      await client.query(
        `UPDATE rmm_vulnerability_exposures
            SET remediation_state='available',last_seen_at=now()
          WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id=$3
            AND status='open' AND remediation_state='in_progress'`,
        [session.tenant_id, plan.device.inventory_id, plan.device.catalogue_id],
      )
    })
    return { ...created, dispatched: false, offline: true }
  }

  const installIntent = plan.manifest.intent === 'install'
  await recordRmmActivity({
    tenantId: session.tenant_id,
    agentDeviceId: plan.device.agent_device_id,
    inventoryId: plan.device.inventory_id,
    actorUserId: session.user_id,
    actorType: 'technician',
    actorLabel: label,
    eventType: installIntent ? 'software.install.requested' : 'patch.software.requested',
    category: installIntent ? 'software' : 'patching',
    summary: installIntent
      ? label + ' started software install “' + plan.manifest.applicationName + '”'
      : label + ' started software patch “' + plan.manifest.applicationName + '”',
    detail: installIntent
      ? 'Target ' + plan.manifest.targetVersion + ' via ' + plan.provider
      : plan.manifest.installedVersion + ' → ' + plan.manifest.targetVersion + ' via ' + plan.provider
        + (cveId ? ' · ' + cveId : ''),
    outcome: 'requested',
    correlationId: created.job.correlation_id,
    jobId: created.job.id,
    metadata: { deploymentId: created.deployment.id, manifest: { ...plan.manifest, downloadUrl: plan.manifest.downloadUrl ? '[vendor URL]' : '' } },
  }).catch(() => null)

  return { ...created, dispatched: true }
}



function rawWingetSoftwarePlan(device, observation) {
  const capabilities = object(device?.patch_capabilities)
  if (capabilities.softwareInstall !== true) {
    return {
      error: 'This device has not reported PatchHost software-install capability yet.',
      status: 409,
      capabilityMissing: true,
    }
  }
  const packageId = clean(observation?.provider_package_id)
  const targetVersion = clean(observation?.available_version)
  const installedVersion = clean(observation?.installed_version)
  if (!packageId) return { error: 'WinGet package ID is missing for this update.', status: 409 }
  if (!targetVersion) return { error: 'WinGet did not report an available target version.', status: 409 }

  return {
    device: {
      ...device,
      device_name: clean(device?.device_name || device?.name),
      catalogue_id: clean(observation?.catalogue_id) || null,
    },
    installed: {
      name: clean(observation?.application_name),
      publisher: clean(observation?.publisher),
      version: installedVersion,
    },
    provider: 'winget',
    installerContinuity: {
      installedTechnology: '',
      targetTechnology: '',
      continuitySelected: false,
    },
    manifest: {
      protocolVersion: 1,
      action: 'software.install',
      intent: 'update',
      catalogueId: clean(observation?.catalogue_id),
      applicationName: clean(observation?.application_name || packageId),
      publisher: clean(observation?.publisher),
      packageId,
      installedVersion,
      targetVersion,
      provider: 'winget',
      vendorSource: '',
      downloadUrl: '',
      sha256: '',
      installerType: '',
      installerTechnology: '',
      installedInstallerTechnology: '',
      installerContinuitySelected: false,
      allowGenericStrategyFallback: false,
      installArguments: '',
      responseFile: {},
      expectedSigner: '',
      fallbackProvider: '',
      verification: {
        method: 'winget',
        packageId,
        targetVersion,
      },
    },
  }
}

export async function bulkSoftwarePatchPlan(tenantId, agentDeviceId, mode = 'selected_catalogue', requestedCatalogueIds = []) {
  const resolvedMode = ['selected_catalogue', 'all_catalogue', 'all_winget'].includes(clean(mode))
    ? clean(mode)
    : 'selected_catalogue'

  const [devices, catalogue, discovery, rejectionRows] = await Promise.all([
    patchDeviceRows(tenantId),
    catalogueRows(tenantId),
    patchDiscoveryRows(tenantId),
    pool.query(
      `SELECT catalogue_id,target_version,reason,rejected_by_label,created_at
         FROM rmm_device_patch_rejections
        WHERE tenant_id=$1 AND agent_device_id=$2 AND revoked_at IS NULL`,
      [tenantId, agentDeviceId],
    ),
  ])

  const device = devices.find((item) => item.agent_device_id === agentDeviceId)
  if (!device) return { error: 'Managed device was not found.', status: 404, mode: resolvedMode }
  if (!device.online) return { error: 'This device is offline. No patch job was queued.', status: 409, offline: true, mode: resolvedMode }

  const software = buildSoftware([device], catalogue, discovery.observations)
  const updateRows = software.deviceSoftware.filter((item) =>
    item.agentDeviceId === agentDeviceId
    && item.patchStatus === 'update_available'
    && item.catalogue?.id,
  )
  const rowByCatalogueId = new Map(updateRows.map((item) => [item.catalogue.id, item]))
  const ignoredKey = new Set(
    rejectionRows.rows.map((item) => item.catalogue_id + '|' + clean(item.target_version)),
  )


  if (resolvedMode === 'all_winget') {
    const wingetUpdates = discovery.observations.filter((item) =>
      item.inventory_id === device.inventory_id
      && clean(item.provider) === 'winget'
      && item.patch_status === 'update_available'
      && clean(item.provider_package_id)
      && clean(item.available_version),
    )
    const ignored = []
    const candidates = wingetUpdates.filter((item) => {
      const catalogueId = clean(item.catalogue_id)
      if (!catalogueId) return true
      const key = catalogueId + '|' + clean(item.available_version)
      if (!ignoredKey.has(key)) return true
      const rejection = rejectionRows.rows.find((row) =>
        clean(row.catalogue_id) === catalogueId
        && clean(row.target_version) === clean(item.available_version),
      )
      ignored.push({
        catalogueId,
        applicationName: clean(item.application_name),
        targetVersion: clean(item.available_version),
        reason: clean(rejection?.reason),
        rejectedBy: clean(rejection?.rejected_by_label),
        rejectedAt: rejection?.created_at || null,
      })
      return false
    })

    if (candidates.length > 50) {
      return {
        error: 'This WinGet patch set contains more than 50 applications. Refine the selection or run the next batch after this one completes.',
        status: 409,
        mode: resolvedMode,
        candidateCount: candidates.length + ignored.length,
        maxItems: 50,
        ignored,
      }
    }

    const plans = []
    const rejected = []
    for (const observation of candidates) {
      const plan = rawWingetSoftwarePlan(device, observation)
      if (plan.error) {
        rejected.push({
          catalogueId: clean(observation.catalogue_id),
          applicationName: clean(observation.application_name),
          packageId: clean(observation.provider_package_id),
          error: plan.error,
          capabilityMissing: Boolean(plan.capabilityMissing),
        })
      } else {
        plans.push(plan)
      }
    }

    return {
      mode: resolvedMode,
      device: {
        agentDeviceId: device.agent_device_id,
        inventoryId: device.inventory_id,
        name: device.name,
        reference: device.reference,
        online: device.online,
        patchCapabilities: object(device.patch_capabilities),
      },
      candidateCount: candidates.length + ignored.length,
      eligibleCount: plans.length,
      ignoredCount: ignored.length,
      rejectedCount: rejected.length,
      ignored,
      rejected,
      items: plans.map((plan) => ({
        catalogueId: clean(plan.device.catalogue_id),
        applicationName: plan.manifest.applicationName,
        installedVersion: plan.manifest.installedVersion,
        targetVersion: plan.manifest.targetVersion,
        provider: plan.provider,
        packageId: plan.manifest.packageId,
        vendorSource: '',
        installerType: '',
        installerTechnology: '',
      })),
      plans,
    }
  }

  let catalogueIds = []
  if (resolvedMode === 'selected_catalogue') {
    catalogueIds = [...new Set(array(requestedCatalogueIds).map(clean).filter(Boolean))]
  } else if (resolvedMode === 'all_catalogue') {
    catalogueIds = [...new Set(
      updateRows
        .filter((item) => item.catalogue?.catalogueSource !== 'patchhost' && item.catalogue?.installable === true)
        .map((item) => item.catalogue.id),
    )]
  } else {
    const wingetIds = new Set(
      discovery.observations
        .filter((item) =>
          item.inventory_id === device.inventory_id
          && item.provider === 'winget'
          && item.patch_status === 'update_available'
          && item.catalogue_id,
        )
        .map((item) => item.catalogue_id),
    )
    catalogueIds = [...new Set([
      ...wingetIds,
      ...updateRows
        .filter((item) => item.catalogue?.provider === 'winget')
        .map((item) => item.catalogue.id),
    ])]
  }

  const ignored = []
  catalogueIds = catalogueIds.filter((catalogueId) => {
    const row = rowByCatalogueId.get(catalogueId)
    if (!row) return true
    const target = clean(row.targetVersion || row.catalogue?.targetVersion)
    if (!ignoredKey.has(catalogueId + '|' + target)) return true
    const rejection = rejectionRows.rows.find((item) =>
      item.catalogue_id === catalogueId && clean(item.target_version) === target,
    )
    ignored.push({
      catalogueId,
      applicationName: row.name,
      targetVersion: target,
      reason: clean(rejection?.reason),
      rejectedBy: clean(rejection?.rejected_by_label),
      rejectedAt: rejection?.created_at || null,
    })
    return false
  })

  if (catalogueIds.length > 50) {
    return {
      error: 'This patch set contains more than 50 applications. Refine the selection or run the next batch after this one completes.',
      status: 409,
      mode: resolvedMode,
      candidateCount: catalogueIds.length,
      maxItems: 50,
      ignored,
    }
  }

  const plans = []
  const rejected = []
  for (const catalogueId of catalogueIds) {
    const plan = await softwarePatchPlan(tenantId, agentDeviceId, catalogueId)
    if (plan.error) {
      rejected.push({
        catalogueId,
        applicationName: rowByCatalogueId.get(catalogueId)?.name || '',
        error: plan.error,
        offline: Boolean(plan.offline),
        capabilityMissing: Boolean(plan.capabilityMissing),
        current: Boolean(plan.current),
        providerBlocked: Boolean(plan.providerBlocked),
        installerTechnologyMigrationRequired: Boolean(plan.installerTechnologyMigrationRequired),
        installedInstallerTechnology: clean(plan.installedInstallerTechnology),
        targetInstallerTechnology: clean(plan.targetInstallerTechnology),
        ignored: Boolean(plan.ignored),
      })
    } else {
      plans.push(plan)
    }
  }

  return {
    mode: resolvedMode,
    device: {
      agentDeviceId: device.agent_device_id,
      inventoryId: device.inventory_id,
      name: device.name,
      reference: device.reference,
      online: device.online,
      patchCapabilities: object(device.patch_capabilities),
    },
    candidateCount: catalogueIds.length + ignored.length,
    eligibleCount: plans.length,
    ignoredCount: ignored.length,
    rejectedCount: rejected.length,
    ignored,
    rejected,
    items: plans.map((plan) => ({
      catalogueId: plan.device.catalogue_id,
      applicationName: plan.manifest.applicationName,
      installedVersion: plan.manifest.installedVersion,
      targetVersion: plan.manifest.targetVersion,
      provider: plan.provider,
      packageId: plan.manifest.packageId,
      vendorSource: plan.manifest.vendorSource || '',
      installerType: plan.manifest.installerType || '',
      installerTechnology: plan.manifest.installerTechnology || '',
    })),
    plans,
  }
}

async function createAndDispatchBulkSoftwarePatch(session, plans, mode = 'selected_catalogue', options = {}) {
  const label = clean(session.name || session.email || 'Technician').slice(0, 255)
  const initiatedBy = clean(options.initiatedBy || 'technician')
  const actorType = initiatedBy === 'system' ? 'system' : 'technician'
  const source = clean(options.source || 'rmm_device_bulk_patching')
  const first = plans[0]
  const linkedCatalogueIds = plans.map((plan) => clean(plan.device.catalogue_id)).filter(Boolean)
  const created = await withTransaction(async (client) => {
    const jobResult = await client.query(
      `INSERT INTO rmm_agent_jobs
        (tenant_id,agent_device_id,job_type,payload,queued_by_user_id,initiated_by,initiated_by_label,request_metadata)
       VALUES ($1,$2,'patch.software.bulk',$3::jsonb,$4,$5,$6,$7::jsonb)
       RETURNING id,status,correlation_id,created_at`,
      [session.tenant_id, first.device.agent_device_id, JSON.stringify({ protocolVersion: 1, mode, items: plans.map((plan) => plan.manifest) }), session.user_id, initiatedBy, label,
        JSON.stringify({ source, mode, item_count: plans.length, policy_id: clean(options.policyId), policy_name: clean(options.policyName), device_name: first.device.device_name, device_reference: first.device.reference })],
    )
    const job = jobResult.rows[0]
    const deployments = []
    for (const plan of plans) {
      const deployment = await client.query(
        `INSERT INTO rmm_patch_deployments
          (tenant_id,inventory_id,catalogue_id,agent_job_id,application_name,provider,provider_package_id,
           installed_version,target_version,status,requested_by_user_id,result)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'eligible',$10,$11::jsonb)
         RETURNING *`,
        [session.tenant_id, plan.device.inventory_id, plan.device.catalogue_id, job.id, plan.manifest.applicationName,
          plan.provider, plan.manifest.packageId, plan.manifest.installedVersion, plan.manifest.targetVersion, session.user_id,
          JSON.stringify({ requestedProvider: plan.provider, vendorSource: plan.manifest.vendorSource || '', bulkMode: mode })],
      )
      deployments.push(deployment.rows[0])
    }
    return { job, deployments }
  })

  const claimed = await pool.query(
    `UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now()
      WHERE id=$1 AND tenant_id=$2 AND status='queued' RETURNING status,claimed_at,updated_at`,
    [created.job.id, session.tenant_id],
  )
  if (!claimed.rowCount) throw new Error('Bulk patch job could not be claimed for immediate dispatch.')

  await withTransaction(async (client) => {
    await client.query(`UPDATE rmm_patch_deployments SET status='running',started_at=now(),updated_at=now() WHERE agent_job_id=$1 AND tenant_id=$2`, [created.job.id, session.tenant_id])
    if (linkedCatalogueIds.length) {
      await client.query(
        `UPDATE rmm_vulnerability_exposures SET remediation_state='in_progress',last_seen_at=now()
          WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id = ANY($3::uuid[])
            AND status='open' AND remediation_state='available'`,
        [session.tenant_id, first.device.inventory_id, linkedCatalogueIds],
      )
    }
  })

  const pushed = sendAgentMessage(first.device.agent_device_id, {
    type: 'job_execute',
    job: { id: created.job.id, job_type: 'patch.software.bulk', payload: { protocolVersion: 1, mode, items: plans.map((plan) => plan.manifest) }, created_at: created.job.created_at },
  })
  if (!pushed) {
    await withTransaction(async (client) => {
      await client.query(`UPDATE rmm_agent_jobs SET status='cancelled',claimed_at=NULL,completed_at=now(),error_message='Device went offline before the bulk patch could be dispatched. The job was not retained for reconnect.',updated_at=now() WHERE id=$1 AND tenant_id=$2 AND status='claimed'`, [created.job.id, session.tenant_id])
      await client.query(`UPDATE rmm_patch_deployments SET status='cancelled',completed_at=now(),updated_at=now(),result=result || '{"reason":"device_offline_before_dispatch"}'::jsonb WHERE agent_job_id=$1 AND tenant_id=$2`, [created.job.id, session.tenant_id])
      if (linkedCatalogueIds.length) {
        await client.query(`UPDATE rmm_vulnerability_exposures SET remediation_state='available',last_seen_at=now() WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id = ANY($3::uuid[]) AND status='open' AND remediation_state='in_progress'`, [session.tenant_id, first.device.inventory_id, linkedCatalogueIds])
      }
    })
    return { ...created, dispatched: false, offline: true }
  }

  await recordRmmActivity({
    tenantId: session.tenant_id, agentDeviceId: first.device.agent_device_id, inventoryId: first.device.inventory_id,
    actorUserId: session.user_id, actorType, actorLabel: label, eventType: 'patch.software.bulk.requested', category: 'patching',
    summary: label + ' started ' + plans.length + ' software patches', detail: plans.map((plan) => plan.manifest.applicationName + ' ' + plan.manifest.installedVersion + ' → ' + plan.manifest.targetVersion).join(' · '),
    outcome: 'requested', correlationId: created.job.correlation_id, jobId: created.job.id,
    metadata: { source, policyId: clean(options.policyId), policyName: clean(options.policyName), mode, deploymentIds: created.deployments.map((deployment) => deployment.id), catalogueIds: linkedCatalogueIds },
  }).catch(() => null)
  return { ...created, dispatched: true }
}


function validProvider(value) {
  return ['winget', 'managed', 'vendor'].includes(value) ? value : 'winget'
}


function vulnerabilityRiskCategory(row) {
  const score = Number(row.cvss_score || 0)
  if (row.kev === true || clean(row.ssvc_exploitation) === 'active') return 'critical_exploited'
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'advisory'
}

function vulnerabilityPolicyAction(policy, exposure) {
  const rules = object(object(policy?.software_rules).vulnerabilityRules)
  const category = vulnerabilityRiskCategory(exposure)
  const configured = clean(rules[category])
  if (['automatic','manual','skip'].includes(configured)) return { category, action: configured }
  return { category, action: 'manual' }
}

function softwarePolicyTarget(policy, exposure) {
  if (!policy) return { targeted: false, mode: 'none' }
  const rules = object(policy.software_rules)
  const mode = ['selected_catalogue', 'all_catalogue', 'all_winget'].includes(clean(rules.targetMode))
    ? clean(rules.targetMode)
    : 'all_catalogue'
  if (mode === 'selected_catalogue') {
    const selected = new Set(array(rules.catalogueIds).map(clean))
    return { targeted: selected.has(clean(exposure.catalogue_id)), mode }
  }
  if (mode === 'all_winget') {
    const metadata = object(exposure.source_metadata)
    const wingetReady = clean(exposure.catalogue_provider) === 'winget'
      || (
        clean(metadata.wingetPackageId)
        && metadata.wingetFallbackReady === true
      )
    return { targeted: Boolean(wingetReady), mode }
  }
  return { targeted: true, mode }
}

function softwarePolicyMaintenance(policy, at = new Date()) {
  const rules = object(policy?.software_rules)
  const configured = object(rules.maintenanceWindow)
  const fallback = object(policy?.maintenance_window)
  const maintenanceWindow = Object.keys(configured).length ? configured : fallback
  return windowsMaintenanceWindow({ maintenance_window: maintenanceWindow }, at)
}


async function patchPolicyMatchesForDevice(tenantId, inventoryId, policyType) {
  const domainClause = policyType === 'os'
    ? "p.windows_enabled=true AND p.software_enabled=false"
    : "p.software_enabled=true AND p.windows_enabled=false"
  const result = await pool.query(
    `SELECT p.id,p.name,p.description,p.software_enabled,p.windows_enabled,p.approval_mode,
            p.deployment_delay_days,p.maintenance_window,p.reboot_policy,p.max_retries,
            p.software_rules,p.windows_rules,p.status,
            x.id AS assignment_id,x.scope_type AS assignment_scope_type,
            x.scope_id AS assignment_scope_id,x.scope_name AS assignment_scope_name,
            x.priority AS assignment_priority,x.created_at AS assignment_created_at
       FROM rmm_patch_assignments x
       JOIN rmm_patch_policies p ON p.id=x.policy_id AND p.tenant_id=x.tenant_id
         AND p.status='active' AND ${domainClause}
       JOIN rmm_device_inventory i ON i.id=$2 AND i.tenant_id=x.tenant_id
       LEFT JOIN organisation_people op ON op.tenant_id=i.tenant_id AND op.id=i.assigned_person_id
       LEFT JOIN organisation_sites os ON os.tenant_id=i.tenant_id AND os.id=op.site_id
      WHERE x.tenant_id=$1 AND x.enabled=true AND (
        (x.scope_type='Estate' AND x.scope_id='ALL') OR
        (x.scope_type='Device' AND x.scope_id IN (
          i.id::text,
          i.reference,
          COALESCE((SELECT id::text FROM rmm_agent_devices WHERE inventory_id=i.id AND disabled_at IS NULL LIMIT 1),'')
        )) OR
        (x.scope_type='Site' AND x.scope_id IN (
          COALESCE(os.id::text,''),
          COALESCE(os.external_key,''),
          COALESCE(os.name,'')
        )) OR
        (x.scope_type='Group' AND EXISTS (
          SELECT 1
            FROM rmm_device_group_memberships gm
           WHERE gm.tenant_id=i.tenant_id
             AND gm.inventory_id=i.id
             AND gm.group_id::text=x.scope_id
        ))
      )
      ORDER BY x.priority DESC,x.created_at DESC`,
    [tenantId, inventoryId],
  )
  return result.rows
}

function patchPolicyResolutionItem(row, type) {
  if (!row) return null
  const assignment = {
    id: clean(row.assignment_id),
    scopeType: clean(row.assignment_scope_type),
    scopeId: clean(row.assignment_scope_id),
    scopeName: clean(row.assignment_scope_name),
    priority: Number(row.assignment_priority || 0),
    inherited: clean(row.assignment_scope_type) !== 'Device',
  }

  if (type === 'os') {
    const rules = object(row.windows_rules)
    const rollout = object(rules.rollout)
    return {
      id: clean(row.id),
      type,
      name: clean(row.name),
      description: clean(row.description),
      assignment,
      settings: {
        automaticInstall: rules.autoInstall === true,
        maintenanceWindow: object(row.maintenance_window),
        rolloutEnabled: rollout.enabled === true,
        deadlineDays: Number(rollout.deadlineDays ?? 0),
        includeFeatureUpdates: rules.includeFeatureUpdates === true,
        includeDrivers: rules.includeDrivers === true,
        includeDefinitions: rules.includeDefinitions !== false,
        rebootPolicy: clean(row.reboot_policy || 'never'),
      },
    }
  }

  const rules = object(row.software_rules)
  const targetMode = ['selected_catalogue', 'all_catalogue', 'all_winget'].includes(clean(rules.targetMode))
    ? clean(rules.targetMode)
    : 'all_catalogue'
  return {
    id: clean(row.id),
    type,
    name: clean(row.name),
    description: clean(row.description),
    assignment,
    settings: {
      targetMode,
      catalogueIds: targetMode === 'selected_catalogue' ? array(rules.catalogueIds).map(clean).filter(Boolean) : [],
      selectedCount: targetMode === 'selected_catalogue' ? array(rules.catalogueIds).filter(Boolean).length : 0,
      maintenanceWindow: object(rules.maintenanceWindow),
      approvalMode: clean(row.approval_mode || 'manual'),
      deploymentDelayDays: Number(row.deployment_delay_days || 0),
      maxRetries: Number(row.max_retries || 0),
    },
  }
}

export async function devicePatchPolicyResolution(tenantId, deviceKey) {
  const device = await pool.query(
    `SELECT i.id AS inventory_id,i.reference,i.name,a.id AS agent_device_id
       FROM rmm_device_inventory i
       LEFT JOIN rmm_agent_devices a
         ON a.inventory_id=i.id AND a.tenant_id=i.tenant_id AND a.disabled_at IS NULL
      WHERE i.tenant_id=$1
        AND ($2 IN (i.id::text,i.reference,COALESCE(a.id::text,'')))
      ORDER BY a.last_authenticated_at DESC NULLS LAST
      LIMIT 1`,
    [tenantId, clean(deviceKey)],
  )
  if (!device.rowCount) return null
  const inventoryId = device.rows[0].inventory_id
  const [osMatches, softwareMatches] = await Promise.all([
    patchPolicyMatchesForDevice(tenantId, inventoryId, 'os'),
    patchPolicyMatchesForDevice(tenantId, inventoryId, 'software'),
  ])
  return {
    device: {
      inventoryId: clean(device.rows[0].inventory_id),
      agentDeviceId: clean(device.rows[0].agent_device_id),
      reference: clean(device.rows[0].reference),
      name: clean(device.rows[0].name),
    },
    os: {
      effective: patchPolicyResolutionItem(osMatches[0], 'os'),
      matches: osMatches.map((row) => patchPolicyResolutionItem(row, 'os')),
    },
    software: {
      effective: patchPolicyResolutionItem(softwareMatches[0], 'software'),
      matches: softwareMatches.map((row) => patchPolicyResolutionItem(row, 'software')),
    },
  }
}

async function effectiveSoftwarePolicy(tenantId, inventoryId) {
  const result = await pool.query(
    `SELECT p.* FROM rmm_patch_assignments x
       JOIN rmm_patch_policies p ON p.id=x.policy_id AND p.tenant_id=x.tenant_id AND p.status='active' AND p.software_enabled=true
       JOIN rmm_device_inventory i ON i.id=$2 AND i.tenant_id=x.tenant_id
       LEFT JOIN organisation_people op ON op.tenant_id=i.tenant_id AND op.id=i.assigned_person_id
       LEFT JOIN organisation_sites os ON os.tenant_id=i.tenant_id AND os.id=op.site_id
      WHERE x.tenant_id=$1 AND x.enabled=true AND (
        (x.scope_type='Estate' AND x.scope_id='ALL') OR
        (x.scope_type='Device' AND x.scope_id IN (i.id::text,i.reference,COALESCE((SELECT id::text FROM rmm_agent_devices WHERE inventory_id=i.id AND disabled_at IS NULL LIMIT 1),''))) OR
        (x.scope_type='Site' AND x.scope_id IN (COALESCE(os.id::text,''),COALESCE(os.external_key,''),COALESCE(os.name,''))) OR
        (x.scope_type='Group' AND EXISTS (SELECT 1 FROM rmm_device_group_memberships gm WHERE gm.tenant_id=i.tenant_id AND gm.inventory_id=i.id AND gm.group_id::text=x.scope_id))
      ) ORDER BY x.priority DESC,x.created_at DESC LIMIT 1`, [tenantId, inventoryId])
  return result.rows[0] || null
}

async function effectiveVulnerabilityPolicy(tenantId, exposure) {
  return effectiveSoftwarePolicy(tenantId, exposure.inventory_id)
}

export async function evaluateRealtimeVulnerabilityPolicies(tenantId, { dispatch = true } = {}) {
  const exposures = await pool.query(
    `SELECT e.*,v.cvss_score,v.severity,v.kev,v.epss_score,v.epss_percentile,v.ssvc_exploitation,
            a.id AS agent_device_id,a.websocket_status,a.last_telemetry_at,
            c.source_metadata,c.qualification_state,c.provider AS catalogue_provider
       FROM rmm_vulnerability_exposures e JOIN rmm_vulnerabilities v ON v.cve_id=e.cve_id
       LEFT JOIN rmm_agent_devices a ON a.inventory_id=e.inventory_id AND a.tenant_id=e.tenant_id AND a.disabled_at IS NULL
       LEFT JOIN rmm_software_catalogue c ON c.id=e.catalogue_id
      WHERE e.tenant_id=$1 AND e.status='open'`, [tenantId])
  const decisions=[]
  for (const exposure of exposures.rows) {
    const policy=await effectiveVulnerabilityPolicy(tenantId, exposure)
    const decision=vulnerabilityPolicyAction(policy, exposure)
    const target=softwarePolicyTarget(policy, exposure)
    const maintenance=policy ? softwarePolicyMaintenance(policy) : { open: false }
    const effectiveAction = policy && target.targeted ? decision.action : 'skip'
    const installable=catalogueDeployabilityWeight(exposure)>0 && clean(exposure.remediation_state)==='available' && clean(exposure.catalogue_id)
    let reason = policy ? 'Matched patch policy '+clean(policy.name) : 'No assigned patch policy; manual review required'
    if (policy && !target.targeted) reason += ' · application is outside this software patch policy'
    if (effectiveAction==='automatic' && !maintenance.open) reason += ' · waiting for software maintenance window'
    if (effectiveAction==='automatic' && !installable) reason += ' · trusted remediation is not currently deployable'
    const saved=await pool.query(`INSERT INTO rmm_vulnerability_policy_decisions (tenant_id,exposure_id,policy_id,risk_category,policy_action,reason,evaluated_at)
      VALUES ($1,$2,$3,$4,$5,$6,now()) ON CONFLICT (tenant_id,exposure_id) DO UPDATE SET policy_id=EXCLUDED.policy_id,risk_category=EXCLUDED.risk_category,policy_action=EXCLUDED.policy_action,reason=EXCLUDED.reason,evaluated_at=now() RETURNING *`,
      [tenantId,exposure.id,policy?.id||null,decision.category,effectiveAction,reason])
    let jobId=''
    const online=exposure.websocket_status==='Connected' && exposure.last_telemetry_at && Date.now()-new Date(exposure.last_telemetry_at).getTime()<=90000
    if (dispatch && effectiveAction==='automatic' && maintenance.open && installable && online && !saved.rows[0].dispatched_job_id) {
      const active=await pool.query(`SELECT 1 FROM rmm_patch_deployments WHERE tenant_id=$1 AND inventory_id=$2 AND catalogue_id=$3 AND status IN ('eligible','running','remediation_required') LIMIT 1`,[tenantId,exposure.inventory_id,exposure.catalogue_id])
      if (!active.rowCount) {
        const plan=await softwarePatchPlan(tenantId,exposure.agent_device_id,exposure.catalogue_id)
        if (!plan.error) {
          const systemSession={tenant_id:tenantId,user_id:null,name:'SYSTEM · vulnerability policy',email:''}
          const pushed=await createAndDispatchSoftwarePatch(systemSession,plan,{source:'vulnerability_policy_auto',cveId:exposure.cve_id,exposureId:exposure.id})
          jobId=clean(pushed?.job?.id || pushed?.id)
          if (jobId) await pool.query(`UPDATE rmm_vulnerability_policy_decisions SET dispatched_job_id=$3 WHERE tenant_id=$1 AND exposure_id=$2`,[tenantId,exposure.id,jobId])
        }
      }
    }
    decisions.push({
      exposureId:exposure.id,
      cveId:exposure.cve_id,
      applicationName:exposure.application_name,
      riskCategory:decision.category,
      action:effectiveAction,
      policyName:policy?.name||'',
      targetMode:target.mode,
      targeted:target.targeted,
      maintenanceOpen:Boolean(maintenance.open),
      installable,
      online,
      jobId,
    })
  }
  return decisions
}

let vulnerabilityPolicyTimer = null
async function runRealtimeVulnerabilityPolicies() {
  const tenants = await pool.query(`SELECT DISTINCT tenant_id FROM rmm_device_inventory WHERE active=true AND tenant_id IS NOT NULL`)
  for (const row of tenants.rows) {
    await evaluateRealtimeVulnerabilityPolicies(row.tenant_id, { dispatch: true }).catch((error) => console.error('RMM vulnerability policy evaluation failed', row.tenant_id, error.message))
  }
}

function validApproval(value) {
  return ['automatic', 'manual', 'pilot', 'blocked'].includes(value) ? value : 'manual'
}

function validReboot(value) {
  return ['never', 'maintenance_window', 'notify_user'].includes(value) ? value : 'never'
}

function normalizeMaintenanceWindow(value = {}) {
  const source = object(value)
  const validTime = (input, fallback) => /^([01]\d|2[0-3]):[0-5]\d$/.test(clean(input)) ? clean(input) : fallback
  let timezone = clean(source.timezone)
  if (!timezone || timezone === 'tenant') timezone = 'Europe/London'
  try { new Intl.DateTimeFormat('en-GB', { timeZone: timezone }).format(new Date()) }
  catch { timezone = 'Europe/London' }
  const days = [...new Set(array(source.days).map((day) => Math.trunc(Number(day))).filter((day) => day >= 1 && day <= 7))]
  return {
    start: validTime(source.start, '18:00'),
    end: validTime(source.end, '05:00'),
    timezone,
    days: days.length ? days : [1, 2, 3, 4, 5],
  }
}

function normalizeSoftwareRules(value = {}, fallbackMaintenance = {}) {
  const source = object(value)
  const mode = ['selected_catalogue', 'all_catalogue', 'all_winget'].includes(clean(source.targetMode))
    ? clean(source.targetMode)
    : 'all_catalogue'
  const catalogueIds = [...new Set(array(source.catalogueIds)
    .map(clean)
    .filter((id) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)))]
    .slice(0, 500)
  const vulnerabilitySource = object(source.vulnerabilityRules)
  const vulnerabilityAction = (key, fallback) => {
    const action = clean(vulnerabilitySource[key])
    return ['automatic', 'manual', 'skip'].includes(action) ? action : fallback
  }
  return {
    targetMode: mode,
    catalogueIds: mode === 'selected_catalogue' ? catalogueIds : [],
    maintenanceWindow: normalizeMaintenanceWindow(source.maintenanceWindow || fallbackMaintenance),
    vulnerabilityRules: {
      critical_exploited: vulnerabilityAction('critical_exploited', 'automatic'),
      critical: vulnerabilityAction('critical', 'automatic'),
      high: vulnerabilityAction('high', 'manual'),
      medium: vulnerabilityAction('medium', 'manual'),
      low: vulnerabilityAction('low', 'skip'),
      advisory: vulnerabilityAction('advisory', 'skip'),
    },
  }
}

async function validateSoftwareRuleCatalogueIds(tenantId, rules, softwareEnabled = true) {
  if (!softwareEnabled || rules.targetMode !== 'selected_catalogue') return { rules }
  if (!rules.catalogueIds.length) return { error: 'Select at least one Hi5Central catalogue application for this software patch policy.' }
  const result = await pool.query(
    `SELECT id FROM rmm_software_catalogue
      WHERE id=ANY($2::uuid[]) AND status<>'archived' AND (tenant_id=$1 OR tenant_id IS NULL)`,
    [tenantId, rules.catalogueIds],
  )
  const valid = new Set(result.rows.map((row) => clean(row.id)))
  const invalid = rules.catalogueIds.filter((id) => !valid.has(id))
  if (invalid.length) return { error: 'One or more selected software catalogue applications are no longer available.' }
  return { rules }
}

function normalizeWindowsRollout(value = {}) {
  const source = object(value)
  const defaults = [
    { id: 'pilot', name: 'Pilot', percentage: 5, delayDays: 0 },
    { id: 'early', name: 'Early', percentage: 15, delayDays: 1 },
    { id: 'broad', name: 'Broad', percentage: 60, delayDays: 3 },
    { id: 'final', name: 'Final', percentage: 20, delayDays: 5 },
  ]
  const configured = new Map(array(source.waves).map((wave) => [clean(wave?.id).toLowerCase(), object(wave)]))
  let remaining = 100
  let previousDelay = 0
  const waves = defaults.map((fallback, index) => {
    const candidate = configured.get(fallback.id) || {}
    const configuredDelay = Number(candidate.delayDays)
    const delayDays = Math.max(previousDelay, Math.max(0, Math.min(365, Number.isFinite(configuredDelay) ? configuredDelay : fallback.delayDays)))
    previousDelay = delayDays
    const configuredPercentage = Number(candidate.percentage)
    const requestedPercentage = Math.max(0, Math.min(100, Number.isFinite(configuredPercentage) ? configuredPercentage : fallback.percentage))
    const percentage = index === defaults.length - 1 ? remaining : Math.min(remaining, requestedPercentage)
    remaining -= percentage
    return { id: fallback.id, name: fallback.name, percentage, delayDays }
  })
  const configuredDeadline = Number(source.deadlineDays)
  const deadlineDays = Math.max(previousDelay, Math.max(0, Math.min(365, Number.isFinite(configuredDeadline) ? configuredDeadline : 7)))
  return { enabled: source.enabled === true, deadlineDays, waves }
}

function normalizeWindowsRules(value = {}, deploymentDelayDays = 0) {
  const source = object(value)
  const delays = object(source.delayDays)
  const base = Math.max(0, Math.min(365, Number(deploymentDelayDays) || 0))
  const delay = (key, fallback) => {
    const configured = Number(delays[key])
    return Math.max(0, Math.min(365, Number.isFinite(configured) ? configured : fallback))
  }
  return {
    autoInstall: source.autoInstall === true,
    includeDrivers: source.includeDrivers === true,
    includeFeatureUpdates: source.includeFeatureUpdates === true,
    includeDefinitions: source.includeDefinitions !== false,
    rollout: normalizeWindowsRollout(source.rollout),
    delayDays: {
      critical: delay('critical', 0),
      security: delay('security', base),
      quality: delay('quality', base),
      feature: delay('feature', Math.max(base, 14)),
      driver: delay('driver', Math.max(base, 14)),
      definition: delay('definition', 0),
      other: delay('other', base),
    },
  }
}

function softwarePolicyMode(policy) {
  const mode = clean(object(policy?.software_rules).targetMode)
  return ['selected_catalogue', 'all_catalogue', 'all_winget'].includes(mode) ? mode : 'all_catalogue'
}

function softwarePolicyReleaseTime(catalogueEntry, wingetCandidate = null) {
  const metadata = object(catalogueEntry?.source_metadata)
  const evidence = object(catalogueEntry?.qualification_evidence)
  for (const value of [
    wingetCandidate?.first_seen_at,
    metadata.releaseDate,
    evidence.cleanInstallVerifiedAt,
    catalogueEntry?.qualified_at,
    catalogueEntry?.created_at,
  ]) {
    if (!value) continue
    const date = new Date(value)
    if (!Number.isNaN(date.getTime())) return date
  }
  return null
}

function softwarePolicyDelaySatisfied(policy, catalogueEntry, wingetCandidate = null, at = new Date()) {
  const delayDays = Math.max(0, Math.min(365, Number(policy?.deployment_delay_days) || 0))
  if (!delayDays) return true
  const releaseTime = softwarePolicyReleaseTime(catalogueEntry, wingetCandidate)
  if (!releaseTime) return false
  return at.getTime() - releaseTime.getTime() >= delayDays * 24 * 60 * 60 * 1000
}

export async function evaluateSoftwarePatchPolicies(tenantId, { dispatch = true, at = new Date() } = {}) {
  const [devices, catalogue, discovery] = await Promise.all([
    patchDeviceRows(tenantId),
    catalogueRows(tenantId),
    patchDiscoveryRows(tenantId),
  ])
  const software = buildSoftware(devices, catalogue, discovery.observations)
  const catalogueById = new Map(catalogue.map((item) => [clean(item.id), item]))
  const candidateByPackageId = new Map(
    discovery.candidates
      .filter((item) => clean(item.provider_package_id))
      .map((item) => [lower(item.provider_package_id), item]),
  )
  const observationsByInventory = new Map()
  for (const observation of discovery.observations) {
    if (!observationsByInventory.has(observation.inventory_id)) observationsByInventory.set(observation.inventory_id, [])
    observationsByInventory.get(observation.inventory_id).push(observation)
  }

  const decisions = []
  for (const device of devices) {
    const policy = await effectiveSoftwarePolicy(tenantId, device.inventory_id)
    const mode = softwarePolicyMode(policy)
    const maintenance = policy ? softwarePolicyMaintenance(policy, at) : { open: false }
    const approval = clean(policy?.approval_mode)
    const base = {
      agentDeviceId: device.agent_device_id,
      inventoryId: device.inventory_id,
      deviceName: device.name,
      policyId: policy?.id || '',
      policyName: clean(policy?.name),
      mode,
      approval,
      maintenanceOpen: Boolean(maintenance.open),
      eligibleCount: 0,
      dispatched: false,
      jobId: '',
      reason: '',
    }

    if (!policy) {
      decisions.push({ ...base, reason: 'no_software_patch_policy' })
      continue
    }
    if (approval !== 'automatic') {
      decisions.push({ ...base, reason: approval === 'blocked' ? 'software_patching_blocked' : 'software_patch_approval_required' })
      continue
    }
    if (!maintenance.open) {
      decisions.push({ ...base, reason: 'outside_software_maintenance_window' })
      continue
    }
    if (!device.online) {
      decisions.push({ ...base, reason: 'device_offline' })
      continue
    }

    const activeBulk = await pool.query(
      `SELECT id FROM rmm_agent_jobs
        WHERE tenant_id=$1 AND agent_device_id=$2 AND job_type='patch.software.bulk'
          AND status IN ('queued','claimed')
        ORDER BY created_at DESC LIMIT 1`,
      [tenantId, device.agent_device_id],
    )
    if (activeBulk.rowCount) {
      decisions.push({ ...base, reason: 'software_patch_job_already_active', jobId: activeBulk.rows[0].id })
      continue
    }

    const observations = observationsByInventory.get(device.inventory_id) || []
    const selectedIds = new Set(array(object(policy.software_rules).catalogueIds).map(clean))
    const updates = software.deviceSoftware.filter((item) =>
      item.agentDeviceId === device.agent_device_id
      && item.patchStatus === 'update_available'
      && item.catalogue?.id,
    )

    let candidateRows = []
    const plans = []
    const rejected = []

    if (mode === 'all_winget') {
      candidateRows = observations
        .filter((item) =>
          clean(item.provider) === 'winget'
          && item.patch_status === 'update_available'
          && clean(item.provider_package_id)
          && clean(item.available_version),
        )
        .filter((item) => {
          const discovered = candidateByPackageId.get(lower(item.provider_package_id))
          const releaseHint = discovered || { first_seen_at: item.observed_at }
          return softwarePolicyDelaySatisfied(policy, null, releaseHint, at)
        })
        .slice(0, 50)

      for (const observation of candidateRows) {
        const plan = rawWingetSoftwarePlan(device, observation)
        if (plan.error) {
          rejected.push({
            catalogueId: clean(observation.catalogue_id),
            packageId: clean(observation.provider_package_id),
            applicationName: clean(observation.application_name),
            error: plan.error,
          })
        } else {
          plans.push(plan)
        }
      }
    } else {
      candidateRows = updates
        .filter((item) => {
          const catalogueId = clean(item.catalogue.id)
          if (mode === 'selected_catalogue' && !selectedIds.has(catalogueId)) return false
          if (mode === 'all_catalogue' && item.catalogue.installable !== true) return false
          const raw = catalogueById.get(catalogueId)
          return softwarePolicyDelaySatisfied(policy, raw, null, at)
        })
        .slice(0, 50)

      for (const item of candidateRows) {
        const plan = await softwarePatchPlan(tenantId, device.agent_device_id, item.catalogue.id)
        if (plan.error) rejected.push({ catalogueId: item.catalogue.id, error: plan.error })
        else plans.push(plan)
      }
    }

    if (!plans.length) {
      decisions.push({
        ...base,
        eligibleCount: candidateRows.length,
        rejectedCount: rejected.length,
        reason: candidateRows.length ? 'no_deployable_software_updates' : 'no_eligible_software_updates',
      })
      continue
    }

    if (!dispatch) {
      decisions.push({
        ...base,
        eligibleCount: plans.length,
        rejectedCount: rejected.length,
        reason: 'software_patch_schedule_ready',
      })
      continue
    }

    const systemSession = {
      tenant_id: tenantId,
      user_id: null,
      name: 'SYSTEM · software patch schedule',
      email: '',
    }
    const pushed = await createAndDispatchBulkSoftwarePatch(systemSession, plans, mode, {
      initiatedBy: 'system',
      source: 'software_patch_schedule',
      policyId: policy.id,
      policyName: policy.name,
    })
    decisions.push({
      ...base,
      eligibleCount: plans.length,
      rejectedCount: rejected.length,
      dispatched: pushed.dispatched === true,
      jobId: clean(pushed?.job?.id),
      reason: pushed.dispatched === true ? 'scheduled_software_patch_dispatched' : 'software_patch_dispatch_failed',
    })
  }
  return decisions
}

let softwarePatchTimer = null
async function runSoftwarePatchSchedules() {
  const tenants = await pool.query(
    'SELECT DISTINCT tenant_id FROM rmm_agent_devices WHERE disabled_at IS NULL AND tenant_id IS NOT NULL',
  )
  for (const row of tenants.rows) {
    await evaluateSoftwarePatchPolicies(row.tenant_id, { dispatch: true })
      .catch((error) => console.error('RMM software patch schedule evaluation failed', row.tenant_id, error.message))
  }
}

let windowsPatchTimer = null
async function runWindowsPatchSchedules() {
  const tenants = await pool.query(
    'SELECT DISTINCT tenant_id FROM rmm_agent_devices WHERE disabled_at IS NULL AND tenant_id IS NOT NULL',
  )
  for (const row of tenants.rows) {
    await evaluateWindowsUpdatePolicies(row.tenant_id, {
      dispatch: true,
      agentSocketForDevice,
      sendAgentMessage,
    }).catch((error) => console.error('RMM Windows patch schedule evaluation failed', row.tenant_id, error.message))
  }
}

function priorityForScope(scopeType) {
  return ({ Estate: 100, Site: 220, Group: 340, Device: 900 })[scopeType] || 100
}

function agentVersionAtLeast(current = '', required = '') {
  const left = clean(current).match(/\d+/g)?.map(Number) || []
  const right = clean(required).match(/\d+/g)?.map(Number) || []
  const length = Math.max(left.length, right.length)
  for (let index = 0; index < length; index += 1) {
    const delta = Number(left[index] || 0) - Number(right[index] || 0)
    if (delta !== 0) return delta > 0
  }
  return left.length > 0 && right.length > 0
}

async function patchAssignmentScopeDevices(tenantId, scopeType, scopeId) {
  const result = await pool.query(
    `SELECT i.id AS inventory_id,i.reference,i.name,i.operating_system,
            a.id AS agent_device_id,a.agent_version,a.websocket_status,a.last_telemetry_at,
            os.id AS site_id,os.name AS site_name
       FROM rmm_device_inventory i
       LEFT JOIN LATERAL (
         SELECT ad.id,ad.agent_version,ad.websocket_status,ad.last_telemetry_at,ad.last_authenticated_at
           FROM rmm_agent_devices ad
          WHERE ad.tenant_id=i.tenant_id AND ad.inventory_id=i.id AND ad.disabled_at IS NULL
          ORDER BY ad.last_authenticated_at DESC NULLS LAST
          LIMIT 1
       ) a ON true
       LEFT JOIN organisation_people op ON op.tenant_id=i.tenant_id AND op.id=i.assigned_person_id
       LEFT JOIN organisation_sites os ON os.tenant_id=i.tenant_id AND os.id=op.site_id
      WHERE i.tenant_id=$1 AND (
        ($2='Estate' AND $3='ALL') OR
        ($2='Device' AND $3 IN (i.id::text,i.reference,COALESCE(a.id::text,''))) OR
        ($2='Site' AND $3 IN (COALESCE(os.id::text,''),COALESCE(os.external_key,''),COALESCE(os.name,''))) OR
        ($2='Group' AND EXISTS (
          SELECT 1 FROM rmm_device_group_memberships gm
           WHERE gm.tenant_id=i.tenant_id AND gm.inventory_id=i.id AND gm.group_id::text=$3
        ))
      )
      ORDER BY lower(i.name),i.id`,
    [tenantId, scopeType, scopeId],
  )
  return result.rows
}

async function effectivePatchPoliciesForDevices(tenantId, inventoryIds, policyType) {
  if (!inventoryIds.length) return []
  const result = await pool.query(
    `SELECT DISTINCT ON (i.id)
            i.id AS inventory_id,p.id AS policy_id,p.name AS policy_name,
            x.id AS assignment_id,x.scope_type,x.scope_id,x.scope_name,x.priority,x.created_at
       FROM rmm_device_inventory i
       JOIN rmm_patch_assignments x ON x.tenant_id=i.tenant_id AND x.enabled=true
       JOIN rmm_patch_policies p ON p.id=x.policy_id AND p.tenant_id=x.tenant_id AND p.status='active'
         AND (
           ($3='os' AND p.windows_enabled=true AND p.software_enabled=false) OR
           ($3='software' AND p.software_enabled=true AND p.windows_enabled=false)
         )
       LEFT JOIN organisation_people op ON op.tenant_id=i.tenant_id AND op.id=i.assigned_person_id
       LEFT JOIN organisation_sites os ON os.tenant_id=i.tenant_id AND os.id=op.site_id
      WHERE i.tenant_id=$1 AND i.id=ANY($2::uuid[]) AND (
        (x.scope_type='Estate' AND x.scope_id='ALL') OR
        (x.scope_type='Device' AND x.scope_id IN (
          i.id::text,
          i.reference,
          COALESCE((SELECT id::text FROM rmm_agent_devices WHERE inventory_id=i.id AND tenant_id=i.tenant_id AND disabled_at IS NULL ORDER BY last_authenticated_at DESC NULLS LAST LIMIT 1),'')
        )) OR
        (x.scope_type='Site' AND x.scope_id IN (COALESCE(os.id::text,''),COALESCE(os.external_key,''),COALESCE(os.name,''))) OR
        (x.scope_type='Group' AND EXISTS (
          SELECT 1 FROM rmm_device_group_memberships gm
           WHERE gm.tenant_id=i.tenant_id AND gm.inventory_id=i.id AND gm.group_id::text=x.scope_id
        ))
      )
      ORDER BY i.id,x.priority DESC,x.created_at DESC`,
    [tenantId, inventoryIds, policyType],
  )
  return result.rows
}

export async function patchAssignmentImpactPreview(tenantId, options = {}) {
  const policyId = clean(options.policyId)
  const scopeType = clean(options.scopeType)
  const scopeId = clean(options.scopeId || (scopeType === 'Estate' ? 'ALL' : ''))
  if (!policyId) return { error: 'Patch policy is required.', status: 400 }
  if (!['Estate','Site','Group','Device'].includes(scopeType)) return { error: 'Invalid patch scope.', status: 400 }
  if (!scopeId) return { error: 'Patch scope target is required.', status: 400 }

  const policyResult = await pool.query(
    `SELECT id,name,software_enabled,windows_enabled,status
       FROM rmm_patch_policies
      WHERE tenant_id=$1 AND id=$2 AND status='active'
      LIMIT 1`,
    [tenantId, policyId],
  )
  if (!policyResult.rowCount) return { error: 'Patch policy not found.', status: 404 }
  const policy = policyResult.rows[0]
  const policyType = policy.windows_enabled === true && policy.software_enabled !== true ? 'os'
    : policy.software_enabled === true && policy.windows_enabled !== true ? 'software'
      : ''
  if (!policyType) return { error: 'Patch policy type is invalid.', status: 409 }

  const devices = await patchAssignmentScopeDevices(tenantId, scopeType, scopeId)
  const inventoryIds = devices.map((device) => device.inventory_id)
  const [currentRows, exactAssignment] = await Promise.all([
    effectivePatchPoliciesForDevices(tenantId, inventoryIds, policyType),
    pool.query(
      `SELECT id,priority,created_at
         FROM rmm_patch_assignments
        WHERE tenant_id=$1 AND policy_id=$2 AND scope_type=$3 AND scope_id=$4
        LIMIT 1`,
      [tenantId, policyId, scopeType, scopeId],
    ),
  ])
  const currentByInventory = new Map(currentRows.map((row) => [clean(row.inventory_id), row]))
  const candidatePriority = priorityForScope(scopeType)
  const exact = exactAssignment.rows[0] || null
  const candidateCreatedAt = exact?.created_at ? new Date(exact.created_at).getTime() : Date.now()

  const rows = devices.map((device) => {
    const current = currentByInventory.get(clean(device.inventory_id)) || null
    const currentPriority = Number(current?.priority || 0)
    const currentCreatedAt = current?.created_at ? new Date(current.created_at).getTime() : 0
    const samePolicy = clean(current?.policy_id) === policyId
    const candidateWins = samePolicy
      || !current
      || candidatePriority > currentPriority
      || (candidatePriority === currentPriority && candidateCreatedAt >= currentCreatedAt)

    const hasAgent = Boolean(device.agent_device_id)
    const isWindows = clean(device.operating_system).toLowerCase().includes('windows')
    let applicable = hasAgent
    let notApplicableReason = ''
    if (!hasAgent) {
      applicable = false
      notApplicableReason = 'No active Hi5Central Agent'
    } else if (policyType === 'os' && !isWindows) {
      applicable = false
      notApplicableReason = 'OS patching applies to Windows endpoints'
    } else if (policyType === 'os' && !agentVersionAtLeast(device.agent_version, '0.1.214')) {
      applicable = false
      notApplicableReason = 'Agent 0.1.214 or later is required'
    }

    const online = hasAgent && clean(device.websocket_status).toLowerCase() === 'connected'
    const result = !applicable ? 'not_applicable'
      : samePolicy ? 'already_effective'
        : candidateWins ? 'will_apply'
          : 'overridden'

    return {
      inventoryId: clean(device.inventory_id),
      agentDeviceId: clean(device.agent_device_id),
      reference: clean(device.reference),
      name: clean(device.name),
      operatingSystem: clean(device.operating_system),
      agentVersion: clean(device.agent_version),
      online,
      applicable,
      notApplicableReason,
      result,
      candidatePriority,
      currentPolicy: current ? {
        id: clean(current.policy_id),
        name: clean(current.policy_name),
        scopeType: clean(current.scope_type),
        scopeName: clean(current.scope_name || current.scope_id),
        priority: currentPriority,
      } : null,
      effectiveAfter: candidateWins ? {
        id: policyId,
        name: clean(policy.name),
        scopeType,
        scopeName: clean(options.scopeName || scopeId),
        priority: candidatePriority,
      } : current ? {
        id: clean(current.policy_id),
        name: clean(current.policy_name),
        scopeType: clean(current.scope_type),
        scopeName: clean(current.scope_name || current.scope_id),
        priority: currentPriority,
      } : null,
      replacesPolicy: candidateWins && current && !samePolicy ? {
        id: clean(current.policy_id),
        name: clean(current.policy_name),
      } : null,
    }
  })

  const count = (name) => rows.filter((row) => row.result === name).length
  return {
    policy: { id: policyId, name: clean(policy.name), type: policyType },
    scope: { type: scopeType, id: scopeId, name: clean(options.scopeName || scopeId), priority: candidatePriority },
    summary: {
      targeted: rows.length,
      willApply: count('will_apply'),
      alreadyEffective: count('already_effective'),
      overridden: count('overridden'),
      notApplicable: count('not_applicable'),
      offline: rows.filter((row) => row.applicable && !row.online).length,
      online: rows.filter((row) => row.applicable && row.online).length,
      replacing: rows.filter((row) => row.replacesPolicy).length,
    },
    devices: rows,
  }
}


async function catalogueListRows(tenantId) {
  const result = await pool.query(
    `SELECT id,tenant_id,canonical_name,publisher,name_pattern,publisher_pattern,platform,provider,
            provider_package_id,target_version,release_channel,installer_type,status,catalogue_source,
            source_metadata,qualification_state,qualification_version
       FROM rmm_software_catalogue
      WHERE status<>'archived' AND (tenant_id=$1 OR tenant_id IS NULL)
      ORDER BY lower(canonical_name),lower(COALESCE(publisher,'')),id`,
    [tenantId],
  )
  return result.rows
}

function catalogueSearchRow(entry) {
  const item = publicCatalogue(entry)
  return {
    key: 'hi5central:' + item.id,
    source: 'hi5central',
    sourceLabel: 'Hi5Central',
    catalogueId: item.id,
    name: clean(item.canonicalName),
    publisher: clean(item.publisher),
    packageId: clean(item.executionPackageId || item.packageId),
    version: clean(item.targetVersion),
    provider: clean(item.provider || 'managed'),
    moniker: '',
    installable: item.installable === true,
    qualificationState: clean(item.qualificationState || 'intelligence_only'),
    deploymentMode: clean(item.deploymentMode),
    trustState: clean(item.trustState),
    builtIn: item.builtIn === true,
  }
}

function wingetSearchRow(item) {
  return {
    key: 'winget:' + clean(item.id),
    source: 'winget',
    sourceLabel: 'WinGet',
    catalogueId: '',
    name: clean(item.name || item.id),
    publisher: clean(array(item.publishers)[0]),
    publishers: array(item.publishers).map(clean).filter(Boolean),
    packageId: clean(item.id),
    version: clean(item.version),
    provider: 'winget',
    moniker: clean(item.moniker),
    installable: false,
    qualificationState: 'repository',
    deploymentMode: 'winget_repository',
    trustState: 'repository',
    builtIn: false,
  }
}

function catalogueSearchMatches(item, query) {
  if (!query) return true
  return [
    item.name,
    item.publisher,
    item.packageId,
    item.version,
    item.provider,
    item.qualificationState,
    item.deploymentMode,
  ].filter(Boolean).join(' ').toLowerCase().includes(query)
}

async function wingetRepositorySlice({ query = '', offset = 0, limit = 50 } = {}) {
  const safeOffset = Math.max(0, Number(offset) || 0)
  const safeLimit = Math.max(0, Math.min(100, Number(limit) || 0))
  const chunkSize = 100
  const firstPage = Math.floor(safeOffset / chunkSize) + 1
  const firstIndex = safeOffset % chunkSize
  const first = await wingetRepositorySearch({ query, page: firstPage, pageSize: chunkSize })
  if (!safeLimit) return { total: first.total, packages: [] }
  const packages = array(first.packages).slice(firstIndex, firstIndex + safeLimit)
  if (packages.length < safeLimit && firstPage < Number(first.pages || 1)) {
    const next = await wingetRepositorySearch({ query, page: firstPage + 1, pageSize: chunkSize })
    packages.push(...array(next.packages).slice(0, safeLimit - packages.length))
  }
  return { total: Number(first.total || 0), packages }
}

export async function unifiedCatalogueSearch(tenantId, options = {}) {
  const queryText = clean(options.query).slice(0, 160)
  const query = queryText.toLowerCase()
  const source = ['all','hi5central','winget'].includes(lower(options.source)) ? lower(options.source) : 'all'
  const provider = ['all','managed','winget','vendor'].includes(lower(options.provider)) ? lower(options.provider) : 'all'
  const pageSize = Math.max(10, Math.min(100, Number(options.pageSize) || 50))
  const requestedPage = Math.max(1, Number(options.page) || 1)

  const hi5RowsRaw = (await catalogueListRows(tenantId))
    .map(catalogueSearchRow)
    .filter((item) => provider === 'all' || item.provider === provider)
    .filter((item) => catalogueSearchMatches(item, query))

  const hi5ByIdentity = new Map()
  for (const item of hi5RowsRaw) {
    const identity = [lower(item.packageId), lower(item.name)].filter(Boolean).join('|') || item.key
    const current = hi5ByIdentity.get(identity)
    if (!current || (current.builtIn && !item.builtIn)) hi5ByIdentity.set(identity, item)
  }
  const hi5Rows = [...hi5ByIdentity.values()].sort((a, b) =>
    clean(a.name).localeCompare(clean(b.name), undefined, { sensitivity: 'base', numeric: true }),
  )

  const hi5Total = hi5Rows.length
  const wingetAllowedByProvider = provider === 'all' || provider === 'winget'

  if (source === 'hi5central') {
    let wingetTotal = 0
    if (wingetAllowedByProvider) {
      const count = await wingetRepositorySearch({ query: queryText, page: 1, pageSize: 10 })
      wingetTotal = Number(count.total || 0)
    }
    const total = hi5Total
    const pages = Math.max(1, Math.ceil(total / pageSize))
    const page = Math.min(requestedPage, pages)
    const offset = (page - 1) * pageSize
    return {
      query: queryText,
      source,
      provider,
      page,
      pageSize,
      pages,
      total,
      sourceCounts: { hi5central: hi5Total, winget: wingetTotal },
      sort: 'name',
      items: hi5Rows.slice(offset, offset + pageSize),
    }
  }

  if (source === 'winget') {
    if (!wingetAllowedByProvider) {
      return {
        query: queryText,
        source,
        provider,
        page: 1,
        pageSize,
        pages: 1,
        total: 0,
        sourceCounts: { hi5central: hi5Total, winget: 0 },
        sort: 'name',
        items: [],
      }
    }
    const result = await wingetRepositorySearch({
      query: queryText,
      page: requestedPage,
      pageSize,
    })
    const items = array(result.packages).map(wingetSearchRow)
    return {
      query: queryText,
      source,
      provider,
      page: Number(result.page || 1),
      pageSize: Number(result.pageSize || pageSize),
      pages: Number(result.pages || 1),
      total: Number(result.total || 0),
      sourceCounts: { hi5central: hi5Total, winget: Number(result.total || 0) },
      sort: 'name',
      items,
    }
  }

  let wingetRows = []
  if (wingetAllowedByProvider) {
    const result = await wingetRepositoryAllSearch({ query: queryText })
    wingetRows = array(result.packages).map(wingetSearchRow)
  }

  const combined = [...hi5Rows, ...wingetRows].sort((a, b) => {
    const name = clean(a.name).localeCompare(clean(b.name), undefined, { sensitivity: 'base', numeric: true })
    if (name) return name
    const publisher = clean(a.publisher).localeCompare(clean(b.publisher), undefined, { sensitivity: 'base', numeric: true })
    if (publisher) return publisher
    if (a.source !== b.source) return a.source === 'hi5central' ? -1 : 1
    return clean(a.packageId).localeCompare(clean(b.packageId), undefined, { sensitivity: 'base', numeric: true })
  })

  const wingetTotal = wingetRows.length
  const total = combined.length
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const page = Math.min(requestedPage, pages)
  const offset = (page - 1) * pageSize

  return {
    query: queryText,
    source,
    provider,
    page,
    pageSize,
    pages,
    total,
    sourceCounts: { hi5central: hi5Total, winget: wingetTotal },
    sort: 'name',
    items: combined.slice(offset, offset + pageSize),
  }
}

export function registerRmmPatchingRoutes(app) {
  if (!vulnerabilityPolicyTimer) {
    vulnerabilityPolicyTimer = setInterval(() => void runRealtimeVulnerabilityPolicies(), 60_000)
    vulnerabilityPolicyTimer.unref?.()
    setTimeout(() => void runRealtimeVulnerabilityPolicies(), 15_000).unref?.()
  }
  if (!softwarePatchTimer) {
    softwarePatchTimer = setInterval(() => void runSoftwarePatchSchedules(), 60_000)
    softwarePatchTimer.unref?.()
    setTimeout(() => void runSoftwarePatchSchedules(), 25_000).unref?.()
  }
  if (!windowsPatchTimer) {
    windowsPatchTimer = setInterval(() => void runWindowsPatchSchedules(), 60_000)
    windowsPatchTimer.unref?.()
    setTimeout(() => void runWindowsPatchSchedules(), 20_000).unref?.()
  }
  app.post('/api/v1/agent/devices/patch-discovery', async (c) => {
    const agent = await authenticateAgent(c.req.header('x-hi5-device-id'), c.req.header('x-hi5-agent-secret'))
    if (!agent) return c.json({ success: false, error: 'Agent authentication failed.' }, 401)
    const body = await c.req.json().catch(() => ({}))
    const result = await ingestPatchDiscovery(agent, body)
    void recalculateTenantVulnerabilityExposures(agent.tenant_id, [agent.inventory_id])
      .catch((error) => console.error('RMM post-discovery vulnerability calculation failed', error))
    const automaticVerificationProbes = await queueAutomaticVendorVerificationProbes(agent.tenant_id).catch(() => [])
    const discoveryResult = { ...result, automaticVerificationProbes }
    await recordRmmActivity({
      tenantId: agent.tenant_id,
      agentDeviceId: agent.id,
      inventoryId: agent.inventory_id,
      actorType: 'agent',
      actorLabel: 'SYSTEM',
      eventType: 'patch.discovery',
      category: 'patching',
      summary: 'SYSTEM: PatchHost refreshed software patch discovery',
      detail: [
        result.packages + ' WinGet package mappings reported',
        automaticVerificationProbes.length ? automaticVerificationProbes.length + ' vendor verification probe(s) queued' : '',
      ].filter(Boolean).join(' · '),
      outcome: 'success',
      metadata: discoveryResult,
    }).catch(() => null)
    return c.json({ success: true, ...discoveryResult })
  })

  app.get('/api/v1/rmm/patching', async (c) => {
    const auth = await requirePatchAccess(c)
    if (auth.error) return auth.error
    return c.json(await patchBundle(auth.session.tenant_id))
  })

  app.get('/api/v1/rmm/devices/:deviceId/patch-policy-resolution', async (c) => {
    const auth = await requirePatchAccess(c)
    if (auth.error) return auth.error
    const resolution = await devicePatchPolicyResolution(
      auth.session.tenant_id,
      c.req.param('deviceId'),
    )
    if (!resolution) return c.json({ error: 'Managed device not found.' }, 404)
    return c.json(resolution)
  })

  app.get('/api/v1/rmm/patching/catalogue', async (c) => {
    const auth = await requirePatchAccess(c)
    if (auth.error) return auth.error
    try {
      return c.json(await unifiedCatalogueSearch(auth.session.tenant_id, {
        query: c.req.query('q'),
        source: c.req.query('source'),
        provider: c.req.query('provider'),
        page: c.req.query('page'),
        pageSize: c.req.query('pageSize'),
      }))
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Unable to read the software catalogue.' }, 503)
    }
  })

  app.get('/api/v1/rmm/patching/winget/repository', async (c) => {
    const auth = await requirePatchAccess(c)
    if (auth.error) return auth.error
    try {
      const result = await wingetRepositorySearch({
        query: clean(c.req.query('q')),
        page: Number(c.req.query('page') || 1),
        pageSize: Number(c.req.query('pageSize') || 50),
      })
      return c.json(result)
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Unable to read the WinGet repository.' }, 503)
    }
  })

  app.post('/api/v1/rmm/vendor-sources', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    try {
      const source = await createTenantVendorSource(auth.session, body)
      await audit(auth.session, 'patch.vendor_source.created', 'Created vendor source “' + clean(body.displayName) + '”', 'Draft · Test required before approval', { sourceId: source.id })
      return c.json({ success: true, source, bundle: await patchBundle(auth.session.tenant_id) }, 201)
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Unable to create vendor source.' }, 400)
    }
  })

  app.put('/api/v1/rmm/vendor-sources/:sourceId', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    try {
      const source = await updateTenantVendorSource(auth.session, clean(c.req.param('sourceId')), body)
      await audit(auth.session, 'patch.vendor_source.updated', 'Updated vendor source “' + clean(body.displayName) + '”', 'Approval reset · Source must be tested again', { sourceId: source.id })
      return c.json({ success: true, source, bundle: await patchBundle(auth.session.tenant_id) })
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Unable to update vendor source.' }, 400)
    }
  })

  app.post('/api/v1/rmm/vendor-sources/:sourceId/test', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    try {
      const sourceId = clean(c.req.param('sourceId'))
      const result = await testTenantVendorSource(auth.session.tenant_id, sourceId)
      let verificationProbe = null
      if (result.verificationRecommendation?.autoProbeRecommended) {
        verificationProbe = await queueVendorVerificationProbe({
          tenantId: auth.session.tenant_id,
          userId: auth.session.user_id,
          actorLabel: auth.session.name || auth.session.email || 'Technician',
          sourceId,
        })
        if (verificationProbe?.error && [404, 409].includes(verificationProbe.status)) verificationProbe = { queued: false, reason: verificationProbe.error }
        else if (verificationProbe?.success) verificationProbe = { queued: true, ...verificationProbe }
      }
      const recommendation = await tenantVendorVerificationRecommendation(auth.session.tenant_id, sourceId)
      await audit(
        auth.session,
        'patch.vendor_source.tested',
        'Tested vendor source',
        [
          result.version,
          result.trustState,
          recommendation.recommendedMethod ? 'Recommended: ' + recommendation.recommendedMethod.replaceAll('_', ' ') : '',
          recommendation.validated ? 'Validated' : recommendation.autoProbeRecommended ? 'Validation queued' : 'Awaiting validation',
        ].filter(Boolean).join(' · '),
        { sourceId: result.sourceId, result, recommendation, verificationProbe },
      )
      return c.json({ success: true, result: { ...result, verificationRecommendation: recommendation }, verificationProbe, bundle: await patchBundle(auth.session.tenant_id) })
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Vendor source test failed.' }, 409)
    }
  })

  app.post('/api/v1/rmm/vendor-sources/:sourceId/probe-verification', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const result = await queueVendorVerificationProbe({
      tenantId: auth.session.tenant_id,
      userId: auth.session.user_id,
      actorLabel: auth.session.name || auth.session.email || 'Technician',
      sourceId: clean(c.req.param('sourceId')),
      agentDeviceId: clean(body.agentDeviceId),
    })
    if (result.error) return c.json({ error: result.error, ...result }, result.status || 409)
    return c.json(result, 202)
  })

  app.post('/api/v1/rmm/vendor-sources/:sourceId/approve', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    try {
      const result = await approveTenantVendorSource(auth.session, clean(c.req.param('sourceId')))
      await audit(auth.session, 'patch.vendor_source.approved', 'Approved vendor source “' + result.source.display_name + '”', result.release.version + ' · ' + result.release.trustState, { sourceId: result.source.id })
      return c.json({ success: true, result, bundle: await patchBundle(auth.session.tenant_id) })
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Vendor source approval failed.' }, 409)
    }
  })

  app.delete('/api/v1/rmm/vendor-sources/:sourceId', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    try {
      const result = await archiveTenantVendorSource(auth.session, clean(c.req.param('sourceId')))
      await audit(auth.session, 'patch.vendor_source.archived', 'Archived vendor source “' + result.display_name + '”', '', { sourceId: result.id })
      return c.json({ success: true, bundle: await patchBundle(auth.session.tenant_id) })
    } catch (error) {
      return c.json({ error: clean(error?.message || error) || 'Unable to archive vendor source.' }, 404)
    }
  })

  app.get('/api/v1/rmm/vulnerabilities', async (c) => {
    const auth = await requirePatchAccess(c)
    if (auth.error) return auth.error
    return c.json({ summary: await vulnerabilitySummary(), vulnerabilities: await recentVulnerabilities(c.req.query('limit')) })
  })

  app.post('/api/v1/rmm/patching/software/plan-bulk', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.devices.control')) return c.json({ error: 'You do not have permission to control RMM devices.' }, 403)

    const body = await c.req.json().catch(() => ({}))
    const agentDeviceId = clean(body.agentDeviceId)
    const catalogueIds = [...new Set((Array.isArray(body.catalogueIds) ? body.catalogueIds : []).map(clean).filter(Boolean))]
    const mode = ['selected_catalogue', 'all_catalogue', 'all_winget'].includes(clean(body.mode)) ? clean(body.mode) : 'selected_catalogue'
    if (!agentDeviceId) return c.json({ error: 'Device is required.' }, 400)
    if (mode === 'selected_catalogue' && !catalogueIds.length) return c.json({ error: 'Select at least one catalogue application to preview.' }, 400)

    const preview = await bulkSoftwarePatchPlan(auth.session.tenant_id, agentDeviceId, mode, catalogueIds)
    if (preview.error) return c.json(preview, preview.status || 400)
    return c.json({
      success: true,
      mode: preview.mode,
      device: preview.device,
      candidateCount: preview.candidateCount,
      eligibleCount: preview.eligibleCount,
      ignoredCount: preview.ignoredCount,
      rejectedCount: preview.rejectedCount,
      items: preview.items,
      ignored: preview.ignored,
      rejected: preview.rejected,
    })
  })

  app.post('/api/v1/rmm/patching/software/deploy-bulk', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.devices.control')) return c.json({ error: 'You do not have permission to control RMM devices.' }, 403)

    const body = await c.req.json().catch(() => ({}))
    const agentDeviceId = clean(body.agentDeviceId)
    const catalogueIds = [...new Set((Array.isArray(body.catalogueIds) ? body.catalogueIds : []).map(clean).filter(Boolean))]
    const mode = ['selected_catalogue', 'all_catalogue', 'all_winget'].includes(clean(body.mode)) ? clean(body.mode) : 'selected_catalogue'
    if (!agentDeviceId) return c.json({ error: 'Device is required.' }, 400)
    if (mode === 'selected_catalogue' && !catalogueIds.length) return c.json({ error: 'Select at least one catalogue application.' }, 400)

    const preview = await bulkSoftwarePatchPlan(auth.session.tenant_id, agentDeviceId, mode, catalogueIds)
    if (preview.error) return c.json(preview, preview.status || 400)
    if (!preview.plans.length) {
      return c.json({ error: 'No eligible application updates remain for this device.', mode, ignored: preview.ignored, rejected: preview.rejected }, 422)
    }
    if (object(preview.plans[0]?.device?.patch_capabilities).softwareBulk !== true) {
      return c.json({ error: 'This endpoint Agent does not support verified bulk software patch jobs yet. Upgrade the Agent first.', capabilityMissing: true, requiredCapability: 'softwareBulk' }, 409)
    }

    const dispatched = await createAndDispatchBulkSoftwarePatch(auth.session, preview.plans, mode)
    if (!dispatched.dispatched) return c.json({ error: 'The device went offline before the bulk patch could be dispatched. No patch job was retained.', offline: true }, 409)
    return c.json({
      success: true,
      job: dispatched.job,
      deployments: dispatched.deployments,
      itemCount: preview.plans.length,
      skippedCount: preview.rejected.length + preview.ignored.length,
      rejected: preview.rejected,
      ignored: preview.ignored,
      mode,
      bundle: await patchBundle(auth.session.tenant_id),
    }, 202)
  })

  app.post('/api/v1/rmm/patching/software/deploy', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.devices.control')) {
      return c.json({ error: 'You do not have permission to control RMM devices.' }, 403)
    }

    const body = await c.req.json().catch(() => ({}))
    const agentDeviceId = clean(body.agentDeviceId)
    const catalogueId = clean(body.catalogueId)
    if (!agentDeviceId || !catalogueId) {
      return c.json({ error: 'Device and software catalogue entry are required.' }, 400)
    }

    const plan = await softwarePatchPlan(auth.session.tenant_id, agentDeviceId, catalogueId)
    if (plan.error) return c.json({ error: plan.error, offline: plan.offline, capabilityMissing: plan.capabilityMissing, current: plan.current, providerBlocked: plan.providerBlocked, installerTechnologyMigrationRequired: plan.installerTechnologyMigrationRequired, installedInstallerTechnology: plan.installedInstallerTechnology, targetInstallerTechnology: plan.targetInstallerTechnology }, plan.status || 400)

    const dispatched = await createAndDispatchSoftwarePatch(auth.session, plan)
    if (!dispatched.dispatched) {
      return c.json({ error: 'The device went offline before the patch could be dispatched. No patch job was retained.', offline: true }, 409)
    }

    return c.json({
      success: true,
      job: dispatched.job,
      deployment: dispatched.deployment,
      provider: plan.provider,
      bundle: await patchBundle(auth.session.tenant_id),
    }, 202)
  })

  app.post('/api/v1/rmm/patching/software/reject', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const agentDeviceId = clean(body.agentDeviceId), catalogueId = clean(body.catalogueId), targetVersion = clean(body.targetVersion)
    const reason = clean(body.reason).slice(0, 500)
    if (!agentDeviceId || !catalogueId || !targetVersion) return c.json({ error: 'Device, catalogue entry and target version are required.' }, 400)
    const device = await pool.query(`SELECT id,inventory_id FROM rmm_agent_devices WHERE id=$1 AND tenant_id=$2 AND disabled_at IS NULL`, [agentDeviceId, auth.session.tenant_id])
    if (!device.rowCount) return c.json({ error: 'Device was not found.' }, 404)
    const label = auth.session.name || auth.session.email || 'Technician'
    const result = await pool.query(`INSERT INTO rmm_device_patch_rejections (tenant_id,agent_device_id,catalogue_id,target_version,reason,rejected_by_user_id,rejected_by_label,revoked_at,revoked_by_user_id) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL) ON CONFLICT (tenant_id,agent_device_id,catalogue_id,target_version) DO UPDATE SET reason=EXCLUDED.reason,rejected_by_user_id=EXCLUDED.rejected_by_user_id,rejected_by_label=EXCLUDED.rejected_by_label,created_at=now(),revoked_at=NULL,revoked_by_user_id=NULL RETURNING id`, [auth.session.tenant_id,agentDeviceId,catalogueId,targetVersion,reason,auth.session.user_id,label])
    await audit(auth.session, 'patch.software.rejected', label + ' ignored a device patch', targetVersion + (reason ? ' · ' + reason : ''), { agentDeviceId, inventoryId: device.rows[0].inventory_id, catalogueId, targetVersion, rejectionId: result.rows[0].id })
    return c.json({ success: true, bundle: await patchBundle(auth.session.tenant_id) })
  })

  app.delete('/api/v1/rmm/patching/software/rejections/:rejectionId', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const rejectionId = clean(c.req.param('rejectionId'))
    const result = await pool.query(`UPDATE rmm_device_patch_rejections SET revoked_at=now(),revoked_by_user_id=$3 WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL RETURNING agent_device_id,catalogue_id,target_version`, [auth.session.tenant_id,rejectionId,auth.session.user_id])
    if (!result.rowCount) return c.json({ error: 'Active patch rejection was not found.' }, 404)
    const row = result.rows[0]
    const device = await pool.query(`SELECT inventory_id FROM rmm_agent_devices WHERE id=$1 AND tenant_id=$2 LIMIT 1`, [row.agent_device_id, auth.session.tenant_id])
    await audit(auth.session, 'patch.software.rejection_revoked', (auth.session.name || auth.session.email || 'Technician') + ' restored a device patch', row.target_version, { rejectionId, agentDeviceId: row.agent_device_id, inventoryId: device.rows[0]?.inventory_id || null, catalogueId: row.catalogue_id })
    return c.json({ success: true, bundle: await patchBundle(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/patching/software/install', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.devices.control')) {
      return c.json({ error: 'You do not have permission to control RMM devices.' }, 403)
    }

    const body = await c.req.json().catch(() => ({}))
    const agentDeviceId = clean(body.agentDeviceId)
    const catalogueId = clean(body.catalogueId)
    if (!agentDeviceId || !catalogueId) {
      return c.json({ error: 'Device and software catalogue entry are required.' }, 400)
    }

    const plan = await softwarePatchPlan(auth.session.tenant_id, agentDeviceId, catalogueId, { intent: 'install' })
    if (plan.error) {
      return c.json({
        error: plan.error,
        offline: plan.offline,
        capabilityMissing: plan.capabilityMissing,
        requiredPatchHostVersion: plan.requiredPatchHostVersion,
        current: plan.current,
      }, plan.status || 400)
    }

    const dispatched = await createAndDispatchSoftwarePatch(auth.session, plan, { source: 'rmm_catalogue_install' })
    if (!dispatched.dispatched) {
      return c.json({ error: 'The device went offline before the install could be dispatched. No install job was retained.', offline: true }, 409)
    }

    return c.json({
      success: true,
      job: dispatched.job,
      deployment: dispatched.deployment,
      provider: plan.provider,
      bundle: await patchBundle(auth.session.tenant_id),
    }, 202)
  })

  app.post('/api/v1/rmm/vulnerability-exposures/:exposureId/remediate', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    if (!hasPermission(auth.session.access, 'rmm.devices.control')) {
      return c.json({ error: 'You do not have permission to control RMM devices.' }, 403)
    }

    const exposureId = clean(c.req.param('exposureId'))
    const exposureResult = await pool.query(
      `SELECT e.id::text,e.cve_id,e.status,e.remediation_state,e.catalogue_id,
              a.agent_device_id
         FROM rmm_vulnerability_exposures e
         LEFT JOIN LATERAL (
           SELECT id::text AS agent_device_id
             FROM rmm_agent_devices
            WHERE tenant_id=e.tenant_id AND inventory_id=e.inventory_id AND disabled_at IS NULL
            ORDER BY last_telemetry_at DESC NULLS LAST
            LIMIT 1
         ) a ON true
        WHERE e.tenant_id=$1 AND e.id::text=$2
        LIMIT 1`,
      [auth.session.tenant_id, exposureId],
    )
    const exposure = exposureResult.rows[0]
    if (!exposure) return c.json({ error: 'Vulnerability exposure not found.' }, 404)
    if (exposure.status !== 'open') {
      return c.json({ error: 'This vulnerability exposure is no longer open.' }, 409)
    }
    if (exposure.remediation_state !== 'available' || !exposure.catalogue_id) {
      return c.json({ error: 'No verified software remediation is currently available for this exposure.' }, 409)
    }
    if (!exposure.agent_device_id) {
      return c.json({ error: 'This device is offline. No patch job was queued.', offline: true }, 409)
    }

    const plan = await softwarePatchPlan(
      auth.session.tenant_id,
      exposure.agent_device_id,
      exposure.catalogue_id,
    )
    if (plan.error) {
      return c.json({
        error: plan.error,
        offline: plan.offline,
        capabilityMissing: plan.capabilityMissing,
        current: plan.current,
        providerBlocked: plan.providerBlocked,
      }, plan.status || 400)
    }

    const dispatched = await createAndDispatchSoftwarePatch(auth.session, plan, {
      source: 'rmm_vulnerability_remediation',
      cveId: exposure.cve_id,
      exposureId: exposure.id,
    })
    if (!dispatched.dispatched) {
      return c.json({
        error: 'The device went offline before the remediation could be dispatched. No patch job was retained.',
        offline: true,
      }, 409)
    }

    return c.json({
      success: true,
      cveId: exposure.cve_id,
      job: dispatched.job,
      deployment: dispatched.deployment,
      provider: plan.provider,
      bundle: await patchBundle(auth.session.tenant_id),
    }, 202)
  })

  app.get('/api/v1/rmm/software-catalogue/:catalogueId/qualification-lab', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const catalogueId=clean(c.req.param('catalogueId'))
    const lab=await qualificationLabPayload(auth.session.tenant_id,catalogueId)
    if(!lab) return c.json({error:'Software catalogue entry not found.'},404)
    return c.json({lab})
  })

  app.post('/api/v1/rmm/software-catalogue/:catalogueId/qualification-lab/action', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const catalogueId=clean(c.req.param('catalogueId'))
    const body=await c.req.json().catch(()=>({}))
    const action=clean(body.action)
    const before=await qualificationLabPayload(auth.session.tenant_id,catalogueId)
    if(!before) return c.json({error:'Software catalogue entry not found.'},404)

    let result=null
    if(action==='clean_cycle') {
      result=await retrySoftwareQualification(catalogueId,{mode:'clean_only'})
    } else if(action==='full') {
      result=await retrySoftwareQualification(catalogueId,{mode:'full'})
    } else if(action==='upgrade') {
      result=await queueUpgradeQualification(catalogueId)
    } else if(action==='rollback') {
      result=await queueRollbackQualification(catalogueId)
    } else if(action==='prepare_previous') {
      result=await prepareQualificationBaselineForCatalogue(catalogueId)
    } else if(action==='mark_limited') {
      const allowedCapabilities=new Set(['clean_install','uninstall','upgrade','rollback','vulnerability_coverage'])
      const unsupportedCapabilities=[...new Set((Array.isArray(body.unsupportedCapabilities)?body.unsupportedCapabilities:[])
        .map((value)=>clean(value))
        .filter((value)=>allowedCapabilities.has(value)))]
      const reason=clean(body.reason).slice(0,1000)
      if(!unsupportedCapabilities.length) return c.json({error:'Select at least one unsupported capability.'},400)
      if(reason.length<8) return c.json({error:'Enter a clear reason for the limited qualification.'},400)
      const current=before.releases?.current
      const trusted=before.source?.state==='healthy'
        && before.application?.trustState==='direct_ready'
        && current?.publishedSha256Present===true
        && current?.sha256Verified===true
        && current?.signatureVerified===true
        && Boolean(current?.verifiedSigner)
      if(!trusted) return c.json({error:'Limited qualification still requires a healthy trusted source and a verified current installer artifact.'},409)

      const capabilityState=(key,testState,verifiedValue='verified')=>unsupportedCapabilities.includes(key)
        ? 'unsupported'
        : testState==='passed' ? verifiedValue : 'available'
      const capabilities={
        cleanInstall:capabilityState('clean_install',before.tests?.cleanInstall?.state),
        uninstall:capabilityState('uninstall',before.tests?.uninstall?.state),
        upgrade:capabilityState('upgrade',before.tests?.upgrade?.state),
        rollback:capabilityState('rollback',before.tests?.rollback?.state),
        vulnerabilityCoverage:unsupportedCapabilities.includes('vulnerability_coverage')
          ? 'unsupported'
          : before.vulnerability?.state==='covered'
            ? 'covered'
            : before.vulnerability?.state==='no_published_identity' ? 'limited' : 'pending',
      }
      const limitation={
        state:'declared',
        reason,
        unsupportedCapabilities,
        recordedAt:new Date().toISOString(),
        recordedByUserId:auth.session.user_id,
        recordedBy:clean(auth.session.name || auth.session.email || 'Technician').slice(0,255),
      }
      await withTransaction(async(client)=>{
        await client.query(
          `UPDATE rmm_software_catalogue
              SET qualification_state='qualified_limited',
                  qualification_version=target_version,
                  qualified_at=now(),
                  qualification_notes=$2,
                  qualification_evidence=qualification_evidence || jsonb_build_object(
                    'manualLimitedQualification',true,
                    'manualLimitedQualifiedAt',now(),
                    'qualificationCapabilities',$3::jsonb,
                    'qualificationLimitations',jsonb_build_object('manual',$4::jsonb)
                  ),
                  updated_by_user_id=$5,
                  updated_at=now()
            WHERE id=$1`,
          [catalogueId,'Limited qualification: '+reason,JSON.stringify(capabilities),JSON.stringify(limitation),auth.session.user_id],
        )
        await client.query(
          `UPDATE rmm_software_qualification_queue
              SET state='cancelled',
                  last_error='limited_capability_declared',
                  completed_at=now(),
                  evidence=evidence || jsonb_build_object(
                    'limitedCapabilityDeclared',true,
                    'limitedCapabilityReason',$2::text,
                    'limitedUnsupportedCapabilities',$3::jsonb
                  ),
                  updated_at=now()
            WHERE catalogue_id=$1
              AND state IN ('queued','review_required')`,
          [catalogueId,reason,JSON.stringify(unsupportedCapabilities)],
        )
      })
      result={limited:true,state:'qualified_limited',unsupportedCapabilities,reason,capabilities}
    } else if(action==='clear_limited') {
      if(before.application?.qualificationState!=='qualified_limited') {
        return c.json({error:'This application is not currently marked as limited.'},409)
      }
      await pool.query(
        `UPDATE rmm_software_catalogue
            SET qualification_state='deployment_candidate',
                qualification_version='',
                qualified_at=NULL,
                qualification_notes='Limited qualification removed; current-version install/verify/uninstall qualification is required again.',
                qualification_evidence=(qualification_evidence
                  - 'manualLimitedQualification'
                  - 'manualLimitedQualifiedAt'
                  - 'qualificationCapabilities'
                  - 'qualificationLimitations')
                  || jsonb_build_object('manualLimitedQualificationClearedAt',now()),
                updated_by_user_id=$2,
                updated_at=now()
          WHERE id=$1`,
        [catalogueId,auth.session.user_id],
      )
      result={cleared:true,state:'deployment_candidate'}
    } else {
      return c.json({error:'Unsupported qualification action.'},400)
    }

    const accepted = action==='prepare_previous'
      ? result?.prepared===true
      : action==='mark_limited'
        ? result?.limited===true
        : action==='clear_limited'
          ? result?.cleared===true
          : result?.queued===true
    const lab=await qualificationLabPayload(auth.session.tenant_id,catalogueId)
    if(!accepted) {
      return c.json({
        error:'Qualification action cannot run yet: '+clean(result?.reason || result?.state || 'not ready').replaceAll('_',' '),
        action,result,lab,
      },409)
    }

    const labels={
      clean_cycle:'Started clean install / verify / uninstall qualification',
      full:'Started full catalogue qualification',
      upgrade:'Started versioned upgrade qualification',
      rollback:'Started rollback qualification',
      prepare_previous:'Prepared previous stable release for qualification',
      mark_limited:'Marked catalogue qualification as limited capabilities',
      clear_limited:'Returned limited catalogue qualification to deployment candidate',
    }
    await audit(
      auth.session,
      'software_catalogue.qualification_action',
      (labels[action] || 'Ran catalogue qualification action')+' for “'+before.application.name+'”',
      [
        result?.previousVersion ? 'Previous '+result.previousVersion : '',
        before.application.targetVersion ? 'Target '+before.application.targetVersion : '',
        result?.state ? clean(result.state).replaceAll('_',' ') : '',
      ].filter(Boolean).join(' · '),
      {catalogueId,action,result},
    )
    return c.json({
      success:true,
      action,
      result,
      lab,
      bundle:await patchBundle(auth.session.tenant_id),
    },202)
  })

  app.put('/api/v1/rmm/software-catalogue/:catalogueId/validation', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const catalogueId = clean(c.req.param('catalogueId'))
    const body = await c.req.json().catch(() => ({}))

    const currentResult = await pool.query(
      `SELECT c.*,s.source_key AS vendor_source_key,s.source_type AS vendor_source_type,
              s.source_url AS vendor_source_url,s.metadata AS vendor_source_metadata,
              b.metadata AS vendor_binding_metadata
         FROM rmm_software_catalogue c
         LEFT JOIN rmm_software_vendor_sources s
           ON s.source_key=c.source_metadata->>'latestSource'
         LEFT JOIN rmm_software_vendor_bindings b
           ON b.source_key=s.source_key
          AND b.provider_package_id=c.external_key
          AND b.enabled=true
        WHERE c.id=$1 AND c.status<>'archived'
          AND (c.tenant_id=$2 OR c.tenant_id IS NULL)
        LIMIT 1`,
      [catalogueId, auth.session.tenant_id],
    )
    const current = currentResult.rows[0]
    if (!current) return c.json({ error: 'Software catalogue entry not found.' }, 404)

    const active = await pool.query(
      `SELECT id,state FROM rmm_software_qualification_queue
        WHERE catalogue_id=$1 AND state IN ('running','cleanup_pending','cleanup_running')
        LIMIT 1`,
      [catalogueId],
    )
    if (active.rowCount) {
      return c.json({ error: 'This software is currently being qualified. Finish the active test before editing validation settings.', state: active.rows[0].state }, 409)
    }

    const canonicalName = clean(body.canonicalName || current.canonical_name)
    const publisher = clean(body.publisher ?? current.publisher)
    const namePattern = clean(body.namePattern || current.name_pattern || canonicalName)
    const publisherPattern = clean(body.publisherPattern ?? current.publisher_pattern)
    const verification = {
      ...object(current.verification),
      ...(body.verification && typeof body.verification === 'object' ? object(body.verification) : {}),
    }
    const execution = {
      ...object(current.execution),
      ...(body.execution && typeof body.execution === 'object' ? object(body.execution) : {}),
    }

    const responseFile = normalizedVendorResponseFile(execution.responseFile)
    execution.responseFile = responseFile
    if (responseFile) {
      if (!safeVendorResponseFileName(responseFile.fileName)) {
        return c.json({ error: 'Response-file name must be a safe basename ending in .xml, .iss, .ini, .txt, .json, .config, or .rsp.' }, 400)
      }
      if (!responseFile.content || Buffer.byteLength(responseFile.content, 'utf8') > 64 * 1024 || responseFile.content.includes('\0')) {
        return c.json({ error: 'Response-file content must be between 1 byte and 64 KiB and cannot contain NUL characters.' }, 400)
      }
      if (!clean(execution.installArguments).includes('{HI5_RESPONSE_FILE}')) {
        return c.json({ error: 'Silent install arguments must include {HI5_RESPONSE_FILE} when a response file is configured.' }, 400)
      }
    }

    const sourceUrl = clean(body.sourceUrl ?? current.vendor_source_url)
    const sourcePatch = {}
    for (const key of ['repository','assetPattern','checksumAssetPattern','releaseTagPattern','staticInstallerUrl','staticSha256','staticReleaseUrl']) {
      if (body[key] !== undefined) sourcePatch[key] = clean(body[key])
    }
    for (const key of ['sourceUrl','staticInstallerUrl','staticReleaseUrl']) {
      const value = key === 'sourceUrl' ? sourceUrl : clean(sourcePatch[key])
      if (value && !/^https:\/\//i.test(value)) return c.json({ error: key + ' must use HTTPS.' }, 400)
    }

    const currentSourceMetadata = object(current.source_metadata)
    const currentVendorSourceMetadata = object(current.vendor_source_metadata)
    const currentBindingMetadata = object(current.vendor_binding_metadata)
    const expectedSigner = clean(body.expectedSigner ?? currentSourceMetadata.expectedSigner)

    const vulnerabilityIdentityProvided = Boolean(body.vulnerabilityIdentity && typeof body.vulnerabilityIdentity === 'object')
    const vulnerabilityIdentity = object(body.vulnerabilityIdentity)
    const nvdVendor = clean(vulnerabilityIdentity.nvdVendor ?? currentSourceMetadata.nvdVendor)
    const nvdProduct = clean(vulnerabilityIdentity.nvdProduct ?? currentSourceMetadata.nvdProduct)
    const osvEcosystem = clean(vulnerabilityIdentity.osvEcosystem ?? currentSourceMetadata.osvEcosystem)
    const osvPackage = clean(vulnerabilityIdentity.osvPackage ?? currentSourceMetadata.osvPackage)
    const githubRepositoryInput = clean(vulnerabilityIdentity.githubRepository ?? currentSourceMetadata.githubRepository)
    const githubRepository = githubRepositoryInput ? normalizeGithubRepository(githubRepositoryInput) : ''
    const vulnerabilityDisposition = clean(vulnerabilityIdentity.disposition ?? currentSourceMetadata.vulnerabilityIdentityDisposition)
    const vulnerabilityIdentityNote = clean(vulnerabilityIdentity.note ?? currentSourceMetadata.vulnerabilityIdentityNote).slice(0, 1000)
    if (!['', 'no_published_identity'].includes(vulnerabilityDisposition)) {
      return c.json({ error: 'Vulnerability identity disposition is not supported.' }, 400)
    }
    if (vulnerabilityDisposition === 'no_published_identity' && (nvdVendor || nvdProduct || osvEcosystem || osvPackage || githubRepository)) {
      return c.json({ error: 'Clear NVD, OSV and GitHub identity fields before marking this application as having no published identity.' }, 400)
    }
    const currentVulnerabilityIdentity = {
      nvdVendor: clean(currentSourceMetadata.nvdVendor),
      nvdProduct: clean(currentSourceMetadata.nvdProduct),
      osvEcosystem: clean(currentSourceMetadata.osvEcosystem),
      osvPackage: clean(currentSourceMetadata.osvPackage),
      githubRepository: normalizeGithubRepository(currentSourceMetadata.githubRepository),
      disposition: clean(currentSourceMetadata.vulnerabilityIdentityDisposition),
      note: clean(currentSourceMetadata.vulnerabilityIdentityNote),
    }
    const nextVulnerabilityIdentity = {
      nvdVendor,
      nvdProduct,
      osvEcosystem,
      osvPackage,
      githubRepository,
      disposition: vulnerabilityDisposition,
      note: vulnerabilityIdentityNote,
    }
    const vulnerabilityIdentityEdited = vulnerabilityIdentityProvided
      && stableJson(nextVulnerabilityIdentity) !== stableJson(currentVulnerabilityIdentity)

    if (vulnerabilityIdentityEdited && Boolean(nvdVendor) !== Boolean(nvdProduct)) {
      return c.json({ error: 'NVD vendor and product must be supplied together.' }, 400)
    }
    if (vulnerabilityIdentityEdited && Boolean(osvEcosystem) !== Boolean(osvPackage)) {
      return c.json({ error: 'OSV ecosystem and package must be supplied together.' }, 400)
    }
    if (vulnerabilityIdentityEdited && githubRepositoryInput && !githubRepository) {
      return c.json({ error: 'GitHub repository must be owner/repository or a github.com repository URL.' }, 400)
    }

    const currentVerification = object(current.verification)
    const currentExecution = object(current.execution)
    const verificationChanged = Boolean(
      clean(verification.method || verification.provider || 'winget') !== clean(currentVerification.method || currentVerification.provider || 'winget')
      || clean(verification.packageId) !== clean(currentVerification.packageId)
      || clean(verification.productCode) !== clean(currentVerification.productCode)
      || clean(verification.filePath) !== clean(currentVerification.filePath)
      || clean(verification.displayNameContains) !== clean(currentVerification.displayNameContains)
      || clean(verification.publisherContains) !== clean(currentVerification.publisherContains)
      || clean(verification.versionTransform) !== clean(currentVerification.versionTransform)
    )
    const executionArgumentsChanged = clean(execution.installArguments) !== clean(currentExecution.installArguments)
    const responseFileChanged = stableJson(responseFile) !== stableJson(normalizedVendorResponseFile(currentExecution.responseFile))
    const executionChanged = executionArgumentsChanged || responseFileChanged
    if (verificationChanged) {
      const verificationMethod = lower(verification.method || verification.provider || 'winget')
      if (!['winget', 'uninstall_registry', 'file_version'].includes(verificationMethod)) {
        return c.json({ error: 'Verification method must be WinGet, uninstall registry, or file version.' }, 400)
      }
      if (verificationMethod === 'winget' && !clean(verification.packageId)) {
        return c.json({ error: 'WinGet verification requires a package ID.' }, 400)
      }
      if (verificationMethod === 'uninstall_registry'
        && !clean(verification.productCode)
        && !clean(verification.displayNameContains)) {
        return c.json({ error: 'Uninstall-registry verification requires a ProductCode or display-name match.' }, 400)
      }
      if (verificationMethod === 'file_version' && !safeVerificationFilePath(verification.filePath)) {
        return c.json({ error: 'File-version verification requires a safe installed EXE/DLL path.' }, 400)
      }
    }
    const coreValidationChanged = Boolean(
      canonicalName !== clean(current.canonical_name)
      || publisher !== clean(current.publisher)
      || namePattern !== clean(current.name_pattern)
      || publisherPattern !== clean(current.publisher_pattern)
      || sourceUrl !== clean(current.vendor_source_url)
      || expectedSigner !== clean(currentSourceMetadata.expectedSigner)
      || verificationChanged
      || executionChanged
      || Object.entries(sourcePatch).some(([key, value]) => clean(currentVendorSourceMetadata[key]) !== clean(value))
    )

    const vulnerabilityMetadataPatch = vulnerabilityIdentityEdited ? {
      nvdVendor,
      nvdProduct,
      osvEcosystem,
      osvPackage,
      githubRepository,
      vulnerabilityIdentityDisposition: vulnerabilityDisposition,
      vulnerabilityIdentityNote,
      vulnerabilityIdentityManualEditAt: new Date().toISOString(),
    } : {}

    if (!current.tenant_id && clean(current.catalogue_source) === 'vendor' && current.vendor_source_key) {
      const bindingPatch = {
        ...sourcePatch,
        expectedSigner,
        signerBaseline: expectedSigner || clean(object(current.source_metadata).signerBaseline),
        namePattern,
        publisherPattern,
        installArguments: clean(execution.installArguments),
        responseFile,
        manualExecutionOverride: currentBindingMetadata.manualExecutionOverride === true || executionChanged,
        manualExecutionOverrideAt: executionChanged
          ? new Date().toISOString()
          : currentBindingMetadata.manualExecutionOverrideAt,
        verificationConfig: verification,
      }
      await withTransaction(async (client) => {
        await client.query(
          `UPDATE rmm_software_vendor_sources
              SET source_url=$2,
                  metadata=metadata || $3::jsonb,
                  last_error='',
                  updated_at=now()
            WHERE source_key=$1`,
          [current.vendor_source_key, sourceUrl, JSON.stringify(sourcePatch)],
        )
        await client.query(
          `UPDATE rmm_software_vendor_bindings
              SET publisher=$3,metadata=metadata || $4::jsonb
            WHERE source_key=$1 AND provider_package_id=$2 AND enabled=true`,
          [current.vendor_source_key, current.external_key, publisher, JSON.stringify(bindingPatch)],
        )

        if (vulnerabilityIdentityEdited) {
          await client.query(
            `UPDATE rmm_software_vulnerability_identities
                SET enabled=false,updated_at=now()
              WHERE catalogue_id=$1 AND source IN ('nvd','osv','github')`,
            [catalogueId],
          )
          const identityMetadata = JSON.stringify({
            origin: 'manual_validation_modal',
            validatedByUserId: auth.session.user_id,
            editedAt: new Date().toISOString(),
          })
          if (nvdVendor && nvdProduct) {
            await client.query(
              `INSERT INTO rmm_software_vulnerability_identities
                (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
               VALUES ($1,'nvd',$2,$3,'','','','curated',true,$4::jsonb)
               ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
               DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now()`,
              [catalogueId, nvdVendor, nvdProduct, identityMetadata],
            )
          }
          if (osvEcosystem && osvPackage) {
            await client.query(
              `INSERT INTO rmm_software_vulnerability_identities
                (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
               VALUES ($1,'osv','','','',$2,$3,'curated',true,$4::jsonb)
               ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
               DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now()`,
              [catalogueId, osvEcosystem, osvPackage, identityMetadata],
            )
          }
          if (githubRepository) {
            await client.query(
              `INSERT INTO rmm_software_vulnerability_identities
                (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
               VALUES ($1,'github','','','','GitHub',$2,'curated',true,$3::jsonb)
               ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
               DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now()`,
              [catalogueId, githubRepository, JSON.stringify({
                origin: 'manual_validation_modal',
                repository: githubRepository,
                validatedByUserId: auth.session.user_id,
                editedAt: new Date().toISOString(),
              })],
            )
          }
        }

        if (coreValidationChanged) {
          await client.query(
          `UPDATE rmm_software_vendor_releases
              SET trust_state='asset_candidate',
                  source_payload=source_payload || jsonb_build_object(
                    'expectedSigner',$3::text,
                    'verification',$4::jsonb,
                    'responseFile',$5::jsonb,
                    'manualValidationEditAt',now()
                  ),
                  last_seen_at=last_seen_at
            WHERE source_key=$1 AND provider_package_id=$2 AND version=$6`,
          [current.vendor_source_key, current.external_key, expectedSigner, JSON.stringify(verification), JSON.stringify(responseFile), current.target_version],
        )
        await client.query(
          `UPDATE rmm_software_catalogue
              SET canonical_name=$2,publisher=$3,name_pattern=$4,publisher_pattern=$5,
                  verification=$6::jsonb,execution=$7::jsonb,
                  qualification_state='deployment_candidate',qualification_version='',qualified_at=NULL,
                  qualification_evidence=qualification_evidence
                    - 'cleanInstallVerified' - 'cleanInstallVersion' - 'cleanInstallVerifiedAt'
                    - 'uninstallVerified' - 'uninstallVerifiedAt'
                    - 'upgradeVerified' - 'upgradeFromVersion' - 'upgradeVersion' - 'upgradeVerifiedAt'
                    - 'sha256Verified' - 'authenticodeVerified'
                    || jsonb_build_object('manualValidationEditAt',now()),
                  source_metadata=source_metadata || jsonb_build_object(
                    'expectedSigner',$8::text,'trustState','asset_candidate','manualValidationEditAt',now()
                  ) || $10::jsonb,
                  updated_by_user_id=$9,updated_at=now()
            WHERE id=$1`,
          [catalogueId, canonicalName, publisher, namePattern, publisherPattern, JSON.stringify(verification), JSON.stringify(execution), expectedSigner, auth.session.user_id, JSON.stringify(vulnerabilityMetadataPatch)],
        )
        await client.query(
          `UPDATE rmm_software_qualification_queue
              SET state='cancelled',last_error='manual_validation_edit',
                  completed_at=now(),updated_at=now()
            WHERE catalogue_id=$1
              AND state NOT IN ('running','cleanup_pending','cleanup_running')`,
          [catalogueId],
        )
        } else {
          await client.query(
            `UPDATE rmm_software_catalogue
                SET canonical_name=$2,publisher=$3,name_pattern=$4,publisher_pattern=$5,
                    verification=$6::jsonb,execution=$7::jsonb,
                    source_metadata=source_metadata || $8::jsonb,
                    qualification_state=CASE
                      WHEN qualification_state='blocked' THEN qualification_state
                      WHEN $10::boolean THEN 'deployment_candidate'
                      ELSE qualification_state
                    END,
                    qualification_version=CASE WHEN $10::boolean THEN '' ELSE qualification_version END,
                    qualified_at=CASE WHEN $10::boolean THEN NULL ELSE qualified_at END,
                    updated_by_user_id=$9,updated_at=now()
              WHERE id=$1`,
            [catalogueId, canonicalName, publisher, namePattern, publisherPattern, JSON.stringify(verification), JSON.stringify(execution), JSON.stringify(vulnerabilityMetadataPatch), auth.session.user_id, vulnerabilityIdentityEdited],
          )
        }
      })
    } else {
      await withTransaction(async (client) => {
        if (vulnerabilityIdentityEdited) {
          await client.query(
            `UPDATE rmm_software_vulnerability_identities
                SET enabled=false,updated_at=now()
              WHERE catalogue_id=$1 AND source IN ('nvd','osv','github')`,
            [catalogueId],
          )
          const identityMetadata = JSON.stringify({
            origin: 'manual_validation_modal',
            validatedByUserId: auth.session.user_id,
            editedAt: new Date().toISOString(),
          })
          if (nvdVendor && nvdProduct) {
            await client.query(
              `INSERT INTO rmm_software_vulnerability_identities
                (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
               VALUES ($1,'nvd',$2,$3,'','','','curated',true,$4::jsonb)
               ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
               DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now()`,
              [catalogueId, nvdVendor, nvdProduct, identityMetadata],
            )
          }
          if (osvEcosystem && osvPackage) {
            await client.query(
              `INSERT INTO rmm_software_vulnerability_identities
                (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
               VALUES ($1,'osv','','','',$2,$3,'curated',true,$4::jsonb)
               ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
               DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now()`,
              [catalogueId, osvEcosystem, osvPackage, identityMetadata],
            )
          }
          if (githubRepository) {
            await client.query(
              `INSERT INTO rmm_software_vulnerability_identities
                (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
               VALUES ($1,'github','','','','GitHub',$2,'curated',true,$3::jsonb)
               ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
               DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now()`,
              [catalogueId, githubRepository, JSON.stringify({
                origin: 'manual_validation_modal',
                repository: githubRepository,
                validatedByUserId: auth.session.user_id,
                editedAt: new Date().toISOString(),
              })],
            )
          }
        }
        await client.query(
          `UPDATE rmm_software_catalogue
              SET canonical_name=$3,publisher=$4,name_pattern=$5,publisher_pattern=$6,
                  verification=$7::jsonb,execution=$8::jsonb,
                  source_metadata=source_metadata || $9::jsonb,
                  qualification_state=CASE
                    WHEN qualification_state='blocked' THEN qualification_state
                    WHEN $10::boolean THEN 'deployment_candidate'
                    ELSE qualification_state
                  END,
                  qualification_version=CASE WHEN $10::boolean THEN '' ELSE qualification_version END,
                  qualified_at=CASE WHEN $10::boolean THEN NULL ELSE qualified_at END,
                  updated_by_user_id=$11,updated_at=now()
            WHERE id=$1 AND (tenant_id=$2 OR tenant_id IS NULL)`,
          [
            catalogueId,
            auth.session.tenant_id,
            canonicalName,
            publisher,
            namePattern,
            publisherPattern,
            JSON.stringify(verification),
            JSON.stringify(execution),
            JSON.stringify(vulnerabilityMetadataPatch),
            coreValidationChanged || vulnerabilityIdentityEdited,
            auth.session.user_id,
          ],
        )
      })
    }

    let vulnerabilityValidation = null
    if (vulnerabilityIdentityEdited) {
      try {
        const identityAudit = await auditCatalogueVulnerabilityIdentities({ limit: 1, force: true, catalogueId })
        vulnerabilityValidation = identityAudit.rows.find((row) => row.id === catalogueId) || {
          state: 'needs_review',
          method: 'identity_not_resolved',
        }
        if (vulnerabilityValidation.state === 'covered' && vulnerabilityValidation.resolvedSource === 'github') {
          const advisoryValidation = await syncGithubRepositoryAdvisoriesForCatalogue(
            catalogueId,
            vulnerabilityValidation.packageName || githubRepository,
          )
          vulnerabilityValidation = {
            ...vulnerabilityValidation,
            advisoryValidation,
            state: advisoryValidation.ok ? 'covered' : 'failed',
            error: advisoryValidation.ok ? '' : clean(advisoryValidation.reason).replaceAll('_', ' '),
          }
        }
        if (vulnerabilityValidation.state === 'covered') {
          await promoteAutomaticAdmissionReady({ limit: 50 })
        }
      } catch (error) {
        vulnerabilityValidation = {
          state: 'failed',
          method: 'identity_validation_error',
          error: clean(error?.message || error).slice(0, 1000),
        }
      }
    }

    await audit(auth.session, 'software_catalogue.validation_updated', 'Updated validation settings for “' + canonicalName + '”', '', {
      catalogueId,
      coreValidationChanged,
      vulnerabilityIdentityEdited,
      vulnerabilityValidation,
    })
    return c.json({
      success: true,
      revalidateSource: coreValidationChanged,
      vulnerabilityValidation,
      bundle: await patchBundle(auth.session.tenant_id),
    })
  })

  app.post('/api/v1/rmm/software-catalogue/:catalogueId/revalidate', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const catalogueId = clean(c.req.param('catalogueId'))
    const result = await pool.query(
      `SELECT c.id,c.canonical_name,c.tenant_id,c.catalogue_source,c.source_metadata->>'latestSource' AS source_key
         FROM rmm_software_catalogue c
        WHERE c.id=$1 AND c.status='active' AND (c.tenant_id=$2 OR c.tenant_id IS NULL)
        LIMIT 1`,
      [catalogueId, auth.session.tenant_id],
    )
    const item = result.rows[0]
    if (!item) return c.json({ error: 'Software catalogue entry not found.' }, 404)
    if (!item.source_key) return c.json({ error: 'This software does not have a refreshable vendor source.' }, 409)

    let source
    try {
      source = await syncSoftwareVendorSource(item.source_key)
    } catch (error) {
      await audit(auth.session, 'software_catalogue.revalidation_failed', 'Vendor source validation failed for “' + item.canonical_name + '”', clean(error?.message || error), { catalogueId, sourceKey: item.source_key })
      return c.json({ error: clean(error?.message || error) || 'Vendor source validation failed.', sourceKey: item.source_key, bundle: await patchBundle(auth.session.tenant_id) }, 409)
    }

    let inspection = { queued: false, reason: 'artifact_probe_not_required_for_this_source' }
    if (!item.tenant_id && clean(item.catalogue_source) === 'vendor') {
      await withTransaction(async (client) => {
        await client.query(
          `UPDATE rmm_software_vendor_releases r
              SET trust_state='asset_candidate',
                  trust_evidence=trust_evidence || jsonb_build_object('manualRevalidationRequestedAt',now())
             FROM rmm_software_catalogue c
            WHERE c.id=$1
              AND r.provider_package_id=c.external_key
              AND r.source_key=c.source_metadata->>'latestSource'
              AND r.version=c.target_version`,
          [catalogueId],
        )
        await client.query(
          `UPDATE rmm_software_catalogue
              SET source_metadata=source_metadata || jsonb_build_object(
                    'trustState','asset_candidate',
                    'manualRevalidationRequestedAt',now()
                  ),
                  updated_at=now()
            WHERE id=$1`,
          [catalogueId],
        )
      })
      inspection = await queueVendorArtifactInspectionForCatalogue(catalogueId)
    }
    await audit(auth.session, 'software_catalogue.revalidation_requested', 'Revalidated vendor source for “' + item.canonical_name + '”', item.source_key, { catalogueId, sourceKey: item.source_key, inspection })
    return c.json({ success: true, source, inspection, bundle: await patchBundle(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/software-catalogue/:catalogueId/retry-qualification', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const catalogueId = clean(c.req.param('catalogueId'))
    const visible = await pool.query(
      `SELECT id,canonical_name FROM rmm_software_catalogue
        WHERE id=$1 AND status='active' AND (tenant_id=$2 OR tenant_id IS NULL) LIMIT 1`,
      [catalogueId, auth.session.tenant_id],
    )
    if (!visible.rowCount) return c.json({ error: 'Software catalogue entry not found.' }, 404)
    const retry = await retrySoftwareQualification(catalogueId)
    if (!retry.queued) {
      return c.json({ error: 'Qualification cannot be retried yet: ' + clean(retry.reason || retry.state || 'not ready').replaceAll('_', ' '), retry, bundle: await patchBundle(auth.session.tenant_id) }, 409)
    }
    await audit(auth.session, 'software_catalogue.qualification_retried', 'Retried catalogue qualification for “' + visible.rows[0].canonical_name + '”', '', { catalogueId })
    return c.json({ success: true, retry, bundle: await patchBundle(auth.session.tenant_id) }, 202)
  })

  app.post('/api/v1/rmm/software-catalogue', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const canonicalName = clean(body.canonicalName)
    const namePattern = clean(body.namePattern || canonicalName)
    if (canonicalName.length < 2 || namePattern.length < 2) {
      return c.json({ error: 'Application name and detection pattern are required.' }, 400)
    }
    const provider = validProvider(clean(body.provider))
    const result = await pool.query(
      `INSERT INTO rmm_software_catalogue
        (tenant_id,canonical_name,publisher,name_pattern,publisher_pattern,provider,provider_package_id,
         target_version,release_channel,installer_type,detection,execution,verification,qualification_state,
         created_by_user_id,updated_by_user_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,'deployment_candidate',$14,$14)
       RETURNING id`,
      [
        auth.session.tenant_id,
        canonicalName,
        clean(body.publisher),
        namePattern,
        clean(body.publisherPattern),
        provider,
        clean(body.packageId),
        clean(body.targetVersion),
        clean(body.releaseChannel || 'stable') || 'stable',
        clean(body.installerType),
        JSON.stringify(object(body.detection)),
        JSON.stringify(object(body.execution)),
        JSON.stringify(object(body.verification)),
        auth.session.user_id,
      ],
    )
    await audit(auth.session, 'software_catalogue.created', 'Created software patch mapping “' + canonicalName + '”', provider, { catalogueId: result.rows[0].id })
    return c.json({ success: true, id: result.rows[0].id, bundle: await patchBundle(auth.session.tenant_id) }, 201)
  })

  app.put('/api/v1/rmm/software-catalogue/:catalogueId', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const canonicalName = clean(body.canonicalName)
    const namePattern = clean(body.namePattern || canonicalName)
    if (canonicalName.length < 2 || namePattern.length < 2) return c.json({ error: 'Application name and detection pattern are required.' }, 400)
    const result = await pool.query(
      `UPDATE rmm_software_catalogue
          SET canonical_name=$3,publisher=$4,name_pattern=$5,publisher_pattern=$6,provider=$7,
              provider_package_id=$8,target_version=$9,release_channel=$10,installer_type=$11,
              updated_by_user_id=$12,updated_at=now()
        WHERE id=$1 AND tenant_id=$2 AND status<>'archived'
        RETURNING id`,
      [
        clean(c.req.param('catalogueId')), auth.session.tenant_id, canonicalName, clean(body.publisher),
        namePattern, clean(body.publisherPattern), validProvider(clean(body.provider)), clean(body.packageId),
        clean(body.targetVersion), clean(body.releaseChannel || 'stable') || 'stable', clean(body.installerType),
        auth.session.user_id,
      ],
    )
    if (!result.rowCount) return c.json({ error: 'Software patch mapping not found.' }, 404)
    await audit(auth.session, 'software_catalogue.updated', 'Updated software patch mapping “' + canonicalName + '”', '', { catalogueId: result.rows[0].id })
    return c.json({ success: true, bundle: await patchBundle(auth.session.tenant_id) })
  })

  app.delete('/api/v1/rmm/software-catalogue/:catalogueId', async (c) => {
    const auth = await requirePatchAccess(c, 'software')
    if (auth.error) return auth.error
    const result = await pool.query(
      `UPDATE rmm_software_catalogue SET status='archived',updated_by_user_id=$3,updated_at=now()
        WHERE id=$1 AND tenant_id=$2 AND status<>'archived' RETURNING id,canonical_name`,
      [clean(c.req.param('catalogueId')), auth.session.tenant_id, auth.session.user_id],
    )
    if (!result.rowCount) return c.json({ error: 'Software patch mapping not found.' }, 404)
    await audit(auth.session, 'software_catalogue.archived', 'Archived software patch mapping “' + result.rows[0].canonical_name + '”', '', { catalogueId: result.rows[0].id })
    return c.json({ success: true, bundle: await patchBundle(auth.session.tenant_id) })
  })
  app.post('/api/v1/rmm/vulnerability-policies/evaluate', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const decisions = await evaluateRealtimeVulnerabilityPolicies(auth.session.tenant_id, { dispatch: body.dispatch !== false })
    return c.json({ success: true, decisions })
  })

  app.post('/api/v1/rmm/windows-updates/evaluate', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const decisions = await evaluateWindowsUpdatePolicies(auth.session.tenant_id, {
      dispatch: body.dispatch !== false,
      agentSocketForDevice,
      sendAgentMessage,
    })
    return c.json({ success: true, decisions, windowsUpdates: await windowsUpdateBundle(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/windows-updates/:updateKey/pause', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const updateKey = clean(c.req.param('updateKey'))
    const body = await c.req.json().catch(() => ({}))
    const result = await setWindowsUpdateControl(auth.session.tenant_id, updateKey, 'paused', {
      userId: auth.session.user_id,
      reason: clean(body.reason) || 'Paused from Windows Update rollout console',
    })
    if (!result) return c.json({ error: 'Windows update release not found.' }, 404)
    await audit(
      auth.session,
      'windows_update.rollout_paused',
      'Paused Windows Update rollout “' + clean(result.release.title) + '”',
      clean(body.reason),
      { updateKey, kbArticles: result.release.kb_articles || [] },
    )
    return c.json({ success: true, control: result.control, windowsUpdates: await windowsUpdateBundle(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/windows-updates/:updateKey/resume', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const updateKey = clean(c.req.param('updateKey'))
    const result = await setWindowsUpdateControl(auth.session.tenant_id, updateKey, 'active', {
      userId: auth.session.user_id,
      reason: 'Rollout resumed',
    })
    if (!result) return c.json({ error: 'Windows update release not found.' }, 404)
    await audit(
      auth.session,
      'windows_update.rollout_resumed',
      'Resumed Windows Update rollout “' + clean(result.release.title) + '”',
      '',
      { updateKey, kbArticles: result.release.kb_articles || [] },
    )
    return c.json({ success: true, control: result.control, windowsUpdates: await windowsUpdateBundle(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/windows-updates/:updateKey/rollback', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const updateKey = clean(c.req.param('updateKey'))
    const body = await c.req.json().catch(() => ({}))
    const actorLabel = clean(auth.session.name || auth.session.email || 'Technician').slice(0, 255)
    const result = await dispatchWindowsUpdateRollback(auth.session.tenant_id, updateKey, {
      agentDeviceIds: array(body.agentDeviceIds),
      dispatch: body.dispatch !== false,
      userId: auth.session.user_id,
      actorType: 'technician',
      actorLabel,
      pauseReason: clean(body.reason) || 'Paused automatically before rollback',
      agentSocketForDevice,
      sendAgentMessage,
    })
    if (result.error === 'update_not_found') return c.json({ error: 'Windows update release not found.' }, 404)
    if (result.error === 'rollback_not_supported') {
      return c.json({ error: 'Windows does not report rollback support for this release on any managed device.' }, 409)
    }
    await audit(
      auth.session,
      'windows_update.rollback_requested',
      'Requested rollback for Windows Update “' + clean(result.release?.title) + '”',
      clean(body.reason),
      { updateKey, results: result.results },
    )
    return c.json({
      success: true,
      results: result.results,
      windowsUpdates: await windowsUpdateBundle(auth.session.tenant_id),
    }, 202)
  })

  app.post('/api/v1/rmm/patch-policies', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name)
    if (name.length < 2) return c.json({ error: 'Policy name is required.' }, 400)
    const policyType = clean(body.policyType).toLowerCase()
    if (!['os', 'software'].includes(policyType)) return c.json({ error: 'Patch policy type must be OS or software.' }, 400)
    const softwareEnabled = policyType === 'software'
    const windowsEnabled = policyType === 'os'
    const deploymentDelayDays = Math.max(0, Math.min(365, Number(body.deploymentDelayDays) || 0))
    const maintenanceWindow = normalizeMaintenanceWindow(
      softwareEnabled ? object(body.softwareRules).maintenanceWindow : body.maintenanceWindow,
    )
    const windowsRules = windowsEnabled ? normalizeWindowsRules(body.windowsRules, deploymentDelayDays) : {}
    const softwareRules = softwareEnabled ? normalizeSoftwareRules(body.softwareRules, maintenanceWindow) : {}
    const softwareValidation = await validateSoftwareRuleCatalogueIds(auth.session.tenant_id, softwareRules, softwareEnabled)
    if (softwareValidation.error) return c.json({ error: softwareValidation.error }, 400)
    const result = await pool.query(
      `INSERT INTO rmm_patch_policies
        (tenant_id,name,description,software_enabled,windows_enabled,approval_mode,deployment_delay_days,
         maintenance_window,reboot_policy,max_retries,software_rules,windows_rules,created_by_user_id,updated_by_user_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10,$11::jsonb,$12::jsonb,$13,$13)
       RETURNING id`,
      [
        auth.session.tenant_id, name, clean(body.description), softwareEnabled,
        windowsEnabled, validApproval(clean(body.approvalMode)), deploymentDelayDays,
        JSON.stringify(maintenanceWindow), validReboot(clean(body.rebootPolicy)),
        Math.max(0, Math.min(10, Number(body.maxRetries) || 2)),
        JSON.stringify(softwareRules), JSON.stringify(windowsRules),
        auth.session.user_id,
      ],
    )
    await audit(auth.session, 'patch_policy.created', 'Created patch policy “' + name + '”', '', { policyId: result.rows[0].id })
    return c.json({ success: true, id: result.rows[0].id, bundle: await patchBundle(auth.session.tenant_id) }, 201)
  })

  app.put('/api/v1/rmm/patch-policies/:policyId', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const name = clean(body.name)
    if (name.length < 2) return c.json({ error: 'Policy name is required.' }, 400)
    const policyType = clean(body.policyType).toLowerCase()
    if (!['os', 'software'].includes(policyType)) return c.json({ error: 'Patch policy type must be OS or software.' }, 400)
    const existing = await pool.query(
      'SELECT software_enabled,windows_enabled FROM rmm_patch_policies WHERE id=$1 AND tenant_id=$2 AND status<>\'archived\' LIMIT 1',
      [clean(c.req.param('policyId')), auth.session.tenant_id],
    )
    if (!existing.rowCount) return c.json({ error: 'Patch policy not found.' }, 404)
    const existingType = existing.rows[0].windows_enabled === true && existing.rows[0].software_enabled !== true
      ? 'os'
      : existing.rows[0].software_enabled === true && existing.rows[0].windows_enabled !== true
        ? 'software'
        : ''
    if (existingType && existingType !== policyType) return c.json({ error: 'Patch policy type cannot be changed after creation.' }, 409)
    const softwareEnabled = policyType === 'software'
    const windowsEnabled = policyType === 'os'
    const deploymentDelayDays = Math.max(0, Math.min(365, Number(body.deploymentDelayDays) || 0))
    const maintenanceWindow = normalizeMaintenanceWindow(
      softwareEnabled ? object(body.softwareRules).maintenanceWindow : body.maintenanceWindow,
    )
    const windowsRules = windowsEnabled ? normalizeWindowsRules(body.windowsRules, deploymentDelayDays) : {}
    const softwareRules = softwareEnabled ? normalizeSoftwareRules(body.softwareRules, maintenanceWindow) : {}
    const softwareValidation = await validateSoftwareRuleCatalogueIds(auth.session.tenant_id, softwareRules, softwareEnabled)
    if (softwareValidation.error) return c.json({ error: softwareValidation.error }, 400)
    const result = await pool.query(
      `UPDATE rmm_patch_policies SET
         name=$3,description=$4,software_enabled=$5,windows_enabled=$6,approval_mode=$7,
         deployment_delay_days=$8,maintenance_window=$9::jsonb,reboot_policy=$10,max_retries=$11,
         software_rules=$12::jsonb,windows_rules=$13::jsonb,updated_by_user_id=$14,updated_at=now()
       WHERE id=$1 AND tenant_id=$2 AND status<>'archived'
       RETURNING id,name`,
      [
        clean(c.req.param('policyId')), auth.session.tenant_id, name, clean(body.description),
        softwareEnabled, windowsEnabled, validApproval(clean(body.approvalMode)),
        deploymentDelayDays, JSON.stringify(maintenanceWindow), validReboot(clean(body.rebootPolicy)),
        Math.max(0, Math.min(10, Number(body.maxRetries) || 2)),
        JSON.stringify(softwareRules), JSON.stringify(windowsRules), auth.session.user_id,
      ],
    )
    if (!result.rowCount) return c.json({ error: 'Patch policy not found.' }, 404)
    await audit(auth.session, 'patch_policy.updated', 'Updated patch policy “' + name + '”', '', { policyId: result.rows[0].id })
    return c.json({ success: true, id: result.rows[0].id, bundle: await patchBundle(auth.session.tenant_id) })
  })

  app.post('/api/v1/rmm/patch-assignments/preview', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const preview = await patchAssignmentImpactPreview(auth.session.tenant_id, body)
    if (preview?.error) return c.json({ error: preview.error }, preview.status || 400)
    return c.json(preview)
  })

  app.post('/api/v1/rmm/patch-assignments', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const body = await c.req.json().catch(() => ({}))
    const scopeType = clean(body.scopeType)
    if (!['Estate', 'Site', 'Group', 'Device'].includes(scopeType)) return c.json({ error: 'Invalid patch scope.' }, 400)
    const scopeId = clean(body.scopeId || (scopeType === 'Estate' ? 'ALL' : ''))
    if (!scopeId) return c.json({ error: 'Patch scope target is required.' }, 400)
    const result = await pool.query(
      `INSERT INTO rmm_patch_assignments
        (tenant_id,policy_id,scope_type,scope_id,scope_name,priority,enabled,created_by_user_id)
       SELECT $1,p.id,$3,$4,$5,$6,true,$7
         FROM rmm_patch_policies p
        WHERE p.id=$2 AND p.tenant_id=$1 AND p.status='active'
       ON CONFLICT (tenant_id,policy_id,scope_type,scope_id)
       DO UPDATE SET scope_name=EXCLUDED.scope_name,priority=EXCLUDED.priority,enabled=true,updated_at=now()
       RETURNING id`,
      [
        auth.session.tenant_id, clean(body.policyId), scopeType, scopeId, clean(body.scopeName),
        Number.isFinite(Number(body.priority)) ? Number(body.priority) : priorityForScope(scopeType),
        auth.session.user_id,
      ],
    )
    if (!result.rowCount) return c.json({ error: 'Patch policy not found.' }, 404)
    await audit(auth.session, 'patch_assignment.updated', 'Assigned patch policy to ' + (clean(body.scopeName) || scopeType), scopeType, { assignmentId: result.rows[0].id, policyId: clean(body.policyId), scopeId })
    return c.json({ success: true, id: result.rows[0].id, bundle: await patchBundle(auth.session.tenant_id) }, 201)
  })

  app.delete('/api/v1/rmm/patch-assignments/:assignmentId', async (c) => {
    const auth = await requirePatchAccess(c, 'policy')
    if (auth.error) return auth.error
    const result = await pool.query(
      'DELETE FROM rmm_patch_assignments WHERE id=$1 AND tenant_id=$2 RETURNING id,scope_name',
      [clean(c.req.param('assignmentId')), auth.session.tenant_id],
    )
    if (!result.rowCount) return c.json({ error: 'Patch assignment not found.' }, 404)
    await audit(auth.session, 'patch_assignment.deleted', 'Removed patch assignment from ' + (result.rows[0].scope_name || 'scope'), '', { assignmentId: result.rows[0].id })
    return c.json({ success: true, bundle: await patchBundle(auth.session.tenant_id) })
  })
}
