import { pool, withTransaction } from './db.js'
import { agentSocketForDevice, sendAgentMessage } from './rmmAgent.js'
import { verificationVersionForRelease } from './rmmSoftwareVersioning.js'
import { COMMON_WINDOWS_SOFTWARE_LOWER } from './rmmCommonSoftware.js'

export const QUALIFICATION_TIMING_LIMITS = Object.freeze({
  installRuntimeSeconds: 600,
  inventoryGraceSeconds: 600,
  uninstallRuntimeSeconds: 480,
  residueCleanupSeconds: 180,
})

function clean(value = '') { return String(value ?? '').trim() }

function qualificationStageEnabled(stage) {
  const key = `RMM_QUALIFICATION_${clean(stage).toUpperCase()}_ENABLED`
  return !['0', 'false', 'off', 'no']
    .includes(clean(process.env[key] ?? 'true').toLowerCase())
}
function lower(value = '') { return clean(value).toLowerCase() }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function array(value) { return Array.isArray(value) ? value : [] }
function normalizedResponseFile(value) {
  const response = object(value)
  const fileName = clean(response.fileName)
  const content = typeof response.content === 'string' ? response.content : ''
  return fileName || content ? { fileName, content } : null
}

function runnerSupportsResponseFiles(runner) {
  const vendorDirect = object(object(runner?.patch_capabilities).vendorDirect)
  return vendorDirect.jobScopedResponseFiles === true
    && vendorDirect.responseFileTargetVersionToken === true
}

function runnerSupportsOfficeClickToRun(runner) {
  return object(object(runner?.patch_capabilities).vendorDirect).officeClickToRun === true
}

function runnerSupportsOfficeClickToRunUninstall(runner) {
  return object(object(runner?.patch_capabilities).vendorDirect).officeClickToRunUninstall === true
}

function runnerSupportsWingetExactVersion(runner) {
  const winget = object(object(runner?.patch_capabilities).winget)
  return winget.exactVersionInstall === true
    && winget.exactVersionUpgrade === true
}

function wingetPackageIdForRelease(release) {
  const sourceMetadata = object(release?.source_metadata)
  const releasePayload = object(release?.release_source_payload)
  const wingetManifest = object(releasePayload.wingetManifest)
  return clean(
    release?.binding_winget_package_id
      || sourceMetadata.wingetPackageId
      || wingetManifest.packageId,
  )
}

function qualificationTransport(release) {
  const sourceMetadata = object(release?.source_metadata)
  const mode = clean(sourceMetadata.deploymentMode)
  const trustState = clean(sourceMetadata.trustState || release?.trust_state)
  const wingetPackageId = wingetPackageIdForRelease(release)
  if (mode === 'winget_preferred'
    && ['winget_ready','direct_ready'].includes(trustState)
    && wingetPackageId) {
    return { provider: 'winget', packageId: wingetPackageId }
  }
  return { provider: 'vendor_direct', packageId: clean(release?.provider_package_id) }
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
function softwareItems(sourcePayload) {
  return array(object(object(sourcePayload).software).items)
    .filter((item) => clean(item?.name))
}

function softwareIdentityKey(item) {
  return [
    lower(item?.registry_key),
    lower(item?.scope),
    lower(item?.user_profile),
    lower(item?.name),
    lower(item?.version),
    lower(item?.publisher),
  ].join('|')
}

function observedQualificationIdentities(catalogue) {
  const learned = array(object(catalogue?.source_metadata).qualificationObservedIdentities)
    .map((item) => object(item))
    .filter((item) => clean(item.name))
  const expanded = []
  for (const identity of learned) {
    expanded.push(identity)
    if (lower(identity.source) !== 'verified_vendor_qualification') continue
    const name = clean(identity.name)
    const learnedVersion = clean(identity.learnedVersion)
    if (!name || !learnedVersion) continue
    const nameLower = lower(name)
    const versionLower = lower(learnedVersion)
    const index = nameLower.indexOf(versionLower)
    if (index < 0) continue
    const before = index > 0 ? name[index - 1] : ''
    const afterIndex = index + learnedVersion.length
    const after = afterIndex < name.length ? name[afterIndex] : ''
    if ((before && /[a-z0-9]/i.test(before)) || (after && /[a-z0-9]/i.test(after))) continue
    const alias = clean((name.slice(0, index) + ' ' + name.slice(afterIndex))
      .replace(/\s+/g, ' ')
      .replace(/^[\s._-]+|[\s._-]+$/g, ''))
    if (alias.length < 3 || !/[a-z]/i.test(alias) || lower(alias) === nameLower) continue
    expanded.push({
      ...identity,
      name: alias,
      derivedFromVersionedName: true,
    })
  }
  return expanded
}

function qualificationScope(value = '') {
  const scope = lower(value)
  if (scope.startsWith('machine')) return 'machine'
  if (scope === 'user') return 'user'
  return scope
}

function installedMatches(sourcePayload, catalogue) {
  const identities = [
    {
      name: clean(catalogue?.name_pattern),
      publisher: clean(catalogue?.publisher_pattern),
      scope: '',
    },
    ...observedQualificationIdentities(catalogue),
  ]
  return softwareItems(sourcePayload).filter((item) => identities.some((identity) => {
    const scope = qualificationScope(identity.scope)
    return identityPhraseMatches(item?.name, identity.name)
      && identityPhraseMatches(item?.publisher, identity.publisher)
      && (!scope || qualificationScope(item?.scope) === scope)
  }))
}

function verifiedPatchResult(value) {
  const result = object(value)
  return result.success !== false
    && result.fallbackUsed !== true
    && (!clean(result.provider) || lower(result.provider) === 'vendor_direct')
    && (result.verificationPassed === true || object(result.verification).meetsTarget === true)
}

function qualificationProviderFailure(value) {
  const result = object(value)
  if (result.fallbackUsed === true) return 'qualification_vendor_direct_fallback_used'
  if (clean(result.provider) && lower(result.provider) !== 'vendor_direct') return 'qualification_non_vendor_provider_used'
  return ''
}

function terminalJobFailure(job) {
  if (!job) return ''
  if (!['failed', 'cancelled'].includes(clean(job.status))) return ''
  return clean(job.error_message || object(job.result).error || job.status)
}

function windowsInstallerBusy(job) {
  const result = object(job?.result)
  if (Number(result.exitCode) === 1618) return true
  return array(result.installAttempts).some((attempt) => Number(object(attempt).exitCode) === 1618)
}

async function requeueWindowsInstallerBusy(queue, stage = 'install') {
  const attempts = Math.max(1, Number(queue?.attempt_count) || 1)
  if (attempts >= 3) return false
  const retrySeconds = Math.min(180, 60 * attempts)
  const retryNotBefore = new Date(Date.now() + retrySeconds * 1000).toISOString()
  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET state='queued',
            runner_agent_device_id=NULL,
            agent_job_id=NULL,
            deployment_id=NULL,
            cleanup_job_id=NULL,
            last_error='qualification_windows_installer_busy',
            evidence=evidence || $2::jsonb,
            started_at=NULL,
            completed_at=NULL,
            updated_at=now()
      WHERE id=$1`,
    [queue.id, JSON.stringify({
      stage: clean(stage),
      transientInstallerBusy: true,
      retryNotBefore,
      retryDelaySeconds: retrySeconds,
      windowsInstallerExitCode: 1618,
    })],
  )
  return true
}

async function liveQualificationRunner() {
  const result = await pool.query(
    `SELECT q.agent_device_id,q.dispatch_enabled,q.pause_reason,q.paused_at,
            a.tenant_id,a.inventory_id,a.agent_version,a.patch_capabilities,
            a.websocket_status,a.last_telemetry_at,a.last_inventory_at,i.name AS device_name,i.reference AS device_reference,
            i.source_payload
       FROM rmm_software_vendor_qualification_runners q
       JOIN rmm_agent_devices a ON a.id=q.agent_device_id AND a.disabled_at IS NULL
       JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true
      WHERE q.enabled=true
        AND a.websocket_status='Connected'
        AND a.last_telemetry_at>now()-interval '90 seconds'
        AND COALESCE((a.patch_capabilities->>'softwareInstall')::boolean,false)=true
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'artifactStorage'),'')='job_scoped'
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'jobDirectoryPurgedOnExit')::boolean,false)=true
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'winInetCacheUsed')::boolean,true)=false
      ORDER BY a.last_telemetry_at DESC
      LIMIT 1`,
  )
  return result.rows[0] || null
}

export async function qualificationRunnerContaminantsForAdmin(agentDeviceId) {
  const runner = await liveQualificationRunner()
  if (!runner || clean(runner.agent_device_id) !== clean(agentDeviceId)) return []
  const result = await pool.query(
    `SELECT q.id,q.catalogue_id,q.state,q.test_type,q.evidence,
            c.canonical_name,c.name_pattern,c.publisher_pattern,c.source_metadata
       FROM rmm_software_qualification_queue q
       JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
      WHERE q.runner_agent_device_id=$1
        AND q.evidence ? 'installCompletedAt'
        AND q.state IN ('running','cleanup_pending','cleanup_running','review_required')
      ORDER BY q.updated_at DESC
      LIMIT 100`,
    [runner.agent_device_id],
  )
  return result.rows.flatMap((row) => {
    const matches = installedMatches(runner.source_payload, row)
    if (!matches.length) return []
    return [{
      queueId: row.id,
      catalogueId: row.catalogue_id,
      state: row.state,
      testType: row.test_type,
      canonicalName: clean(row.canonical_name),
      installed: matches.map((item) => ({
        name: clean(item?.name),
        publisher: clean(item?.publisher),
        version: clean(item?.version),
        registryKey: clean(item?.registry_key),
        scope: clean(item?.scope),
      })),
    }]
  })
}

async function qualificationRunnerContaminants(runner, excludeQueueId = '') {
  if (!runner?.agent_device_id) return []
  const result = await pool.query(
    `SELECT q.id,c.canonical_name,c.name_pattern,c.publisher_pattern,c.source_metadata
       FROM rmm_software_qualification_queue q
       JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
      WHERE q.runner_agent_device_id=$1
        AND q.id<>COALESCE(NULLIF($2,'')::uuid,'00000000-0000-0000-0000-000000000000'::uuid)
        AND q.evidence ? 'installCompletedAt'
        AND q.state IN ('running','cleanup_pending','cleanup_running','review_required')
      ORDER BY q.updated_at DESC
      LIMIT 50`,
    [runner.agent_device_id, clean(excludeQueueId)],
  )
  return result.rows
    .filter((row) => installedMatches(runner.source_payload, row).length)
    .map((row) => clean(row.canonical_name))
    .filter(Boolean)
}

async function markReview(queueId, error, evidence = {}) {
  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET state='review_required',last_error=$2,
            evidence=evidence || $3::jsonb,completed_at=now(),updated_at=now()
      WHERE id=$1`,
    [queueId, clean(error).slice(0, 1000), JSON.stringify({ ...evidence, reviewRequiredAt: new Date().toISOString() })],
  )
}

async function classifyRotatedHistoricalArtifact(queue, job, stage) {
  if (clean(stage) !== 'upgrade_baseline_running') return { classified: false }
  const result = object(job?.result)
  const failure = clean(result.error || job?.error_message)
  const actualSha256 = lower(result.actualSha256)
  const evidence = object(queue?.evidence)
  const baselineReleaseId = clean(evidence.vendorReleaseId)
  if (failure !== 'sha256_mismatch' || !actualSha256 || !baselineReleaseId) return { classified: false }

  const releaseResult = await pool.query(
    `SELECT b.id AS baseline_id,b.version AS baseline_version,b.source_key,b.provider_package_id,
            b.channel,b.platform,b.architecture,b.installer_url AS baseline_url,
            b.installer_sha256 AS baseline_sha256,c.target_version,
            t.id AS target_id,t.installer_url AS target_url,t.installer_sha256 AS target_sha256
       FROM rmm_software_vendor_releases b
       JOIN rmm_software_catalogue c ON c.id=$1
       JOIN rmm_software_vendor_releases t
         ON t.source_key=b.source_key
        AND t.provider_package_id=b.provider_package_id
        AND t.channel=b.channel
        AND t.platform=b.platform
        AND t.architecture=b.architecture
        AND t.version=c.target_version
        AND t.trust_state='direct_ready'
      WHERE b.id=$2
        AND b.version<>c.target_version
      LIMIT 1`,
    [queue.catalogue_id, baselineReleaseId],
  )
  const release = releaseResult.rows[0]
  if (!release) return { classified: false }

  const baselineUrl = clean(release.baseline_url)
  const targetUrl = clean(release.target_url)
  const baselineSha256 = lower(release.baseline_sha256)
  const targetSha256 = lower(release.target_sha256)
  if (!baselineUrl || baselineUrl !== targetUrl
    || !baselineSha256 || !targetSha256
    || baselineSha256 === targetSha256
    || actualSha256 !== targetSha256) {
    return { classified: false }
  }

  const rejected = await pool.query(
    `UPDATE rmm_software_vendor_releases
        SET trust_state='rejected',
            trust_evidence=COALESCE(trust_evidence,'{}'::jsonb) || $7::jsonb,
            source_payload=COALESCE(source_payload,'{}'::jsonb) || $8::jsonb
      WHERE source_key=$1
        AND provider_package_id=$2
        AND channel=$3
        AND platform=$4
        AND architecture=$5
        AND installer_url=$6
        AND id<>$9
        AND trust_state='direct_ready'
        AND lower(COALESCE(installer_sha256,''))<>$10
      RETURNING id,version`,
    [
      release.source_key,
      release.provider_package_id,
      release.channel,
      release.platform,
      release.architecture,
      baselineUrl,
      JSON.stringify({
        reason: 'sha256_mismatch',
        historicalMutableUrl: true,
        historicalMutableUrlDetectedAt: new Date().toISOString(),
        historicalMutableUrlCurrentSha256: targetSha256.toUpperCase(),
      }),
      JSON.stringify({
        historicalArtifactUnavailable: true,
        historicalArtifactUnavailableReason: 'mutable_vendor_url_rotated_to_current_release',
        historicalArtifactUnavailableAt: new Date().toISOString(),
      }),
      release.target_id,
      targetSha256,
    ],
  )

  await pool.query(
    `UPDATE rmm_software_vendor_sources
        SET metadata=(metadata - 'baselinePreparationError') || $2::jsonb,updated_at=now()
      WHERE source_key=$1`,
    [release.source_key, JSON.stringify({
      baselinePreparationState: 'previous_stable_installer_unavailable',
      baselinePreparationTargetVersion: clean(release.target_version),
      baselinePreparationPreviousVersion: clean(release.baseline_version),
      baselinePreparationReason: 'mutable_vendor_url_rotated_to_current_release',
      baselinePreparationCompletedAt: new Date().toISOString(),
      baselinePreparationRequestedForCatalogueId: queue.catalogue_id,
      baselinePreparationEvidence: {
        installerUrl: baselineUrl,
        historicalExpectedSha256: baselineSha256.toUpperCase(),
        observedSha256: actualSha256.toUpperCase(),
        currentTrustedSha256: targetSha256.toUpperCase(),
        rejectedHistoricalReleaseIds: rejected.rows.map((row) => row.id),
      },
    })],
  )

  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET state='cancelled',last_error='previous_stable_installer_unavailable',
            evidence=evidence || $2::jsonb,completed_at=now(),updated_at=now()
      WHERE id=$1`,
    [queue.id, JSON.stringify({
      stage: 'upgrade_unavailable',
      upgradeUnavailable: true,
      upgradeUnavailableReason: 'historical_installer_mutable_url_rotated',
      historicalInstallerUrl: baselineUrl,
      historicalExpectedSha256: baselineSha256.toUpperCase(),
      observedSha256: actualSha256.toUpperCase(),
      currentTrustedSha256: targetSha256.toUpperCase(),
      rejectedHistoricalReleases: rejected.rows.map((row) => ({
        id: row.id,
        version: clean(row.version),
      })),
      unavailableAt: new Date().toISOString(),
    })],
  )

  return {
    classified: true,
    reason: 'previous_stable_installer_unavailable',
    baselineVersion: clean(release.baseline_version),
    targetVersion: clean(release.target_version),
    rejectedHistoricalReleases: rejected.rows,
  }
}

async function qualificationRow(queueId) {
  const result = await pool.query(
    `SELECT q.*,c.canonical_name,c.publisher,c.name_pattern,c.publisher_pattern,c.provider,
            c.provider_package_id,c.target_version,c.installer_type,c.execution,c.verification,
            c.source_metadata,c.qualification_state,c.status AS catalogue_status,
            a.inventory_id AS runner_inventory_id,i.source_payload AS runner_source_payload
       FROM rmm_software_qualification_queue q
       JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
       LEFT JOIN rmm_agent_devices a ON a.id=q.runner_agent_device_id
       LEFT JOIN rmm_device_inventory i ON i.id=a.inventory_id
      WHERE q.id=$1 LIMIT 1`,
    [queueId],
  )
  return result.rows[0] || null
}

function versionIdentity(value = '') {
  return lower(value).replace(/^v(?=\d)/, '')
}

function verificationObservedName(result = {}) {
  const verification = object(result.verification)
  const packageId = clean(verification.packageId || result.packageId)
  const output = clean(verification.output)
  if (!packageId || !output) return ''
  const packageNeedle = lower(packageId)
  const versionNeedle = versionIdentity(result.verifiedVersion || verification.installedVersion)
  for (const line of output.split(/\r?\n/)) {
    const lowered = lower(line)
    const index = lowered.indexOf(packageNeedle)
    if (index <= 0) continue
    if (versionNeedle && !lowered.includes(versionNeedle)) continue
    return clean(line.slice(0, index))
  }
  return ''
}

function observedNameIsPlausible(itemName, catalogue, result) {
  const observed = verificationObservedName(result)
  if (observed) {
    return identityPhraseMatches(itemName, observed)
      || identityPhraseMatches(observed, itemName)
  }
  return identityPhraseMatches(itemName, catalogue.name_pattern)
    || identityPhraseMatches(catalogue.name_pattern, itemName)
}

async function learnVerifiedObservedIdentity(queue, runner) {
  const evidence = object(queue.evidence)
  const beforeKeys = new Set(array(evidence.preInstallInventoryKeys).map(clean).filter(Boolean))
  if (!beforeKeys.size || !queue.agent_job_id) return { learned: false, reason: 'preinstall_inventory_missing' }

  const jobResult = await pool.query(
    `SELECT status,result,error_message,completed_at FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
    [queue.agent_job_id],
  )
  const job = jobResult.rows[0]
  const result = object(job?.result)
  const verification = object(result.verification)
  if (!job
    || clean(job.status) !== 'completed'
    || !verifiedPatchResult(result)
    || result.sha256Verified !== true
    || result.signatureVerified !== true
    || verification.meetsTarget !== true) {
    return { learned: false, reason: 'strict_verification_not_satisfied' }
  }

  const sourceMetadata = object(queue.source_metadata)
  const expectedPackageId = clean(object(queue.verification).packageId || sourceMetadata.wingetPackageId)
  if (!expectedPackageId || lower(result.packageId) !== lower(expectedPackageId)) {
    return { learned: false, reason: expectedPackageId ? 'package_identity_mismatch' : 'package_identity_missing' }
  }
  const expectedSigner = clean(sourceMetadata.expectedSigner || sourceMetadata.signerBaseline)
  if (!expectedSigner || !clean(result.signer)) {
    return { learned: false, reason: 'signer_identity_missing' }
  }

  const verifiedVersion = clean(result.verifiedVersion || verification.installedVersion || evidence.verifiedVersion || queue.target_version)
  if (!verifiedVersion) return { learned: false, reason: 'verified_version_missing' }

  const candidates = softwareItems(runner.source_payload)
    .filter((item) => !beforeKeys.has(softwareIdentityKey(item)))
    .filter((item) => versionIdentity(item?.version) === versionIdentity(verifiedVersion))
    .filter((item) => observedNameIsPlausible(item?.name, queue, result))

  if (candidates.length !== 1) {
    return {
      learned: false,
      reason: candidates.length ? 'observed_identity_ambiguous' : 'observed_identity_not_visible',
      candidates: candidates.map((item) => ({
        name: clean(item?.name),
        publisher: clean(item?.publisher),
        version: clean(item?.version),
        scope: clean(item?.scope),
      })),
    }
  }

  const item = candidates[0]
  const scope = qualificationScope(item?.scope)
  const userProfile = lower(item?.user_profile)
  if (scope === 'user' || userProfile.includes('systemprofile')) {
    return { learned: false, scopeMismatch: true, item }
  }

  const identity = {
    name: clean(item?.name),
    publisher: clean(item?.publisher),
    scope,
    registryKey: clean(item?.registry_key),
    learnedVersion: verifiedVersion,
    learnedAt: new Date().toISOString(),
    packageId: clean(result.packageId),
    signer: clean(result.signer),
    source: 'verified_vendor_qualification',
  }
  if (!identity.name || !identity.publisher) return { learned: false, reason: 'observed_identity_incomplete' }

  const existing = observedQualificationIdentities(queue)
  const key = `${lower(identity.name)}|${lower(identity.publisher)}|${lower(identity.scope)}`
  const merged = [
    ...existing.filter((entry) => `${lower(entry.name)}|${lower(entry.publisher)}|${lower(entry.scope)}` !== key),
    identity,
  ].slice(-12)
  const metadataPatch = {
    qualificationObservedIdentities: merged,
    qualificationObservedIdentityUpdatedAt: identity.learnedAt,
  }

  await withTransaction(async (client) => {
    await client.query(
      `UPDATE rmm_software_catalogue
          SET source_metadata=source_metadata || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [queue.catalogue_id, JSON.stringify(metadataPatch)],
    )
    await client.query(
      `UPDATE rmm_software_vendor_bindings b
          SET metadata=metadata || $2::jsonb
         FROM rmm_software_catalogue c
        WHERE c.id=$1
          AND b.provider_package_id=c.external_key
          AND b.source_key=c.source_metadata->>'latestSource'
          AND b.enabled=true`,
      [queue.catalogue_id, JSON.stringify(metadataPatch)],
    )
    await client.query(
      `UPDATE rmm_software_qualification_queue
          SET evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [queue.id, JSON.stringify({
        observedIdentityLearned: identity,
        observedIdentityLearnedAt: identity.learnedAt,
      })],
    )
  })
  return { learned: true, identity }
}

async function qualificationUninstallJobSpec(queue, item) {
  const genericPayload = {
    name: clean(item?.name),
    registry_key: clean(item?.registry_key),
    scope: clean(item?.scope),
    user_profile: clean(item?.user_profile),
  }

  const result = await pool.query(
    `SELECT c.canonical_name,c.publisher,c.target_version,c.provider_package_id,c.verification,c.source_metadata,
            r.id AS vendor_release_id,r.source_key,r.installer_url,r.installer_sha256,r.installer_type,r.source_payload,
            COALESCE(NULLIF(b.metadata->>'expectedSigner',''),NULLIF(r.source_payload->>'expectedSigner',''),NULLIF(c.source_metadata->>'expectedSigner',''),'') AS expected_signer,
            COALESCE(NULLIF(b.metadata->>'installerTechnology',''),NULLIF(r.source_payload->>'installerTechnology',''),NULLIF(c.source_metadata->>'installerTechnology',''),'') AS installer_technology
       FROM rmm_software_catalogue c
       JOIN rmm_software_vendor_releases r
         ON r.provider_package_id=c.external_key
        AND r.version=c.target_version
        AND r.trust_state='direct_ready'
       LEFT JOIN rmm_software_vendor_bindings b
         ON b.source_key=r.source_key
        AND b.provider_package_id=r.provider_package_id
        AND b.channel=r.channel
        AND b.platform=r.platform
        AND b.architecture=r.architecture
        AND b.enabled=true
      WHERE c.id=$1
        AND c.tenant_id IS NULL
        AND c.status='active'
      ORDER BY r.last_seen_at DESC
      LIMIT 1`,
    [queue.catalogue_id],
  )
  const row = result.rows[0]
  if (!row || lower(row.installer_technology) !== 'office_odt_sfx') {
    return { jobType: 'software.uninstall', payload: genericPayload, officeOdt: false }
  }

  const verification = object(row.verification)
  const sourcePayload = object(row.source_payload)
  const sourceVerification = object(sourcePayload.verification)
  const productId = clean(verification.productId || sourceVerification.productId)
  if (!productId) {
    return { error: 'qualification_office_c2r_product_id_missing', officeOdt: true }
  }

  const installedVersion = clean(item?.version || row.target_version)
  const responseFile = {
    fileName: 'microsoft-365-remove.xml',
    content: [
      '<Configuration>',
      '  <Remove All="FALSE">',
      `    <Product ID="${productId}" />`,
      '  </Remove>',
      '  <Display Level="None" AcceptEULA="TRUE" />',
      '</Configuration>',
      '',
    ].join('\n'),
  }

  return {
    jobType: 'patch.software',
    officeOdt: true,
    vendorReleaseId: row.vendor_release_id,
    payload: {
      protocolVersion: 1,
      action: 'software.install',
      intent: 'uninstall',
      catalogueId: queue.catalogue_id,
      applicationName: clean(row.canonical_name),
      publisher: clean(row.publisher),
      packageId: clean(row.provider_package_id),
      installedVersion,
      targetVersion: installedVersion || clean(row.target_version),
      provider: 'vendor_direct',
      vendorSource: clean(row.source_key),
      downloadUrl: clean(row.installer_url),
      sha256: clean(row.installer_sha256).toUpperCase(),
      installerType: lower(row.installer_type),
      installerTechnology: 'office_odt_sfx',
      installArguments: '/configure {HI5_RESPONSE_FILE}',
      responseFile,
      expectedSigner: clean(row.expected_signer),
      fallbackProvider: '',
      verification: {
        ...verification,
        ...sourceVerification,
        method: 'office_c2r_registry',
        productId,
        targetVersion: installedVersion || clean(row.target_version),
        expectAbsent: true,
      },
    },
  }
}

async function dispatchUninstall(queue, runner, item) {
  const liveSocket = agentSocketForDevice(runner.agent_device_id)
  const canPush = Boolean(liveSocket && liveSocket.readyState === 1)

  const uninstallSpec = await qualificationUninstallJobSpec(queue, item)
  if (uninstallSpec.error) {
    await markReview(queue.id, uninstallSpec.error)
    return { dispatched: false }
  }
  if (uninstallSpec.officeOdt && !runnerSupportsOfficeClickToRunUninstall(runner)) {
    await markReview(queue.id, 'qualification_office_c2r_uninstall_capability_required', {
      requiredPatchHostVersion: '0.2.19',
      currentPatchHostVersion: clean(object(runner.patch_capabilities).patchHostVersion || object(runner.patch_capabilities).version),
    })
    return { dispatched: false, blocked: true }
  }
  const payload = uninstallSpec.payload
  const jobType = uninstallSpec.jobType
  if (jobType === 'software.uninstall' && !payload.name && !payload.registry_key) {
    await markReview(queue.id, 'qualification_uninstall_identity_missing')
    return { dispatched: false }
  }

  const inserted = await pool.query(
    `INSERT INTO rmm_agent_jobs
      (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
     VALUES ($1,$2,$3,$4::jsonb,'system','Catalogue qualification',$5::jsonb)
     RETURNING id,status,created_at`,
    [
      runner.tenant_id,
      runner.agent_device_id,
      jobType,
      JSON.stringify(payload),
      JSON.stringify({
        source: 'catalogue_qualification_cleanup',
        qualification_queue_id: queue.id,
        catalogue_id: queue.catalogue_id,
        ...(uninstallSpec.officeOdt ? { uninstall_transport: 'office_odt', vendor_release_id: uninstallSpec.vendorReleaseId } : {}),
      }),
    ],
  )
  const job = inserted.rows[0]
  let delivery = 'queued_agent_channel'

  if (canPush) {
    const claimed = await pool.query(
      `UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now()
        WHERE id=$1 AND status='queued' RETURNING id`,
      [job.id],
    )
    if (claimed.rowCount) {
      const pushed = sendAgentMessage(runner.agent_device_id, {
        type: 'job_execute',
        job: { id: job.id, job_type: jobType, payload, created_at: job.created_at },
      })
      if (pushed) {
        delivery = 'websocket'
      } else {
        await pool.query(
          `UPDATE rmm_agent_jobs
              SET status='queued',claimed_at=NULL,error_message='',updated_at=now()
            WHERE id=$1 AND status='claimed'`,
          [job.id],
        )
      }
    }
  }

  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET state='cleanup_running',cleanup_job_id=$2,last_error='',
            evidence=evidence || $3::jsonb,updated_at=now()
      WHERE id=$1`,
    [queue.id, job.id, JSON.stringify({
      cleanupDispatchedAt: new Date().toISOString(),
      cleanupDelivery: delivery,
      uninstallName: clean(item?.name),
      uninstallRegistryKey: clean(item?.registry_key),
      uninstallTransport: uninstallSpec.officeOdt ? 'office_odt' : 'native',
      installedDisplayName: clean(item?.name),
      installedPublisher: clean(item?.publisher),
      installLocation: clean(item?.install_location),
      installedScope: clean(item?.scope),
      installedUserProfile: clean(item?.user_profile),
      uninstallString: clean(item?.uninstall_string),
      quietUninstallString: clean(item?.quiet_uninstall_string),
    })],
  )
  return { dispatched: true, queued: delivery !== 'websocket', jobId: job.id }
}


async function dispatchPrecleanUninstall(queue, runner, item) {
  const liveSocket = agentSocketForDevice(runner.agent_device_id)
  const canPush = Boolean(liveSocket && liveSocket.readyState === 1)
  const uninstallSpec = await qualificationUninstallJobSpec(queue, item)
  if (uninstallSpec.error) {
    await markReview(queue.id, uninstallSpec.error, { stage: 'preclean' })
    return { dispatched: false }
  }
  if (uninstallSpec.officeOdt && !runnerSupportsOfficeClickToRunUninstall(runner)) {
    await markReview(queue.id, 'qualification_office_c2r_uninstall_capability_required', {
      stage: 'preclean',
      requiredPatchHostVersion: '0.2.19',
      currentPatchHostVersion: clean(object(runner.patch_capabilities).patchHostVersion || object(runner.patch_capabilities).version),
    })
    return { dispatched: false, blocked: true }
  }
  const payload = uninstallSpec.payload
  const jobType = uninstallSpec.jobType
  if (jobType === 'software.uninstall' && !payload.name && !payload.registry_key) {
    await markReview(queue.id, 'qualification_preclean_identity_missing', { stage: 'preclean' })
    return { dispatched: false }
  }

  const inserted = await pool.query(
    `INSERT INTO rmm_agent_jobs
      (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
     VALUES ($1,$2,$3,$4::jsonb,'system','Catalogue qualification pre-clean',$5::jsonb)
     RETURNING id,status,created_at`,
    [
      runner.tenant_id,
      runner.agent_device_id,
      jobType,
      JSON.stringify(payload),
      JSON.stringify({
        source: 'catalogue_qualification_preclean',
        qualification_queue_id: queue.id,
        catalogue_id: queue.catalogue_id,
        ...(uninstallSpec.officeOdt ? { uninstall_transport: 'office_odt', vendor_release_id: uninstallSpec.vendorReleaseId } : {}),
      }),
    ],
  )
  const job = inserted.rows[0]
  let delivery = 'queued_agent_channel'

  if (canPush) {
    const claimed = await pool.query(
      `UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now()
        WHERE id=$1 AND status='queued' RETURNING id`,
      [job.id],
    )
    if (claimed.rowCount) {
      const pushed = sendAgentMessage(runner.agent_device_id, {
        type: 'job_execute',
        job: { id: job.id, job_type: jobType, payload, created_at: job.created_at },
      })
      if (pushed) {
        delivery = 'websocket'
      } else {
        await pool.query(
          `UPDATE rmm_agent_jobs
              SET status='queued',claimed_at=NULL,error_message='',updated_at=now()
            WHERE id=$1 AND status='claimed'`,
          [job.id],
        )
      }
    }
  }

  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET state='cleanup_running',runner_agent_device_id=$2,cleanup_job_id=$3,last_error='',
            started_at=COALESCE(started_at,now()),completed_at=NULL,
            evidence=evidence || $4::jsonb,updated_at=now()
      WHERE id=$1`,
    [queue.id, runner.agent_device_id, job.id, JSON.stringify({
      stage: 'preclean_running',
      cleanupPhase: 'preclean',
      precleanDispatchedAt: new Date().toISOString(),
      precleanDelivery: delivery,
      precleanName: clean(item?.name),
      precleanRegistryKey: clean(item?.registry_key),
      precleanTransport: uninstallSpec.officeOdt ? 'office_odt' : 'native',
      precleanVersion: clean(item?.version),
      precleanScope: clean(item?.scope),
    })],
  )
  return { dispatched: true, queued: delivery !== 'websocket', jobId: job.id }
}

async function dispatchRollbackUninstall(queue, runner, item, stage) {
  const liveSocket = agentSocketForDevice(runner.agent_device_id)
  const canPush = Boolean(liveSocket && liveSocket.readyState === 1)
  const uninstallSpec = await qualificationUninstallJobSpec(queue, item)
  if (uninstallSpec.error) {
    await markReview(queue.id, uninstallSpec.error, { stage })
    return { dispatched: false }
  }
  if (uninstallSpec.officeOdt && !runnerSupportsOfficeClickToRunUninstall(runner)) {
    await markReview(queue.id, 'qualification_office_c2r_uninstall_capability_required', {
      stage,
      requiredPatchHostVersion: '0.2.19',
      currentPatchHostVersion: clean(object(runner.patch_capabilities).patchHostVersion || object(runner.patch_capabilities).version),
    })
    return { dispatched: false, blocked: true }
  }
  const payload = uninstallSpec.payload
  const jobType = uninstallSpec.jobType
  if (jobType === 'software.uninstall' && !payload.name && !payload.registry_key) {
    await markReview(queue.id, 'qualification_rollback_uninstall_identity_missing', { stage })
    return { dispatched: false }
  }

  const inserted = await pool.query(
    `INSERT INTO rmm_agent_jobs
      (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
     VALUES ($1,$2,$3,$4::jsonb,'system','Catalogue rollback qualification',$5::jsonb)
     RETURNING id,status,created_at`,
    [
      runner.tenant_id,
      runner.agent_device_id,
      jobType,
      JSON.stringify(payload),
      JSON.stringify({
        source: 'catalogue_qualification_rollback',
        qualification_queue_id: queue.id,
        catalogue_id: queue.catalogue_id,
        stage,
        ...(uninstallSpec.officeOdt ? { uninstall_transport: 'office_odt', vendor_release_id: uninstallSpec.vendorReleaseId } : {}),
      }),
    ],
  )
  const job = inserted.rows[0]
  let delivery = 'queued_agent_channel'
  if (canPush) {
    const claimed = await pool.query(
      `UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now()
        WHERE id=$1 AND status='queued' RETURNING id`,
      [job.id],
    )
    if (claimed.rowCount) {
      const pushed = sendAgentMessage(runner.agent_device_id, {
        type: 'job_execute',
        job: { id: job.id, job_type: jobType, payload, created_at: job.created_at },
      })
      if (pushed) {
        delivery = 'websocket'
      } else {
        await pool.query(
          `UPDATE rmm_agent_jobs
              SET status='queued',claimed_at=NULL,error_message='',updated_at=now()
            WHERE id=$1 AND status='claimed'`,
          [job.id],
        )
      }
    }
  }

  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET state='running',agent_job_id=$2,cleanup_job_id=NULL,last_error='',
            evidence=evidence || $3::jsonb,updated_at=now()
      WHERE id=$1`,
    [queue.id, job.id, JSON.stringify({
      stage,
      rollbackUninstallDispatchedAt: new Date().toISOString(),
      rollbackUninstallDelivery: delivery,
      uninstallName: clean(item?.name),
      uninstallRegistryKey: clean(item?.registry_key),
      uninstallTransport: uninstallSpec.officeOdt ? 'office_odt' : 'native',
      installedDisplayName: clean(item?.name),
      installedPublisher: clean(item?.publisher),
      installLocation: clean(item?.install_location),
      installedScope: clean(item?.scope),
      installedUserProfile: clean(item?.user_profile),
      uninstallString: clean(item?.uninstall_string),
      quietUninstallString: clean(item?.quiet_uninstall_string),
    })],
  )
  return { dispatched: true, queued: delivery !== 'websocket', jobId: job.id }
}

function safeQualificationProgramPath(value = '') {
  const path = clean(value).replace(/\//g, '\\').replace(/\\+$/g, '')
  if (/^C:\\Program Files(?: \(x86\))?\\[^\\]+/i.test(path)) return path
  if (/^C:\\Users\\[^\\]+\\AppData\\Local\\Programs\\[^\\]+/i.test(path)) return path
  if (/^C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Programs\\[^\\]+/i.test(path)) return path
  return ''
}

function qualificationInstallPath(evidence = {}) {
  const direct = safeQualificationProgramPath(evidence.installLocation)
  if (direct) return { path: direct, onlyNew: !/^C:\\Program Files/i.test(direct) }
  const uninstall = clean(evidence.quietUninstallString || evidence.uninstallString)
  const quoted = clean(uninstall.match(/^\s*"([^"]+\.exe)"/i)?.[1])
  const bare = quoted || clean(uninstall.match(/^\s*([A-Za-z]:\\.*?\.exe)(?:\s|$)/i)?.[1])
  if (!bare) return { path: '', onlyNew: true }
  const parent = bare.replace(/\\[^\\]+\.exe$/i, '')
  const safe = safeQualificationProgramPath(parent)
  return { path: safe, onlyNew: safe ? !/^C:\\Program Files/i.test(safe) : true }
}

function safeQualificationAlias(value = '') {
  const alias = clean(value)
    .replace(/\s+\((?:32|64)-bit\)$/i, '')
    .replace(/\s+\(x64\)$/i, '')
  if (!alias || alias.length > 100 || /[\\/:*?"<>|]/.test(alias)) return ''
  return alias
}

function psSingleQuoted(value = '') {
  return "'" + clean(value).replace(/'/g, "''") + "'"
}

async function dispatchQualificationResidueCleanup(queue, runner, {
  finalState = 'passed',
  finalError = '',
  uninstallCompletedAt = '',
} = {}) {
  const liveSocket = agentSocketForDevice(runner.agent_device_id)
  const canPush = Boolean(liveSocket && liveSocket.readyState === 1)
  const evidence = object(queue.evidence)
  const installTarget = qualificationInstallPath(evidence)
  const installLocation = installTarget.path
  const aliases = [...new Set([
    safeQualificationAlias(queue.canonical_name),
    safeQualificationAlias(evidence.installedDisplayName),
    safeQualificationAlias(evidence.uninstallName),
  ].filter(Boolean))]
  const startedAtValue = queue.started_at || evidence.dispatchedAt || evidence.installCompletedAt || new Date().toISOString()
  const startedAtDate = startedAtValue instanceof Date ? startedAtValue : new Date(startedAtValue)
  const startedAt = Number.isNaN(startedAtDate.getTime()) ? new Date().toISOString() : startedAtDate.toISOString()
  const patchHostWorkDir = clean(queue.agent_job_id)
    ? `C:\\ProgramData\\Hi5Central\\Agent\\PatchHost\\jobs\\${clean(queue.agent_job_id)}`
    : ''
  const command = [
    "$ErrorActionPreference='SilentlyContinue'",
    `$start=[DateTime]::Parse(${psSingleQuoted(startedAt)}).ToUniversalTime()`,
    '$removed=@();$retained=@()',
    'function Size-Bytes($p){if(!(Test-Path -LiteralPath $p)){return 0};$m=Get-ChildItem -LiteralPath $p -Force -Recurse -File -ErrorAction SilentlyContinue|Measure-Object Length -Sum;return [int64]($m.Sum)}',
    'function Remove-QualificationTree($p,$reason,$onlyNew){if(!$p -or !(Test-Path -LiteralPath $p)){return};$i=Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue;if($onlyNew -and $i -and $i.CreationTimeUtc -lt $start.AddMinutes(-2)){$script:retained+=[pscustomobject]@{Path=$p;Reason="pre_existing";Bytes=(Size-Bytes $p)};return};$b=Size-Bytes $p;Remove-Item -LiteralPath $p -Force -Recurse -ErrorAction SilentlyContinue;if(Test-Path -LiteralPath $p){$script:retained+=[pscustomobject]@{Path=$p;Reason="remove_failed";Bytes=(Size-Bytes $p)}}else{$script:removed+=[pscustomobject]@{Path=$p;Reason=$reason;Bytes=$b}}}',
    '$disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID=\'C:\'"',
    '$before=[int64]$disk.FreeSpace',
    installLocation ? `Remove-QualificationTree ${psSingleQuoted(installLocation)} 'captured_install_location' $${installTarget.onlyNew ? 'true' : 'false'}` : '',
    patchHostWorkDir ? `Remove-QualificationTree ${psSingleQuoted(patchHostWorkDir)} 'patchhost_job_workdir' $false` : '',
    `$aliases=@(${aliases.map(psSingleQuoted).join(',')})`,
    "foreach($u in Get-ChildItem 'C:\\Users' -Directory -ErrorAction SilentlyContinue){foreach($rel in @('AppData\\Local','AppData\\Roaming')){foreach($a in $aliases){$p=Join-Path (Join-Path $u.FullName $rel) $a;Remove-QualificationTree $p 'qualification_created_appdata' $true}}}",
    "foreach($a in $aliases){$p=Join-Path 'C:\\ProgramData' $a;Remove-QualificationTree $p 'qualification_created_programdata' $true}",
    '$after=[int64](Get-CimInstance Win32_LogicalDisk -Filter "DeviceID=\'C:\'").FreeSpace',
    '[pscustomobject]@{BeforeFreeBytes=$before;AfterFreeBytes=$after;ReclaimedMiB=[math]::Round((($after-$before)/1MB),2);InstallLocation=' + psSingleQuoted(installLocation) + ';Removed=$removed;Retained=$retained}|ConvertTo-Json -Depth 6 -Compress',
  ].filter(Boolean).join(';')

  const inserted = await pool.query(
    `INSERT INTO rmm_agent_jobs
      (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
     VALUES ($1,$2,'custom.command',$3::jsonb,'system','Catalogue qualification residue cleanup',$4::jsonb)
     RETURNING id,status,created_at`,
    [
      runner.tenant_id,
      runner.agent_device_id,
      JSON.stringify({ command, timeout_seconds: 180 }),
      JSON.stringify({
        source: 'catalogue_qualification_residue_cleanup',
        qualification_queue_id: queue.id,
        catalogue_id: queue.catalogue_id,
      }),
    ],
  )
  const job = inserted.rows[0]
  let delivery = 'queued_agent_channel'
  if (canPush) {
    const claimed = await pool.query(
      `UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now()
        WHERE id=$1 AND status='queued' RETURNING id`,
      [job.id],
    )
    if (claimed.rowCount) {
      const pushed = sendAgentMessage(runner.agent_device_id, {
        type: 'job_execute',
        job: { id: job.id, job_type: 'custom.command', payload: { command, timeout_seconds: 180 }, created_at: job.created_at },
      })
      if (pushed) delivery = 'websocket'
      else {
        await pool.query(
          `UPDATE rmm_agent_jobs SET status='queued',claimed_at=NULL,error_message='',updated_at=now()
            WHERE id=$1 AND status='claimed'`,
          [job.id],
        )
      }
    }
  }

  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET state='cleanup_running',cleanup_job_id=$2,
            evidence=evidence || $3::jsonb,updated_at=now()
      WHERE id=$1`,
    [queue.id, job.id, JSON.stringify({
      cleanupPhase: 'residue_cleanup',
      uninstallJobId: queue.cleanup_job_id,
      uninstallCompletedAt,
      residueCleanupDispatchedAt: new Date().toISOString(),
      residueCleanupDelivery: delivery,
      residueFinalState: finalState,
      residueFinalError: clean(finalError),
      residueInstallLocation: installLocation,
      residueAliases: aliases,
    })],
  )
  return { dispatched: true, queued: delivery !== 'websocket', jobId: job.id }
}

function residueCleanupSummary(job) {
  const result = object(job?.result)
  const parsed = object(result.parsed)
  const data = Object.keys(parsed).length ? parsed : result
  return {
    reclaimedMiB: Number(data.ReclaimedMiB || 0) || 0,
    installLocation: clean(data.InstallLocation),
    removed: array(data.Removed).map((item) => ({
      path: clean(item?.Path),
      reason: clean(item?.Reason),
      bytes: Number(item?.Bytes || 0) || 0,
    })),
    retained: array(data.Retained).map((item) => ({
      path: clean(item?.Path),
      reason: clean(item?.Reason),
      bytes: Number(item?.Bytes || 0) || 0,
    })),
  }
}

async function finalizeResidueCleanup(current, cleanup, { upgrade = false, rollback = false } = {}) {
  const failure = terminalJobFailure(cleanup)
  if (failure || clean(cleanup?.status) !== 'completed') {
    await markReview(current.id, failure || 'qualification_residue_cleanup_failed', { stage: 'residue_cleanup' })
    return { id: current.id, state: 'review_required' }
  }
  const evidence = object(current.evidence)
  const summary = residueCleanupSummary(cleanup)
  if (clean(evidence.residueFinalState) === 'review_required') {
    await markReview(current.id, clean(evidence.residueFinalError) || 'qualification_cleanup_failed', {
      stage: 'residue_cleanup',
      residueCleanup: summary,
      residueCleanupCompletedAt: cleanup.completed_at || new Date().toISOString(),
    })
    return { id: current.id, state: 'review_required' }
  }
  if (clean(evidence.residueFinalState) === 'cancelled') {
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET state='cancelled',last_error=$2,completed_at=now(),
              evidence=evidence || $3::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, clean(evidence.residueFinalError) || 'admin_cancelled_after_cleanup', JSON.stringify({
        stage: 'cancelled',
        residueCleanupCompletedAt: cleanup.completed_at || new Date().toISOString(),
        residueCleanup: summary,
        inventoryRemovalConfirmedAt: new Date().toISOString(),
      })],
    )
    return { id: current.id, state: 'cancelled' }
  }

  const now = new Date().toISOString()
  await withTransaction(async (client) => {
    await client.query(
      `UPDATE rmm_software_qualification_queue
          SET state='passed',last_error='',completed_at=now(),
              evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, JSON.stringify({
        stage: 'passed',
        residueCleanupCompletedAt: cleanup.completed_at || now,
        residueCleanup: summary,
        inventoryRemovalConfirmedAt: now,
      })],
    )
    await client.query(
      `UPDATE rmm_software_catalogue
          SET qualification_evidence=qualification_evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.catalogue_id, JSON.stringify(rollback ? {
        rollbackVerified: true,
        rollbackFromVersion: current.target_version,
        rollbackPreviousVersion: clean(evidence.previousVersion),
        rollbackRestoredVersion: current.target_version,
        rollbackVerifiedAt: now,
        rollbackCurrentInstallVerified: evidence.rollbackCurrentInstallVerified === true,
        rollbackCurrentUninstallVerified: evidence.rollbackCurrentUninstallVerified === true,
        rollbackPreviousInstallVerified: evidence.rollbackPreviousInstallVerified === true,
        rollbackPreviousInventoryVerified: evidence.rollbackPreviousInventoryVerified === true,
        rollbackRestorePatchDetectionVerified: evidence.rollbackRestorePatchDetectionVerified === true,
        rollbackRestorePatchDetectionInstalledVersion: clean(evidence.rollbackRestorePatchDetectionInstalledVersion),
        rollbackRestorePatchDetectionTargetVersion: clean(evidence.rollbackRestorePatchDetectionTargetVersion),
        rollbackRestoreVerified: evidence.rollbackRestoreVerified === true,
        rollbackFinalUninstallVerified: evidence.rollbackFinalUninstallVerified === true,
        rollbackQualificationQueueId: current.id,
        qualificationRunnerAgentDeviceId: current.runner_agent_device_id,
        rollbackResidueCleanupVerified: true,
        rollbackResidueCleanupVerifiedAt: now,
        rollbackResidueCleanupReclaimedMiB: summary.reclaimedMiB,
      } : upgrade ? {
        upgradeVerified: true,
        upgradeFromVersion: clean(evidence.previousVersion),
        upgradeVersion: current.target_version,
        upgradeVerifiedAt: now,
        upgradePatchDetectionVerified: evidence.upgradePatchDetectionVerified === true,
        upgradePatchDetectionInstalledVersion: clean(evidence.upgradePatchDetectionInstalledVersion),
        upgradePatchDetectionTargetVersion: clean(evidence.upgradePatchDetectionTargetVersion),
        upgradePatchDetectionVerifiedAt: clean(evidence.upgradePatchDetectionVerifiedAt),
        upgradeQualificationQueueId: current.id,
        qualificationRunnerAgentDeviceId: current.runner_agent_device_id,
        residueCleanupVerified: true,
        residueCleanupVerifiedAt: now,
        residueCleanupReclaimedMiB: summary.reclaimedMiB,
      } : {
        cleanInstallVerified: true,
        cleanInstallVersion: current.target_version,
        cleanInstallVerifiedAt: now,
        uninstallVerified: true,
        uninstallVerifiedAt: now,
        qualificationQueueId: current.id,
        qualificationRunnerAgentDeviceId: current.runner_agent_device_id,
        residueCleanupVerified: true,
        residueCleanupVerifiedAt: now,
        residueCleanupReclaimedMiB: summary.reclaimedMiB,
      })],
    )
  })
  return { id: current.id, state: 'passed' }
}

async function directReleaseForCatalogue(catalogueId) {
  const result = await pool.query(
    `SELECT c.*,r.id AS vendor_release_id,r.source_key,r.version AS release_version,
            r.installer_url,r.installer_sha256,r.installer_type AS release_installer_type,
            r.trust_state,r.asset_health_state,r.source_payload AS release_source_payload,
            s.last_success_at AS source_last_success_at,s.last_error AS source_last_error,
            COALESCE(NULLIF(b.metadata->>'expectedSigner',''),
                     NULLIF(b.metadata->>'autoExpectedSigner',''),
                     NULLIF(b.metadata->>'signerBaseline',''),
                     NULLIF(r.source_payload->>'expectedSigner',''),
                     NULLIF(r.source_payload->>'signerBaseline',''),
                     NULLIF(r.trust_evidence->>'signer',''),
                     NULLIF(s.metadata->>'expectedSigner',''),
                     NULLIF(s.metadata->>'signerBaseline',''),
                     NULLIF(c.publisher,''),'') AS expected_signer,
            COALESCE(NULLIF(b.metadata->>'installerTechnology',''),
                     NULLIF(r.source_payload->>'installerTechnology',''),'') AS installer_technology,
            COALESCE(NULLIF(b.metadata->>'wingetPackageId',''),'') AS binding_winget_package_id
       FROM rmm_software_catalogue c
       JOIN rmm_software_vendor_releases r
         ON r.provider_package_id=c.external_key
        AND r.source_key=c.source_metadata->>'latestSource'
        AND r.version=c.target_version
       JOIN rmm_software_vendor_sources s ON s.source_key=r.source_key AND s.enabled=true
       LEFT JOIN rmm_software_vendor_bindings b
         ON b.source_key=r.source_key AND b.provider_package_id=r.provider_package_id
        AND b.channel=r.channel AND b.platform=r.platform AND b.architecture=r.architecture
        AND b.enabled=true
      WHERE c.id=$1 AND c.tenant_id IS NULL AND c.status='active'
        AND c.qualification_state='deployment_candidate'
        AND c.source_metadata->>'deploymentMode' IN ('vendor_direct','winget_preferred')
        AND c.source_metadata->>'trustState'='direct_ready'
        AND r.trust_state='direct_ready'
      ORDER BY r.source_priority DESC,COALESCE(r.release_date,r.last_seen_at) DESC
      LIMIT 1`,
    [catalogueId],
  )
  return result.rows[0] || null
}

async function dispatchCleanInstall(queue, runner) {
  const liveSocket = agentSocketForDevice(runner.agent_device_id)
  const canPush = Boolean(liveSocket && liveSocket.readyState === 1)

  const catalogue = await directReleaseForCatalogue(queue.catalogue_id)
  if (!catalogue) {
    await markReview(queue.id, 'qualification_direct_release_not_ready')
    return { dispatched: false }
  }
  if (clean(catalogue.source_last_error) || !catalogue.source_last_success_at) {
    await markReview(queue.id, 'qualification_source_health_not_ready')
    return { dispatched: false }
  }
  if (clean(catalogue.asset_health_state) === 'dead') {
    await markReview(queue.id, 'qualification_vendor_asset_dead')
    return { dispatched: false }
  }
  if (!/^https:\/\//i.test(clean(catalogue.installer_url))
    || !/^[a-f0-9]{64}$/i.test(clean(catalogue.installer_sha256))
    || !['msi', 'exe'].includes(lower(catalogue.release_installer_type))
    || !clean(catalogue.expected_signer)) {
    await markReview(queue.id, 'qualification_artifact_gate_failed')
    return { dispatched: false }
  }

  const releasePayload = object(catalogue.release_source_payload)
  const wingetManifest = object(releasePayload.wingetManifest)
  const declaredScope = lower(wingetManifest.scope)
  if (declaredScope === 'user') {
    await markReview(queue.id, 'qualification_scope_mismatch', {
      stage: 'pre_install_scope_validation',
      expectedScope: 'machine',
      declaredScope,
      selectedAsset: clean(object(catalogue.source_metadata).selectedAsset || catalogue.asset_name),
    })
    return { dispatched: false, blocked: true, reason: 'qualification_scope_mismatch' }
  }

  const current = await qualificationRow(queue.id)
  if (!current) return { dispatched: false }
  const contaminants = await qualificationRunnerContaminants(runner, queue.id)
  if (contaminants.length) {
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET last_error='runner_contaminated_by_prior_qualification',
              evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1 AND state='queued'`,
      [queue.id, JSON.stringify({ runnerContaminants: contaminants })],
    )
    return { dispatched: false, blocked: true, reason: 'runner_contaminated_by_prior_qualification', contaminants }
  }
  const preinstalled = installedMatches(runner.source_payload, current)
  if (preinstalled.length) {
    const manualQualification = object(current.evidence).manualRequalification === true
    if (manualQualification) {
      const target = preinstalled[preinstalled.length - 1]
      const preclean = await dispatchPrecleanUninstall(current, runner, target)
      return {
        dispatched: false,
        blocked: !preclean.dispatched,
        reason: preclean.dispatched ? 'qualification_preclean_running' : 'qualification_preclean_dispatch_failed',
        preclean,
      }
    }
    await markReview(queue.id, 'qualification_runner_not_clean', {
      stage: 'pre_install',
      installed: preinstalled.map((item) => ({
        name: clean(item?.name),
        version: clean(item?.version),
        registryKey: clean(item?.registry_key),
      })),
    })
    return { dispatched: false }
  }

  const sourceMetadata = object(catalogue.source_metadata)
  const execution = object(catalogue.execution)
  const verification = object(catalogue.verification)
  const responseFile = normalizedResponseFile(execution.responseFile)
  if (responseFile && !runnerSupportsResponseFiles(runner)) {
    await markReview(queue.id, 'qualification_response_file_capability_required', {
      stage: 'pre_install_response_file_capability',
      requiredPatchHostVersion: '0.2.16',
      currentPatchHostVersion: clean(object(runner.patch_capabilities).patchHostVersion || object(runner.patch_capabilities).version),
    })
    return { dispatched: false, blocked: true, reason: 'qualification_response_file_capability_required' }
  }
  if (lower(catalogue.installer_technology) === 'office_odt_sfx' && !runnerSupportsOfficeClickToRun(runner)) {
    await markReview(queue.id, 'qualification_office_c2r_capability_required', {
      stage: 'pre_install_office_c2r_capability',
      requiredPatchHostVersion: '0.2.18',
      currentPatchHostVersion: clean(object(runner.patch_capabilities).patchHostVersion || object(runner.patch_capabilities).version),
    })
    return { dispatched: false, blocked: true, reason: 'qualification_office_c2r_capability_required' }
  }
  const fallbackPackageId = sourceMetadata.wingetFallbackReady === true
    ? clean(catalogue.binding_winget_package_id || sourceMetadata.wingetPackageId)
    : ''
  const executionPackageId = fallbackPackageId || clean(catalogue.provider_package_id)
  const verificationMethod = clean(verification.method || verification.provider || 'winget')
  if (!verificationMethod || !clean(catalogue.target_version)) {
    await markReview(queue.id, 'qualification_verification_gate_failed')
    return { dispatched: false }
  }

  const verificationTargetVersion = verificationVersionForRelease(catalogue.target_version, verification)
  const manifest = {
    protocolVersion: 1,
    action: 'software.install',
    intent: 'install',
    catalogueId: catalogue.id,
    applicationName: catalogue.canonical_name,
    publisher: catalogue.publisher,
    packageId: executionPackageId,
    installedVersion: '',
    targetVersion: clean(catalogue.target_version),
    provider: 'vendor_direct',
    vendorSource: clean(catalogue.source_key),
    downloadUrl: clean(catalogue.installer_url),
    sha256: clean(catalogue.installer_sha256).toUpperCase(),
    installerType: lower(catalogue.release_installer_type),
    installerTechnology: clean(catalogue.installer_technology),
    installArguments: clean(execution.installArguments),
    responseFile: normalizedResponseFile(execution.responseFile),
    expectedSigner: clean(catalogue.expected_signer),
    fallbackProvider: '',
    verification: {
      ...verification,
      method: verificationMethod,
      packageId: clean(verification.packageId || executionPackageId),
      targetVersion: verificationTargetVersion,
    },
  }

  const created = await withTransaction(async (client) => {
    const jobResult = await client.query(
      `INSERT INTO rmm_agent_jobs
        (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
       VALUES ($1,$2,'patch.software',$3::jsonb,'system','Catalogue qualification',$4::jsonb)
       RETURNING id,status,created_at`,
      [
        runner.tenant_id,
        runner.agent_device_id,
        JSON.stringify(manifest),
        JSON.stringify({
          source: 'catalogue_qualification_clean_install',
          qualification_queue_id: queue.id,
          catalogue_id: catalogue.id,
          vendor_release_id: catalogue.vendor_release_id,
          device_name: runner.device_name,
          device_reference: runner.device_reference,
        }),
      ],
    )
    const job = jobResult.rows[0]
    const deploymentResult = await client.query(
      `INSERT INTO rmm_patch_deployments
        (tenant_id,inventory_id,catalogue_id,agent_job_id,application_name,provider,provider_package_id,
         installed_version,target_version,status,result)
       VALUES ($1,$2,$3,$4,$5,'vendor_direct',$6,'',$7,'eligible',$8::jsonb)
       RETURNING id`,
      [
        runner.tenant_id,
        runner.inventory_id,
        catalogue.id,
        job.id,
        catalogue.canonical_name,
        executionPackageId,
        clean(catalogue.target_version),
        JSON.stringify({ qualificationTest: 'clean_install', vendorSource: catalogue.source_key }),
      ],
    )
    const deployment = deploymentResult.rows[0]
    await client.query(
      `UPDATE rmm_software_qualification_queue
          SET state='running',attempt_count=attempt_count+1,runner_agent_device_id=$2,
              agent_job_id=$3,deployment_id=$4,cleanup_job_id=NULL,last_error='',
              started_at=now(),completed_at=NULL,
              evidence=evidence || $5::jsonb,updated_at=now()
        WHERE id=$1`,
      [queue.id, runner.agent_device_id, job.id, deployment.id, JSON.stringify({
        stage: 'install_running',
        targetVersion: catalogue.target_version,
        vendorSource: catalogue.source_key,
        vendorReleaseId: catalogue.vendor_release_id,
        dispatchedAt: new Date().toISOString(),
        preInstallInventoryKeys: softwareItems(runner.source_payload).map(softwareIdentityKey),
      })],
    )
    return { job, deployment }
  })
  let delivery = 'queued_agent_channel'
  if (canPush) {
    const claimed = await pool.query(
      `UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now()
        WHERE id=$1 AND status='queued' RETURNING id`,
      [created.job.id],
    )
    if (claimed.rowCount) {
      const pushed = sendAgentMessage(runner.agent_device_id, {
        type: 'job_execute',
        job: {
          id: created.job.id,
          job_type: 'patch.software',
          payload: manifest,
          created_at: created.job.created_at,
        },
      })
      if (pushed) {
        delivery = 'websocket'
      } else {
        await pool.query(
          `UPDATE rmm_agent_jobs
              SET status='queued',claimed_at=NULL,error_message='',updated_at=now()
            WHERE id=$1 AND status='claimed'`,
          [created.job.id],
        )
      }
    }
  }
  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET evidence=evidence || $2::jsonb,updated_at=now()
      WHERE id=$1`,
    [queue.id, JSON.stringify({ installDelivery: delivery })],
  )
  return {
    dispatched: true,
    queued: delivery !== 'websocket',
    jobId: created.job.id,
    deploymentId: created.deployment.id,
  }
}

function compareVersionish(a, b) {
  return clean(a).localeCompare(clean(b), undefined, { numeric: true, sensitivity: 'base' })
}

async function upgradeReleasePair(catalogueId) {
  const result = await pool.query(
    `SELECT c.*,r.id AS vendor_release_id,r.source_key,r.version AS release_version,
            r.installer_url,r.installer_sha256,r.installer_type AS release_installer_type,
            r.trust_state,r.asset_health_state,r.source_payload AS release_source_payload,
            r.trust_evidence AS release_trust_evidence,
            COALESCE(r.source_payload->'verification',c.verification) AS release_verification,
            jsonb_build_object(
              'installArguments',
              CASE
                WHEN lower(COALESCE(b.metadata->>'manualExecutionOverride','false'))='true'
                  THEN COALESCE(
                    NULLIF(b.metadata->>'installArguments',''),
                    NULLIF(r.source_payload->>'installArguments',''),
                    c.execution->>'installArguments',
                    ''
                  )
                ELSE COALESCE(
                  NULLIF(r.source_payload->>'installArguments',''),
                  NULLIF(b.metadata->>'installArguments',''),
                  c.execution->>'installArguments',
                  ''
                )
              END,
              'responseFile',
              CASE
                WHEN lower(COALESCE(b.metadata->>'manualExecutionOverride','false'))='true'
                  THEN COALESCE(
                    b.metadata->'responseFile',
                    r.source_payload->'responseFile',
                    c.execution->'responseFile'
                  )
                ELSE COALESCE(
                  r.source_payload->'responseFile',
                  b.metadata->'responseFile',
                  c.execution->'responseFile'
                )
              END
            ) AS release_execution,
            s.last_success_at AS source_last_success_at,s.last_error AS source_last_error,
            COALESCE(NULLIF(b.metadata->>'expectedSigner',''),
                     NULLIF(r.trust_evidence->>'signer',''),
                     NULLIF(r.source_payload->>'signerBaseline',''),
                     NULLIF(c.publisher,''),'') AS expected_signer,
            COALESCE(NULLIF(r.source_payload->>'installerTechnology',''),
                     NULLIF(b.metadata->>'installerTechnology',''),
                     NULLIF(r.installer_type,''),'') AS installer_technology
       FROM rmm_software_catalogue c
       JOIN rmm_software_vendor_releases r
         ON r.provider_package_id=c.external_key
        AND r.source_key=c.source_metadata->>'latestSource'
       JOIN rmm_software_vendor_sources s ON s.source_key=r.source_key AND s.enabled=true
       LEFT JOIN rmm_software_vendor_bindings b
         ON b.source_key=r.source_key AND b.provider_package_id=r.provider_package_id
        AND b.channel=r.channel AND b.platform=r.platform AND b.architecture=r.architecture
        AND b.enabled=true
      WHERE c.id=$1 AND c.tenant_id IS NULL AND c.status='active'
        AND c.qualification_state IN ('deployment_candidate','qualified','qualified_limited')
        AND r.trust_state='direct_ready'
      ORDER BY r.last_seen_at DESC`,
    [catalogueId],
  )
  const target = result.rows.find((row) => clean(row.release_version) === clean(row.target_version))
  const previous = result.rows
    .filter((row) => compareVersionish(row.release_version, row.target_version) < 0)
    .sort((a, b) => compareVersionish(b.release_version, a.release_version))[0]
  return { target: target || null, previous: previous || null }
}

function strictDirectArtifactReady(release) {
  return Boolean(
    release
    && !clean(release.source_last_error)
    && release.source_last_success_at
    && clean(release.asset_health_state) !== 'dead'
    && /^https:\/\//i.test(clean(release.installer_url))
    && /^[a-f0-9]{64}$/i.test(clean(release.installer_sha256))
    && ['msi', 'exe'].includes(lower(release.release_installer_type))
    && clean(release.expected_signer),
  )
}

async function dispatchUpgradeInstall(queue, runner, release, {
  intent,
  installedVersion = '',
  stage,
  qualificationTest = 'upgrade',
  requestSource = 'catalogue_qualification_upgrade',
  actorLabel = 'Catalogue upgrade qualification',
}) {
  const liveSocket = agentSocketForDevice(runner.agent_device_id)
  const canPush = Boolean(liveSocket && liveSocket.readyState === 1)
  if (!strictDirectArtifactReady(release)) {
    await markReview(queue.id, 'qualification_upgrade_artifact_gate_failed', { stage, releaseVersion: clean(release?.release_version) })
    return { dispatched: false }
  }

  const verification = object(release.release_verification || release.verification)
  const execution = object(release.release_execution || release.execution)
  const responseFile = normalizedResponseFile(execution.responseFile)
  if (responseFile && !runnerSupportsResponseFiles(runner)) {
    await markReview(queue.id, 'qualification_response_file_capability_required', {
      stage,
      requiredPatchHostVersion: '0.2.16',
      currentPatchHostVersion: clean(object(runner.patch_capabilities).patchHostVersion || object(runner.patch_capabilities).version),
    })
    return { dispatched: false, blocked: true, reason: 'qualification_response_file_capability_required' }
  }
  if (lower(release.installer_technology) === 'office_odt_sfx' && !runnerSupportsOfficeClickToRun(runner)) {
    await markReview(queue.id, 'qualification_office_c2r_capability_required', {
      stage,
      requiredPatchHostVersion: '0.2.18',
      currentPatchHostVersion: clean(object(runner.patch_capabilities).patchHostVersion || object(runner.patch_capabilities).version),
    })
    return { dispatched: false, blocked: true, reason: 'qualification_office_c2r_capability_required' }
  }
  const targetVersion = clean(release.release_version)
  const packageId = clean(release.provider_package_id)
  const verificationMethod = clean(verification.method || verification.provider || 'uninstall_registry')
  if (!targetVersion || !verificationMethod) {
    await markReview(queue.id, 'qualification_upgrade_verification_gate_failed', { stage })
    return { dispatched: false }
  }

  const verificationTargetVersion = verificationVersionForRelease(targetVersion, verification)
  const manifest = {
    protocolVersion: 1,
    action: 'software.install',
    intent,
    catalogueId: release.id,
    applicationName: release.canonical_name,
    publisher: release.publisher,
    packageId,
    installedVersion: clean(installedVersion),
    targetVersion,
    provider: 'vendor_direct',
    vendorSource: clean(release.source_key),
    downloadUrl: clean(release.installer_url),
    sha256: clean(release.installer_sha256).toUpperCase(),
    installerType: lower(release.release_installer_type),
    installerTechnology: clean(release.installer_technology),
    installArguments: clean(execution.installArguments),
    responseFile: normalizedResponseFile(execution.responseFile),
    expectedSigner: clean(release.expected_signer),
    fallbackProvider: '',
    verification: {
      ...verification,
      method: verificationMethod,
      packageId: clean(verification.packageId || packageId),
      targetVersion: verificationTargetVersion,
    },
  }

  const created = await withTransaction(async (client) => {
    const jobResult = await client.query(
      `INSERT INTO rmm_agent_jobs
        (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
       VALUES ($1,$2,'patch.software',$3::jsonb,'system',$5,$4::jsonb)
       RETURNING id,status,created_at`,
      [
        runner.tenant_id,
        runner.agent_device_id,
        JSON.stringify(manifest),
        JSON.stringify({
          source: requestSource,
          qualification_queue_id: queue.id,
          catalogue_id: release.id,
          vendor_release_id: release.vendor_release_id,
          stage,
          device_name: runner.device_name,
          device_reference: runner.device_reference,
        }),
        actorLabel,
      ],
    )
    const job = jobResult.rows[0]
    const deploymentResult = await client.query(
      `INSERT INTO rmm_patch_deployments
        (tenant_id,inventory_id,catalogue_id,agent_job_id,application_name,provider,provider_package_id,
         installed_version,target_version,status,result)
       VALUES ($1,$2,$3,$4,$5,'vendor_direct',$6,$7,$8,'eligible',$9::jsonb)
       RETURNING id`,
      [
        runner.tenant_id,
        runner.inventory_id,
        release.id,
        job.id,
        release.canonical_name,
        packageId,
        clean(installedVersion),
        targetVersion,
        JSON.stringify({ qualificationTest, stage, vendorSource: release.source_key, intent }),
      ],
    )
    const deployment = deploymentResult.rows[0]
    await client.query(
      `UPDATE rmm_software_qualification_queue
          SET state='running',runner_agent_device_id=$2,agent_job_id=$3,deployment_id=$4,
              cleanup_job_id=NULL,last_error='',started_at=COALESCE(started_at,now()),completed_at=NULL,
              attempt_count=CASE WHEN $6 IN ('upgrade_baseline_running','rollback_current_install_running') THEN attempt_count+1 ELSE attempt_count END,
              evidence=evidence || $5::jsonb,updated_at=now()
        WHERE id=$1`,
      [queue.id, runner.agent_device_id, job.id, deployment.id, JSON.stringify({
        stage,
        releaseVersion: targetVersion,
        vendorReleaseId: release.vendor_release_id,
        dispatchedAt: new Date().toISOString(),
        preInstallInventoryKeys: softwareItems(runner.source_payload).map(softwareIdentityKey),
        ...(intent === 'install' ? { previousVersion: targetVersion } : { targetVersion }),
      }), stage],
    )
    return { job, deployment }
  })

  let delivery = 'queued_agent_channel'
  if (canPush) {
    const claimed = await pool.query(
      `UPDATE rmm_agent_jobs SET status='claimed',claimed_at=now(),updated_at=now()
        WHERE id=$1 AND status='queued' RETURNING id`,
      [created.job.id],
    )
    if (claimed.rowCount) {
      const pushed = sendAgentMessage(runner.agent_device_id, {
        type: 'job_execute',
        job: { id: created.job.id, job_type: 'patch.software', payload: manifest, created_at: created.job.created_at },
      })
      if (pushed) {
        delivery = 'websocket'
      } else {
        await pool.query(
          `UPDATE rmm_agent_jobs
              SET status='queued',claimed_at=NULL,error_message='',updated_at=now()
            WHERE id=$1 AND status='claimed'`,
          [created.job.id],
        )
      }
    }
  }
  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET evidence=evidence || $2::jsonb,updated_at=now()
      WHERE id=$1`,
    [queue.id, JSON.stringify({ installDelivery: delivery })],
  )
  return {
    dispatched: true,
    queued: delivery !== 'websocket',
    jobId: created.job.id,
    deploymentId: created.deployment.id,
  }
}

async function dispatchUpgradeBaseline(queue, runner) {
  const current = await qualificationRow(queue.id)
  if (!current) return { dispatched: false }
  const contaminants = await qualificationRunnerContaminants(runner, queue.id)
  if (contaminants.length) {
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET last_error='runner_contaminated_by_prior_qualification',
              evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1 AND state='queued'`,
      [queue.id, JSON.stringify({ runnerContaminants: contaminants })],
    )
    return { dispatched: false, blocked: true, reason: 'runner_contaminated_by_prior_qualification', contaminants }
  }
  if (installedMatches(runner.source_payload, current).length) {
    await markReview(queue.id, 'qualification_runner_not_clean', { stage: 'upgrade_pre_install' })
    return { dispatched: false }
  }
  const pair = await upgradeReleasePair(queue.catalogue_id)
  if (!pair.target) {
    await markReview(queue.id, 'qualification_current_trusted_release_not_available', { stage: 'upgrade_pre_install' })
    return { dispatched: false }
  }
  if (!pair.previous) {
    await markReview(queue.id, 'previous_trusted_release_not_available', { stage: 'upgrade_pre_install' })
    return { dispatched: false }
  }
  return dispatchUpgradeInstall(queue, runner, pair.previous, {
    intent: 'install',
    installedVersion: '',
    stage: 'upgrade_baseline_running',
  })
}

async function reconcileUpgradeQueueRow(queue, runner) {
  const current = await qualificationRow(queue.id)
  if (!current) return { id: queue.id, state: 'missing' }
  const evidence = object(current.evidence)

  if (current.state === 'running') {
    const jobResult = await pool.query(
      `SELECT status,result,error_message,completed_at FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.agent_job_id],
    )
    const job = jobResult.rows[0]
    if (!job || ['queued', 'claimed'].includes(clean(job.status))) return { id: current.id, state: current.state }
    const failure = terminalJobFailure(job)
    const providerFailure = qualificationProviderFailure(job.result)
    if (failure || providerFailure || clean(job.status) !== 'completed' || !verifiedPatchResult(job.result)) {
      if (current.deployment_id) {
        await pool.query(
          `UPDATE rmm_patch_deployments SET status=$2,result=COALESCE($3::jsonb,'{}'::jsonb),
              completed_at=COALESCE(completed_at,now()),updated_at=now() WHERE id=$1`,
          [current.deployment_id, clean(job.status) === 'cancelled' ? 'cancelled' : 'verification_failed', JSON.stringify(object(job?.result))],
        )
      }
      const historicalUnavailable = await classifyRotatedHistoricalArtifact(current, job, clean(evidence.stage))
      if (historicalUnavailable.classified) {
        return { id: current.id, state: 'cancelled', ...historicalUnavailable }
      }

      if (windowsInstallerBusy(job)) {
        const requeued = await requeueWindowsInstallerBusy(current, clean(evidence.stage) || 'upgrade_install')
        if (requeued) return { id: current.id, state: 'queued', retry: 'windows_installer_busy' }
      }

      if (failure === 'qualification_runtime_limit_exceeded' && runner
        && clean(current.runner_agent_device_id) === clean(runner.agent_device_id)) {
        const installed=installedMatches(runner.source_payload,current)
        if (installed.length) {
          await pool.query(
            `UPDATE rmm_software_qualification_queue
                SET evidence=evidence || $2::jsonb,updated_at=now() WHERE id=$1`,
            [current.id,JSON.stringify({skipAfterTimeout:true,
              timeoutFinalError:failure,installCompletedAt:new Date().toISOString()})],
          )
          const dispatched=await dispatchUninstall(current,runner,installed[installed.length-1])
          return { id:current.id,state:dispatched.dispatched?'cleanup_running':'review_required' }
        }
      }
      await markReview(current.id, failure || providerFailure || 'qualification_upgrade_verification_failed', { stage: clean(evidence.stage) })
      return { id: current.id, state: 'review_required' }
    }

    if (current.deployment_id) {
      await pool.query(
        `UPDATE rmm_patch_deployments SET status='succeeded',result=$2::jsonb,
            completed_at=COALESCE(completed_at,$3,now()),updated_at=now() WHERE id=$1`,
        [current.deployment_id, JSON.stringify(object(job.result)), job.completed_at || null],
      )
    }

    if (clean(evidence.stage) === 'upgrade_baseline_running') {
      const pair = await upgradeReleasePair(current.catalogue_id)
      if (!pair.target || !pair.previous) {
        await markReview(current.id, 'qualification_upgrade_release_pair_lost', { stage: 'upgrade_detection_pending' })
        return { id: current.id, state: 'review_required' }
      }
      await pool.query(
        `UPDATE rmm_software_qualification_queue
            SET evidence=evidence || $2::jsonb,updated_at=now()
          WHERE id=$1`,
        [current.id, JSON.stringify({
          stage: 'upgrade_detection_pending',
          baselineInstallCompletedAt: job.completed_at || new Date().toISOString(),
          previousVersion: clean(pair.previous.release_version),
          targetVersion: clean(pair.target.release_version),
        })],
      )
      return { id: current.id, state: 'running' }
    }

    if (clean(evidence.stage) === 'upgrade_detection_pending') {
      if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) {
        return { id: current.id, state: current.state }
      }
      const pair = await upgradeReleasePair(current.catalogue_id)
      if (!pair.target || !pair.previous) {
        await markReview(current.id, 'qualification_upgrade_release_pair_lost', { stage: 'upgrade_detection_pending' })
        return { id: current.id, state: 'review_required' }
      }

      const targetVersion = clean(pair.target.release_version)
      const installed = installedMatches(runner.source_payload, current)
      const outdated = installed
        .map((item) => ({ item, comparison: compareVersionish(clean(item?.version), targetVersion) }))
        .filter((entry) => entry.comparison < 0)
        .sort((a, b) => compareVersionish(clean(b.item?.version), clean(a.item?.version)))

      if (!outdated.length) {
        const baselineAt = Date.parse(clean(evidence.baselineInstallCompletedAt || job.completed_at))
        if (Number.isFinite(baselineAt) && Date.now() - baselineAt > 10 * 60 * 1000) {
          await markReview(current.id, 'qualification_upgrade_patch_detection_failed', {
            stage: 'upgrade_detection_pending',
            expectedPreviousVersion: clean(pair.previous.release_version),
            targetVersion,
            observedMatches: installed.map((item) => ({
              name: clean(item?.name),
              publisher: clean(item?.publisher),
              version: clean(item?.version),
              registryKey: clean(item?.registry_key),
            })),
          })
          return { id: current.id, state: 'review_required' }
        }
        return { id: current.id, state: current.state }
      }

      const detected = outdated[0].item
      const detectedVersion = clean(detected?.version)
      const detectedScope = qualificationScope(detected?.scope)
      const detectedUserProfile = lower(detected?.user_profile)
      if (detectedScope === 'user' || detectedUserProfile.includes('systemprofile')) {
        await pool.query(
          `UPDATE rmm_software_qualification_queue
              SET evidence=evidence || $2::jsonb,updated_at=now()
            WHERE id=$1`,
          [current.id, JSON.stringify({
            postInstallScopeMismatch: true,
            stage: 'upgrade_baseline_scope_mismatch_cleanup',
            expectedScope: 'machine',
            actualScope: clean(detected?.scope),
            actualUserProfile: clean(detected?.user_profile),
            observedScopeIdentity: {
              name: clean(detected?.name),
              publisher: clean(detected?.publisher),
              version: clean(detected?.version),
              registryKey: clean(detected?.registry_key),
            },
          })],
        )
        const dispatched = await dispatchUninstall(current, runner, detected)
        return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : 'review_required' }
      }
      await pool.query(
        `UPDATE rmm_software_qualification_queue
            SET evidence=evidence || $2::jsonb,updated_at=now()
          WHERE id=$1`,
        [current.id, JSON.stringify({
          upgradePatchDetectionVerified: true,
          upgradePatchDetectionStatus: 'update_available',
          upgradePatchDetectionInstalledVersion: detectedVersion,
          upgradePatchDetectionTargetVersion: targetVersion,
          upgradePatchDetectionVerifiedAt: new Date().toISOString(),
          upgradePatchDetectionIdentity: {
            name: clean(detected?.name),
            publisher: clean(detected?.publisher),
            registryKey: clean(detected?.registry_key),
            scope: clean(detected?.scope),
          },
        })],
      )

      const result = await dispatchUpgradeInstall(current, runner, pair.target, {
        intent: 'update',
        installedVersion: detectedVersion || clean(pair.previous.release_version),
        stage: 'upgrade_target_running',
      })
      return { id: current.id, state: result.dispatched ? 'running' : 'review_required' }
    }

    if (clean(evidence.stage) === 'upgrade_target_running') {
      const result = object(job.result)
      await pool.query(
        `UPDATE rmm_software_qualification_queue
            SET state='cleanup_pending',last_error='',
                evidence=evidence || $2::jsonb,updated_at=now()
          WHERE id=$1`,
        [current.id, JSON.stringify({
          stage: 'upgrade_cleanup_pending',
          upgradeCompletedAt: job.completed_at || new Date().toISOString(),
          verifiedVersion: clean(result.verifiedVersion || object(result.verification).installedVersion),
        })],
      )
      return { id: current.id, state: 'cleanup_pending' }
    }

    await markReview(current.id, 'qualification_upgrade_unknown_stage', { stage: clean(evidence.stage) })
    return { id: current.id, state: 'review_required' }
  }

  if (current.state === 'cleanup_pending') {
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) return { id: current.id, state: current.state }
    const upgradeCompletedAt = Date.parse(clean(object(current.evidence).upgradeCompletedAt))
    const inventoryObservedAt = runner.last_inventory_at instanceof Date
      ? runner.last_inventory_at.getTime()
      : Date.parse(clean(runner.last_inventory_at))
    if (Number.isFinite(upgradeCompletedAt)
      && (!Number.isFinite(inventoryObservedAt) || inventoryObservedAt <= upgradeCompletedAt)) {
      return { id: current.id, state: current.state }
    }
    let installed = installedMatches(runner.source_payload, current)
    if (!installed.length) {
      const learned = await learnVerifiedObservedIdentity(current, runner)
      if (learned.scopeMismatch) {
        await pool.query(
          `UPDATE rmm_software_qualification_queue
              SET evidence=evidence || $2::jsonb,updated_at=now()
            WHERE id=$1`,
          [current.id, JSON.stringify({
            postInstallScopeMismatch: true,
            expectedScope: 'machine',
            actualScope: clean(learned.item?.scope),
            actualUserProfile: clean(learned.item?.user_profile),
            observedScopeIdentity: {
              name: clean(learned.item?.name),
              publisher: clean(learned.item?.publisher),
              version: clean(learned.item?.version),
              registryKey: clean(learned.item?.registry_key),
            },
          })],
        )
        const dispatched = await dispatchUninstall(current, runner, learned.item)
        return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : 'cleanup_pending' }
      }
      if (learned.learned) {
        const refreshed = await qualificationRow(current.id)
        installed = refreshed ? installedMatches(runner.source_payload, refreshed) : []
        if (installed.length) {
          const dispatched = await dispatchUninstall(refreshed, runner, installed[installed.length - 1])
          return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : 'cleanup_pending' }
        }
      }
    }
    if (installed.length) {
      const dispatched = await dispatchUninstall(current, runner, installed[installed.length - 1])
      return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : 'cleanup_pending' }
    }
    const completedAt = Date.parse(clean(evidence.upgradeCompletedAt))
    if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
      await markReview(current.id, 'qualification_upgrade_not_visible_in_inventory', { stage: 'upgrade_cleanup_pending' })
      return { id: current.id, state: 'review_required' }
    }
    return { id: current.id, state: current.state }
  }

  if (current.state === 'cleanup_running') {
    const cleanupResult = await pool.query(
      `SELECT status,result,error_message,completed_at FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.cleanup_job_id],
    )
    const cleanup = cleanupResult.rows[0]
    if (!cleanup || ['queued', 'claimed'].includes(clean(cleanup.status))) return { id: current.id, state: current.state }
    if (clean(object(current.evidence).cleanupPhase) === 'residue_cleanup') {
      return finalizeResidueCleanup(current, cleanup, { upgrade: true })
    }
    const failure = terminalJobFailure(cleanup)
    if (failure || clean(cleanup.status) !== 'completed') {
      if (runner && clean(current.runner_agent_device_id) === clean(runner.agent_device_id)
        && !installedMatches(runner.source_payload, current).length) {
        const dispatched = await dispatchQualificationResidueCleanup(current, runner, {
          finalState: 'review_required',
          finalError: failure || 'qualification_upgrade_cleanup_failed',
          uninstallCompletedAt: cleanup.completed_at || '',
        })
        return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : current.state }
      }
      await markReview(current.id, failure || 'qualification_upgrade_cleanup_failed', { stage: 'upgrade_cleanup' })
      return { id: current.id, state: 'review_required' }
    }
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) return { id: current.id, state: current.state }
    const remaining = installedMatches(runner.source_payload, current)
    if (remaining.length) {
      const cleanupReason = clean(object(cleanup.result).reason || object(object(cleanup.result).parsed).reason)
      const requestedRegistryKey = lower(object(current.evidence).uninstallRegistryKey)
      const liveIdentityChanged = remaining.some((item) => {
        const registryKey = lower(item?.registry_key)
        return registryKey && requestedRegistryKey && registryKey !== requestedRegistryKey
      })
      if (cleanupReason === 'already_not_present' && liveIdentityChanged) {
        const dispatched = await dispatchUninstall(current, runner, remaining[remaining.length - 1])
        return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : current.state }
      }
      const completedAt = Date.parse(clean(cleanup.completed_at))
      if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
        await markReview(current.id, 'qualification_upgrade_uninstall_residue_detected', {
          stage: 'upgrade_cleanup',
          remaining: remaining.map((item) => ({ name: clean(item?.name), version: clean(item?.version), registryKey: clean(item?.registry_key) })),
        })
        return { id: current.id, state: 'review_required' }
      }
      return { id: current.id, state: current.state }
    }

    const scopeMismatch = object(current.evidence).postInstallScopeMismatch === true
    const timedOut = object(current.evidence).skipAfterTimeout === true
    const dispatched = await dispatchQualificationResidueCleanup(current, runner, {
      finalState: (scopeMismatch || timedOut) ? 'review_required' : 'passed',
      finalError: timedOut ? 'qualification_runtime_limit_exceeded' : scopeMismatch ? 'qualification_scope_mismatch' : '',
      uninstallCompletedAt: cleanup.completed_at || '',
    })
    return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : current.state }
  }

  return { id: current.id, state: current.state }
}

async function rollbackFailureOrCleanup(current, runner, error, stage, details = {}) {
  const reason = clean(error || 'qualification_rollback_failed')
  if (runner && clean(current.runner_agent_device_id) === clean(runner.agent_device_id)) {
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET state='running',last_error=$2,
              evidence=evidence || $3::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, reason, JSON.stringify({
        stage: 'rollback_failure_cleanup_pending',
        rollbackFailureError: reason,
        rollbackFailureStage: stage,
        rollbackFailureAt: new Date().toISOString(),
        ...details,
      })],
    )
    return { id: current.id, state: 'running', cleanup: true }
  }
  await markReview(current.id, reason, { stage, ...details })
  return { id: current.id, state: 'review_required' }
}

function rollbackJobTimedOut(job, startedAt = '') {
  if (!job || !['queued','claimed'].includes(clean(job.status))) return false
  const started = Date.parse(clean(startedAt || job.claimed_at || job.created_at))
  return Number.isFinite(started) && Date.now() - started > 10 * 60 * 1000
}

async function dispatchRollbackQualification(queue, runner) {
  const current = await qualificationRow(queue.id)
  if (!current) return { dispatched: false }

  const contaminants = await qualificationRunnerContaminants(runner, queue.id)
  if (contaminants.length) {
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET last_error='runner_contaminated_by_prior_qualification',
              evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1 AND state='queued'`,
      [queue.id, JSON.stringify({ runnerContaminants: contaminants })],
    )
    return { dispatched: false, blocked: true, reason: 'runner_contaminated_by_prior_qualification', contaminants }
  }
  if (installedMatches(runner.source_payload, current).length) {
    await markReview(queue.id, 'qualification_runner_not_clean', { stage: 'rollback_pre_install' })
    return { dispatched: false }
  }

  const pair = await upgradeReleasePair(queue.catalogue_id)
  if (!pair.target) {
    await markReview(queue.id, 'qualification_current_trusted_release_not_available', { stage: 'rollback_pre_install' })
    return { dispatched: false }
  }
  if (!pair.previous) {
    await markReview(queue.id, 'previous_trusted_release_not_available', { stage: 'rollback_pre_install' })
    return { dispatched: false }
  }
  if (!strictDirectArtifactReady(pair.target) || !strictDirectArtifactReady(pair.previous)) {
    await markReview(queue.id, 'qualification_rollback_artifact_gate_failed', {
      stage: 'rollback_pre_install',
      targetVersion: clean(pair.target.release_version),
      previousVersion: clean(pair.previous.release_version),
    })
    return { dispatched: false }
  }

  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET evidence=evidence || $2::jsonb,updated_at=now()
      WHERE id=$1`,
    [queue.id, JSON.stringify({
      rollbackStartedAt: new Date().toISOString(),
      targetVersion: clean(pair.target.release_version),
      previousVersion: clean(pair.previous.release_version),
    })],
  )

  return dispatchUpgradeInstall(current, runner, pair.target, {
    intent: 'install',
    installedVersion: '',
    stage: 'rollback_current_install_running',
    qualificationTest: 'rollback',
    requestSource: 'catalogue_qualification_rollback',
    actorLabel: 'Catalogue rollback qualification',
  })
}

async function reconcileRollbackQueueRow(queue, runner) {
  const current = await qualificationRow(queue.id)
  if (!current) return { id: queue.id, state: 'missing' }
  const evidence = object(current.evidence)
  const stage = clean(evidence.stage)

  if (current.state === 'cleanup_running' && clean(evidence.cleanupPhase) === 'residue_cleanup') {
    const cleanupResult = await pool.query(
      `SELECT status,result,error_message,completed_at,created_at,claimed_at
         FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.cleanup_job_id],
    )
    const cleanup = cleanupResult.rows[0]
    if (!cleanup || ['queued','claimed'].includes(clean(cleanup.status))) {
      if (rollbackJobTimedOut(cleanup, evidence.residueCleanupDispatchedAt)) {
        await markReview(current.id, 'qualification_runtime_limit_exceeded', { stage: 'rollback_residue_cleanup' })
        return { id: current.id, state: 'review_required' }
      }
      return { id: current.id, state: current.state }
    }
    return finalizeResidueCleanup(current, cleanup, { rollback: true })
  }

  if (stage === 'rollback_failure_cleanup_pending') {
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) {
      return { id: current.id, state: current.state }
    }
    const installed = installedMatches(runner.source_payload, current)
    if (installed.length) {
      const result = await dispatchRollbackUninstall(current, runner, installed[installed.length - 1], 'rollback_failure_uninstall_running')
      return { id: current.id, state: result.dispatched ? 'running' : 'review_required' }
    }
    const result = await dispatchQualificationResidueCleanup(current, runner, {
      finalState: 'review_required',
      finalError: clean(evidence.rollbackFailureError || current.last_error || 'qualification_rollback_failed'),
      uninstallCompletedAt: clean(evidence.rollbackFailureUninstallCompletedAt),
    })
    return { id: current.id, state: result.dispatched ? 'cleanup_running' : 'review_required' }
  }

  if (stage === 'rollback_failure_uninstall_running') {
    const jobResult = await pool.query(
      `SELECT status,result,error_message,completed_at,created_at,claimed_at
         FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.agent_job_id],
    )
    const job = jobResult.rows[0]
    if (!job || ['queued','claimed'].includes(clean(job.status))) {
      if (rollbackJobTimedOut(job, evidence.rollbackUninstallDispatchedAt)) {
        await markReview(current.id, 'qualification_runtime_limit_exceeded', { stage })
        return { id: current.id, state: 'review_required' }
      }
      return { id: current.id, state: current.state }
    }
    const failure = terminalJobFailure(job) || (object(job.result).success === false ? clean(object(job.result).error || 'qualification_rollback_cleanup_uninstall_failed') : '')
    if (failure || clean(job.status) !== 'completed') {
      await markReview(current.id, failure || 'qualification_rollback_cleanup_uninstall_failed', { stage })
      return { id: current.id, state: 'review_required' }
    }
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, JSON.stringify({
        stage: 'rollback_failure_cleanup_pending',
        rollbackFailureUninstallCompletedAt: job.completed_at || new Date().toISOString(),
      })],
    )
    return { id: current.id, state: 'running' }
  }

  const pair = await upgradeReleasePair(current.catalogue_id)
  if (!pair.target || !pair.previous) {
    return rollbackFailureOrCleanup(current, runner, 'qualification_rollback_release_pair_lost', stage || 'rollback')
  }
  const targetVersion = clean(pair.target.release_version)
  const previousVersion = clean(pair.previous.release_version)

  if (stage === 'rollback_current_install_running'
    || stage === 'rollback_previous_install_running'
    || stage === 'rollback_restore_target_running') {
    const jobResult = await pool.query(
      `SELECT status,result,error_message,completed_at,created_at,claimed_at
         FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.agent_job_id],
    )
    const job = jobResult.rows[0]
    if (!job || ['queued','claimed'].includes(clean(job.status))) {
      if (rollbackJobTimedOut(job, evidence.dispatchedAt)) {
        return rollbackFailureOrCleanup(current, runner, 'qualification_runtime_limit_exceeded', stage)
      }
      return { id: current.id, state: current.state }
    }
    const failure = terminalJobFailure(job)
    const providerFailure = qualificationProviderFailure(job?.result)
    if (failure || providerFailure || clean(job.status) !== 'completed' || !verifiedPatchResult(job.result)) {
      if (current.deployment_id) {
        await pool.query(
          `UPDATE rmm_patch_deployments
              SET status=$2,result=COALESCE($3::jsonb,'{}'::jsonb),
                  completed_at=COALESCE(completed_at,now()),updated_at=now()
            WHERE id=$1`,
          [current.deployment_id, clean(job?.status) === 'cancelled' ? 'cancelled' : 'verification_failed', JSON.stringify(object(job?.result))],
        )
      }
      return rollbackFailureOrCleanup(current, runner, failure || providerFailure || 'qualification_rollback_verification_failed', stage)
    }

    if (current.deployment_id) {
      await pool.query(
        `UPDATE rmm_patch_deployments
            SET status='succeeded',result=$2::jsonb,
                completed_at=COALESCE(completed_at,$3,now()),updated_at=now()
          WHERE id=$1`,
        [current.deployment_id, JSON.stringify(object(job.result)), job.completed_at || null],
      )
    }

    if (stage === 'rollback_current_install_running') {
      await pool.query(
        `UPDATE rmm_software_qualification_queue
            SET evidence=evidence || $2::jsonb,updated_at=now()
          WHERE id=$1`,
        [current.id, JSON.stringify({
          stage: 'rollback_current_uninstall_pending',
          installCompletedAt: job.completed_at || new Date().toISOString(),
          rollbackCurrentInstallVerified: true,
          rollbackCurrentInstallVerifiedAt: job.completed_at || new Date().toISOString(),
          targetVersion,
          previousVersion,
        })],
      )
      return { id: current.id, state: 'running' }
    }

    if (stage === 'rollback_previous_install_running') {
      await pool.query(
        `UPDATE rmm_software_qualification_queue
            SET evidence=evidence || $2::jsonb,updated_at=now()
          WHERE id=$1`,
        [current.id, JSON.stringify({
          stage: 'rollback_restore_detection_pending',
          rollbackPreviousInstallVerified: true,
          rollbackPreviousInstallVerifiedAt: job.completed_at || new Date().toISOString(),
          rollbackPreviousInstallCompletedAt: job.completed_at || new Date().toISOString(),
          previousVersion,
          targetVersion,
        })],
      )
      return { id: current.id, state: 'running' }
    }

    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, JSON.stringify({
        stage: 'rollback_final_cleanup_pending',
        rollbackRestoreVerified: true,
        rollbackRestoreVerifiedAt: job.completed_at || new Date().toISOString(),
        rollbackRestoreCompletedAt: job.completed_at || new Date().toISOString(),
        targetVersion,
      })],
    )
    return { id: current.id, state: 'running' }
  }

  if (stage === 'rollback_current_uninstall_pending') {
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) return { id: current.id, state: current.state }
    const installed = installedMatches(runner.source_payload, current)
    const target = installed.find((item) => compareVersionish(clean(item?.version), targetVersion) === 0)
    if (target) {
      const result = await dispatchRollbackUninstall(current, runner, target, 'rollback_current_uninstall_running')
      return { id: current.id, state: result.dispatched ? 'running' : 'review_required' }
    }
    const completedAt = Date.parse(clean(evidence.rollbackCurrentInstallVerifiedAt || evidence.installCompletedAt))
    if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
      return rollbackFailureOrCleanup(current, runner, 'qualification_rollback_current_not_visible_in_inventory', stage)
    }
    return { id: current.id, state: current.state }
  }

  if (stage === 'rollback_current_uninstall_running' || stage === 'rollback_final_uninstall_running') {
    const jobResult = await pool.query(
      `SELECT status,result,error_message,completed_at,created_at,claimed_at
         FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.agent_job_id],
    )
    const job = jobResult.rows[0]
    if (!job || ['queued','claimed'].includes(clean(job.status))) {
      if (rollbackJobTimedOut(job, evidence.rollbackUninstallDispatchedAt)) {
        await markReview(current.id, 'qualification_runtime_limit_exceeded', { stage })
        return { id: current.id, state: 'review_required' }
      }
      return { id: current.id, state: current.state }
    }
    const result = object(job.result)
    const parsed = object(result.parsed)
    const removedVersion = clean(result.version || parsed.version)
    const removalReason = clean(result.reason || parsed.reason)
    const failure = terminalJobFailure(job) || (result.success === false ? clean(result.error || 'qualification_rollback_uninstall_failed') : '')
    if (failure || clean(job.status) !== 'completed') {
      return rollbackFailureOrCleanup(current, runner, failure || 'qualification_rollback_uninstall_failed', stage)
    }
    if (removalReason !== 'verified_removed' || compareVersionish(removedVersion, targetVersion) !== 0) {
      return rollbackFailureOrCleanup(current, runner, 'qualification_rollback_uninstall_version_not_verified', stage, {
        expectedVersion: targetVersion,
        removedVersion,
        removalReason,
      })
    }
    const nextStage = stage === 'rollback_current_uninstall_running'
      ? 'rollback_current_removal_pending'
      : 'rollback_final_removal_pending'
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, JSON.stringify({
        stage: nextStage,
        ...(stage === 'rollback_current_uninstall_running'
          ? { rollbackCurrentUninstallVerified: true, rollbackCurrentUninstallVerifiedAt: job.completed_at || new Date().toISOString() }
          : { rollbackFinalUninstallVerified: true, rollbackFinalUninstallVerifiedAt: job.completed_at || new Date().toISOString() }),
        rollbackUninstallCompletedAt: job.completed_at || new Date().toISOString(),
      })],
    )
    return { id: current.id, state: 'running' }
  }

  if (stage === 'rollback_current_removal_pending') {
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) return { id: current.id, state: current.state }
    const remaining = installedMatches(runner.source_payload, current)
    if (remaining.length) {
      const completedAt = Date.parse(clean(evidence.rollbackUninstallCompletedAt))
      if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
        return rollbackFailureOrCleanup(current, runner, 'qualification_rollback_current_uninstall_residue_detected', stage, {
          remaining: remaining.map((item) => ({ name: clean(item?.name), version: clean(item?.version), registryKey: clean(item?.registry_key) })),
        })
      }
      return { id: current.id, state: current.state }
    }
    const result = await dispatchUpgradeInstall(current, runner, pair.previous, {
      intent: 'install',
      installedVersion: '',
      stage: 'rollback_previous_install_running',
      qualificationTest: 'rollback',
      requestSource: 'catalogue_qualification_rollback',
      actorLabel: 'Catalogue rollback qualification',
    })
    return { id: current.id, state: result.dispatched ? 'running' : 'review_required' }
  }

  if (stage === 'rollback_restore_detection_pending') {
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) return { id: current.id, state: current.state }
    const installed = installedMatches(runner.source_payload, current)
    const previous = installed.find((item) => compareVersionish(clean(item?.version), previousVersion) === 0)

    if (!previous) {
      const baselineAt = Date.parse(clean(evidence.rollbackPreviousInstallCompletedAt))
      if (Number.isFinite(baselineAt) && Date.now() - baselineAt > 10 * 60 * 1000) {
        return rollbackFailureOrCleanup(current, runner, 'qualification_rollback_previous_not_visible_in_inventory', stage, {
          expectedPreviousVersion: previousVersion,
          targetVersion,
          observedMatches: installed.map((item) => ({ name: clean(item?.name), version: clean(item?.version), publisher: clean(item?.publisher) })),
        })
      }
      return { id: current.id, state: current.state }
    }

    const detected = previous
    const detectedVersion = clean(detected?.version)
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, JSON.stringify({
        rollbackPreviousInventoryVerified: true,
        rollbackPreviousInventoryVerifiedAt: new Date().toISOString(),
        rollbackRestorePatchDetectionVerified: true,
        rollbackRestorePatchDetectionStatus: 'update_available',
        rollbackRestorePatchDetectionInstalledVersion: detectedVersion,
        rollbackRestorePatchDetectionTargetVersion: targetVersion,
        rollbackRestorePatchDetectionVerifiedAt: new Date().toISOString(),
      })],
    )

    const result = await dispatchUpgradeInstall(current, runner, pair.target, {
      intent: 'update',
      installedVersion: detectedVersion || previousVersion,
      stage: 'rollback_restore_target_running',
      qualificationTest: 'rollback',
      requestSource: 'catalogue_qualification_rollback',
      actorLabel: 'Catalogue rollback qualification',
    })
    return { id: current.id, state: result.dispatched ? 'running' : 'review_required' }
  }

  if (stage === 'rollback_final_cleanup_pending') {
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) return { id: current.id, state: current.state }
    const installed = installedMatches(runner.source_payload, current)
    const target = installed.find((item) => compareVersionish(clean(item?.version), targetVersion) === 0)
    if (target) {
      const result = await dispatchRollbackUninstall(current, runner, target, 'rollback_final_uninstall_running')
      return { id: current.id, state: result.dispatched ? 'running' : 'review_required' }
    }
    const completedAt = Date.parse(clean(evidence.rollbackRestoreCompletedAt))
    if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
      return rollbackFailureOrCleanup(current, runner, 'qualification_rollback_restored_target_not_visible_in_inventory', stage)
    }
    return { id: current.id, state: current.state }
  }

  if (stage === 'rollback_final_removal_pending') {
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) return { id: current.id, state: current.state }
    const remaining = installedMatches(runner.source_payload, current)
    if (remaining.length) {
      const completedAt = Date.parse(clean(evidence.rollbackUninstallCompletedAt))
      if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
        return rollbackFailureOrCleanup(current, runner, 'qualification_rollback_final_uninstall_residue_detected', stage, {
          remaining: remaining.map((item) => ({ name: clean(item?.name), version: clean(item?.version), registryKey: clean(item?.registry_key) })),
        })
      }
      return { id: current.id, state: current.state }
    }
    const result = await dispatchQualificationResidueCleanup(current, runner, {
      finalState: 'passed',
      finalError: '',
      uninstallCompletedAt: clean(evidence.rollbackUninstallCompletedAt),
    })
    if (result.dispatched) {
      await pool.query(
        `UPDATE rmm_software_qualification_queue
            SET evidence=evidence || $2::jsonb,updated_at=now()
          WHERE id=$1`,
        [current.id, JSON.stringify({ stage: 'rollback_residue_cleanup' })],
      )
    }
    return { id: current.id, state: result.dispatched ? 'cleanup_running' : 'review_required' }
  }

  await markReview(current.id, 'qualification_rollback_unknown_stage', { stage })
  return { id: current.id, state: 'review_required' }
}

async function reconcileQueueRow(queue, runner) {
  const current = await qualificationRow(queue.id)
  if (!current) return { id: queue.id, state: 'missing' }

  if (current.state === 'running') {
    const jobResult = await pool.query(
      `SELECT status,result,error_message,completed_at FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.agent_job_id],
    )
    const job = jobResult.rows[0]
    if (!job || ['queued', 'claimed'].includes(clean(job.status))) return { id: current.id, state: current.state }
    const failure = terminalJobFailure(job)
    const providerFailure = qualificationProviderFailure(job.result)
    if (failure || providerFailure || clean(job.status) !== 'completed' || !verifiedPatchResult(job.result)) {
      if (current.deployment_id) {
        await pool.query(
          `UPDATE rmm_patch_deployments SET status=$2,result=COALESCE($3::jsonb,'{}'::jsonb),
              completed_at=COALESCE(completed_at,now()),updated_at=now() WHERE id=$1`,
          [current.deployment_id, clean(job.status) === 'cancelled' ? 'cancelled' : 'verification_failed', JSON.stringify(object(job?.result))],
        )
      }
      if (failure === 'qualification_runtime_limit_exceeded' && runner
        && clean(current.runner_agent_device_id) === clean(runner.agent_device_id)) {
        const installed=installedMatches(runner.source_payload,current)
        if (installed.length) {
          await pool.query(
            `UPDATE rmm_software_qualification_queue
                SET evidence=evidence || $2::jsonb,updated_at=now() WHERE id=$1`,
            [current.id,JSON.stringify({skipAfterTimeout:true,
              timeoutFinalError:failure,installCompletedAt:new Date().toISOString()})],
          )
          const dispatched=await dispatchUninstall(current,runner,installed[installed.length-1])
          return { id:current.id,state:dispatched.dispatched?'cleanup_running':'review_required' }
        }
      }
      if (windowsInstallerBusy(job)) {
        const requeued = await requeueWindowsInstallerBusy(current, 'install')
        if (requeued) return { id: current.id, state: 'queued', retry: 'windows_installer_busy' }
      }
      await markReview(current.id, failure || providerFailure || 'qualification_install_verification_failed', { stage: 'install' })
      return { id: current.id, state: 'review_required' }
    }

    if (current.deployment_id) {
      await pool.query(
        `UPDATE rmm_patch_deployments SET status='succeeded',result=$2::jsonb,
            completed_at=COALESCE(completed_at,$3,now()),updated_at=now() WHERE id=$1`,
        [current.deployment_id, JSON.stringify(object(job.result)), job.completed_at || null],
      )
    }
    const result = object(job.result)
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET state='cleanup_pending',last_error='',
              evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, JSON.stringify({
        stage: 'cleanup_pending',
        installCompletedAt: job.completed_at || new Date().toISOString(),
        verifiedVersion: clean(result.verifiedVersion || object(result.verification).installedVersion),
        installProvider: clean(result.provider),
      })],
    )
    return { id: current.id, state: 'cleanup_pending' }
  }
  if (current.state === 'cleanup_pending') {
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) {
      return { id: current.id, state: current.state }
    }
    let installed = installedMatches(runner.source_payload, current)
    if (!installed.length) {
      const learned = await learnVerifiedObservedIdentity(current, runner)
      if (learned.scopeMismatch) {
        await pool.query(
          `UPDATE rmm_software_qualification_queue
              SET evidence=evidence || $2::jsonb,updated_at=now()
            WHERE id=$1`,
          [current.id, JSON.stringify({
            postInstallScopeMismatch: true,
            expectedScope: 'machine',
            actualScope: clean(learned.item?.scope),
            actualUserProfile: clean(learned.item?.user_profile),
            observedScopeIdentity: {
              name: clean(learned.item?.name),
              publisher: clean(learned.item?.publisher),
              version: clean(learned.item?.version),
              registryKey: clean(learned.item?.registry_key),
            },
          })],
        )
        const dispatched = await dispatchUninstall(current, runner, learned.item)
        return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : 'cleanup_pending' }
      }
      if (learned.learned) {
        const refreshed = await qualificationRow(current.id)
        installed = refreshed ? installedMatches(runner.source_payload, refreshed) : []
        if (installed.length) {
          const dispatched = await dispatchUninstall(refreshed, runner, installed[installed.length - 1])
          return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : 'cleanup_pending' }
        }
      }
    }
    if (installed.length) {
      const dispatched = await dispatchUninstall(current, runner, installed[installed.length - 1])
      return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : 'cleanup_pending' }
    }
    const completedAt = Date.parse(clean(object(current.evidence).installCompletedAt))
    if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
      await markReview(current.id, 'qualification_install_not_visible_in_inventory', { stage: 'cleanup_pending' })
      return { id: current.id, state: 'review_required' }
    }
    return { id: current.id, state: current.state }
  }

  if (current.state === 'cleanup_running' && clean(object(current.evidence).cleanupPhase) === 'preclean') {
    const cleanupResult = await pool.query(
      `SELECT status,result,error_message,completed_at FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.cleanup_job_id],
    )
    const cleanup = cleanupResult.rows[0]
    if (!cleanup || ['queued', 'claimed'].includes(clean(cleanup.status))) {
      return { id: current.id, state: current.state }
    }

    const cleanupPayload = object(cleanup.result)
    const cleanupParsed = object(cleanupPayload.parsed)
    const cleanupReason = clean(cleanupPayload.reason || cleanupParsed.reason)
    const rebootRequired = cleanupPayload.reboot_required === true || cleanupParsed.reboot_required === true
    const failure = terminalJobFailure(cleanup)
    if (failure || clean(cleanup.status) !== 'completed') {
      const precleanError = rebootRequired
        ? 'qualification_preclean_reboot_required'
        : cleanupReason
          ? 'qualification_preclean_' + cleanupReason
          : failure || 'qualification_preclean_uninstall_failed'
      await markReview(current.id, precleanError, {
        stage: 'preclean',
        cleanupJobId: current.cleanup_job_id,
        uninstallReason: cleanupReason,
        rebootRequired,
      })
      return { id: current.id, state: 'review_required' }
    }

    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) {
      return { id: current.id, state: current.state }
    }

    const remaining = installedMatches(runner.source_payload, current)
    if (remaining.length) {
      const completedAt = Date.parse(clean(cleanup.completed_at))
      if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
        await markReview(current.id, 'qualification_preclean_residue_detected', {
          stage: 'preclean',
          remaining: remaining.map((item) => ({
            name: clean(item?.name),
            version: clean(item?.version),
            registryKey: clean(item?.registry_key),
          })),
        })
        return { id: current.id, state: 'review_required' }
      }
      return { id: current.id, state: current.state }
    }

    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET state='queued',runner_agent_device_id=NULL,cleanup_job_id=NULL,last_error='',
              started_at=NULL,completed_at=NULL,
              evidence=(evidence - 'cleanupPhase') || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [current.id, JSON.stringify({
        stage: 'preclean_verified',
        precleanVerifiedAt: new Date().toISOString(),
        precleanUninstallCompletedAt: cleanup.completed_at || new Date().toISOString(),
      })],
    )
    return { id: current.id, state: 'queued', precleanVerified: true }
  }

  if (current.state === 'cleanup_running') {
    const cleanupResult = await pool.query(
      `SELECT status,result,error_message,completed_at FROM rmm_agent_jobs WHERE id=$1 LIMIT 1`,
      [current.cleanup_job_id],
    )
    const cleanup = cleanupResult.rows[0]
    if (!cleanup || ['queued', 'claimed'].includes(clean(cleanup.status))) return { id: current.id, state: current.state }
    if (clean(object(current.evidence).cleanupPhase) === 'residue_cleanup') {
      return finalizeResidueCleanup(current, cleanup)
    }
    const failure = terminalJobFailure(cleanup)
    if (failure || clean(cleanup.status) !== 'completed') {
      if (runner && clean(current.runner_agent_device_id) === clean(runner.agent_device_id)
        && !installedMatches(runner.source_payload, current).length) {
        const dispatched = await dispatchQualificationResidueCleanup(current, runner, {
          finalState: 'review_required',
          finalError: failure || 'qualification_cleanup_failed',
          uninstallCompletedAt: cleanup.completed_at || '',
        })
        return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : current.state }
      }
      await markReview(current.id, failure || 'qualification_cleanup_failed', { stage: 'cleanup' })
      return { id: current.id, state: 'review_required' }
    }
    if (!runner || clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) {
      return { id: current.id, state: current.state }
    }
    const remaining = installedMatches(runner.source_payload, current)
    if (remaining.length) {
      const completedAt = Date.parse(clean(cleanup.completed_at))
      if (Number.isFinite(completedAt) && Date.now() - completedAt > 10 * 60 * 1000) {
        await markReview(current.id, 'qualification_uninstall_residue_detected', {
          stage: 'cleanup',
          remaining: remaining.map((item) => ({ name: clean(item?.name), version: clean(item?.version), registryKey: clean(item?.registry_key) })),
        })
        return { id: current.id, state: 'review_required' }
      }
      return { id: current.id, state: current.state }
    }

    const currentEvidence = object(current.evidence)
    const scopeMismatch = currentEvidence.postInstallScopeMismatch === true
    const timedOut = currentEvidence.skipAfterTimeout === true
    const adminCleanupOnly = currentEvidence.adminCleanupOnly === true
    const adminCancelRequested = currentEvidence.adminCancelRequested === true
    const finalState = (adminCleanupOnly || adminCancelRequested)
      ? 'cancelled'
      : (scopeMismatch || timedOut) ? 'review_required' : 'passed'
    const finalError = adminCleanupOnly
      ? 'admin_cleanup_completed'
      : adminCancelRequested
        ? 'admin_cancelled_after_cleanup'
        : timedOut
          ? 'qualification_runtime_limit_exceeded'
          : scopeMismatch ? 'qualification_scope_mismatch' : ''
    const dispatched = await dispatchQualificationResidueCleanup(current, runner, {
      finalState,
      finalError,
      uninstallCompletedAt: cleanup.completed_at || '',
    })
    return { id: current.id, state: dispatched.dispatched ? 'cleanup_running' : current.state }
  }

  return { id: current.id, state: current.state }
}

export async function resetStaleQualificationQueuesForCurrentTargets({ limit = 100 } = {}) {
  const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100))
  const result = await pool.query(
    `WITH stale AS (
       SELECT q.id
         FROM rmm_software_qualification_queue q
         JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
        WHERE c.tenant_id IS NULL
          AND c.status='active'
          AND c.qualification_state='deployment_candidate'
          AND q.state IN ('queued','passed','review_required')
          AND (
            (
              q.test_type='clean_install'
              AND (
                (
                  COALESCE(q.evidence->>'targetVersion','')<>''
                  AND q.evidence->>'targetVersion'<>c.target_version
                )
                OR (
                  COALESCE(q.evidence->>'targetVersion','')=''
                  AND COALESCE(c.qualification_evidence->>'cleanInstallVersion','')<>''
                  AND c.qualification_evidence->>'cleanInstallVersion'<>c.target_version
                )
              )
            )
            OR (
              q.test_type='upgrade'
              AND (
                (
                  COALESCE(c.qualification_evidence->>'upgradeVersion','')<>''
                  AND c.qualification_evidence->>'upgradeVersion'<>c.target_version
                )
                OR (
                  COALESCE(c.qualification_evidence->>'upgradePatchDetectionTargetVersion','')<>''
                  AND c.qualification_evidence->>'upgradePatchDetectionTargetVersion'<>c.target_version
                )
                OR (
                  COALESCE(q.evidence->>'targetVersion','')<>''
                  AND q.evidence->>'targetVersion'<>c.target_version
                )
              )
            )
            OR (
              q.test_type='rollback'
              AND (
                (
                  COALESCE(c.qualification_evidence->>'rollbackRestoredVersion','')<>''
                  AND c.qualification_evidence->>'rollbackRestoredVersion'<>c.target_version
                )
                OR (
                  COALESCE(q.evidence->>'targetVersion','')<>''
                  AND q.evidence->>'targetVersion'<>c.target_version
                )
              )
            )
          )
        ORDER BY q.updated_at
        LIMIT $1
     )
     UPDATE rmm_software_qualification_queue q
        SET state='cancelled',
            last_error='qualification_target_version_changed',
            runner_agent_device_id=NULL,
            agent_job_id=NULL,
            deployment_id=NULL,
            cleanup_job_id=NULL,
            evidence=q.evidence || jsonb_build_object(
              'targetVersionChangedAt',now()
            ),
            started_at=NULL,
            completed_at=now(),
            updated_at=now()
       FROM stale
      WHERE q.id=stale.id
      RETURNING q.id,q.catalogue_id,q.test_type,q.state`,
    [safeLimit],
  )
  return result.rows
}

export async function queueCommonSoftwareQualifications({ limit = 50, allowUnresolvedVulnerability = true } = {}) {
  const safeLimit = Math.max(1, Math.min(COMMON_WINDOWS_SOFTWARE_LOWER.length, Number(limit) || 50))
  const result = await pool.query(
    `WITH candidates AS (
       SELECT c.id AS catalogue_id,c.canonical_name,
              2000-array_position($1::text[],lower(c.canonical_name)) AS priority
         FROM rmm_software_catalogue c
         JOIN rmm_software_vendor_sources s
           ON s.source_key=c.source_metadata->>'latestSource' AND s.enabled=true
         JOIN rmm_software_vendor_releases r
           ON r.provider_package_id=c.external_key
          AND r.source_key=c.source_metadata->>'latestSource'
          AND r.version=c.target_version
        WHERE c.tenant_id IS NULL
          AND c.status='active'
          AND c.qualification_state='deployment_candidate'
          AND lower(c.canonical_name)=ANY($1::text[])
          AND c.source_metadata->>'deploymentMode' IN ('vendor_direct','winget_preferred')
          AND c.source_metadata->>'trustState'='direct_ready'
          AND lower(COALESCE(c.installer_type,'')) IN ('msi','exe')
          AND COALESCE(c.target_version,'')<>''
          AND c.target_version !~* '(alpha|beta|rc|preview|eap|nightly|dev|canary)'
          AND s.last_success_at IS NOT NULL
          AND COALESCE(s.last_error,'')=''
          AND r.trust_state='direct_ready'
          AND lower(COALESCE(r.source_payload->'wingetManifest'->>'scope',''))<>'user'
          AND r.installer_type IN ('msi','exe')
          AND r.installer_url LIKE 'https://%'
          AND r.installer_sha256 ~* '^[a-f0-9]{64}$'
          AND COALESCE(
            NULLIF(c.source_metadata->>'expectedSigner',''),
            NULLIF(r.source_payload->>'expectedSigner',''),
            NULLIF(r.trust_evidence->>'signer','')
          ) IS NOT NULL
          AND c.qualification_evidence->>'vendorReleaseId'=r.id::text
          AND c.qualification_evidence->>'artifactVerificationVersion'=c.target_version
          AND lower(COALESCE(c.qualification_evidence->>'sha256Verified','false'))='true'
          AND lower(COALESCE(c.qualification_evidence->>'authenticodeVerified','false'))='true'
          AND (
            $3::boolean
            OR (
              c.source_metadata->'vulnerabilityIdentityAudit'->>'state'='covered'
              AND EXISTS (
                SELECT 1
                  FROM rmm_software_vulnerability_identities vi
                 WHERE vi.catalogue_id=c.id AND vi.enabled=true
              )
            )
            OR c.source_metadata->'vulnerabilityIdentityAudit'->>'state'='no_published_identity'
          )
          AND NOT EXISTS (
            SELECT 1
              FROM rmm_software_qualification_queue q
             WHERE q.catalogue_id=c.id
               AND q.test_type='clean_install'
               AND NOT (
                 (
                   q.state='review_required'
                   AND q.last_error IN (
                     'qualification_direct_release_not_ready',
                     'qualification_artifact_gate_failed',
                     'qualification_source_health_not_ready',
                     'PatchHost did not return a result.',
                     'telemetry HTTP status 502'
                   )
                 )
                 OR (
                   q.state='cancelled'
                   AND q.last_error='qualification_target_version_changed'
                 )
               )
          )
        ORDER BY priority DESC,lower(c.canonical_name)
        LIMIT $2
     )
     INSERT INTO rmm_software_qualification_queue
       (catalogue_id,test_type,state,priority,attempt_count,last_error,evidence,created_at,updated_at)
     SELECT catalogue_id,'clean_install','queued',priority,0,'',
            jsonb_build_object(
              'automaticCleanInstallQualification',true,
              'qualificationCohort','business_essentials',
              'businessPriority',true,
              'vendorArtifactRequired',true,
              'wingetQualificationAllowed',true,
              'queuedAt',now()
            ),
            now(),now()
       FROM candidates
     ON CONFLICT (catalogue_id,test_type)
     DO UPDATE SET
       state='queued',
       priority=EXCLUDED.priority,
       attempt_count=0,
       runner_agent_device_id=NULL,
       agent_job_id=NULL,
       deployment_id=NULL,
       cleanup_job_id=NULL,
       last_error='',
       evidence=(rmm_software_qualification_queue.evidence || EXCLUDED.evidence)
         || jsonb_build_object('businessRetryAt',now()),
       started_at=NULL,
       completed_at=NULL,
       updated_at=now()
     WHERE (
       rmm_software_qualification_queue.state='review_required'
       AND rmm_software_qualification_queue.last_error IN (
         'qualification_direct_release_not_ready',
         'qualification_artifact_gate_failed',
         'qualification_source_health_not_ready',
         'PatchHost did not return a result.',
         'telemetry HTTP status 502'
       )
     ) OR (
       rmm_software_qualification_queue.state='cancelled'
       AND rmm_software_qualification_queue.last_error='qualification_target_version_changed'
     )
     RETURNING id,catalogue_id,test_type,state,priority`,
    [COMMON_WINDOWS_SOFTWARE_LOWER, safeLimit, Boolean(allowUnresolvedVulnerability)],
  )
  return result.rows
}

export async function queueAutomaticCleanInstallQualifications({
  limit = 2000,
  allowUnresolvedVulnerability = true,
} = {}) {
  const safeLimit = Math.max(1, Math.min(5000, Number(limit) || 2000))

  const result = await pool.query(
    `WITH candidates AS (
       SELECT c.id AS catalogue_id,c.canonical_name,
              CASE
                WHEN lower(c.canonical_name)='google chrome' THEN 350
                WHEN lower(c.canonical_name)='microsoft edge' THEN 345
                WHEN lower(c.canonical_name)='adobe acrobat reader' THEN 340
                WHEN lower(c.canonical_name)='mozilla firefox' THEN 335
                WHEN lower(c.canonical_name)='7-zip' THEN 330
                WHEN lower(c.canonical_name) LIKE 'microsoft teams%' THEN 325
                WHEN lower(c.canonical_name) LIKE 'zoom%' THEN 320
                WHEN lower(c.canonical_name)='vlc media player' THEN 315
                WHEN lower(c.canonical_name)='notepad++' THEN 310
                WHEN lower(COALESCE(c.installer_type,''))='msi' THEN 110
                ELSE 100
              END AS priority
         FROM rmm_software_catalogue c
         JOIN rmm_software_vendor_sources s
           ON s.source_key=c.source_metadata->>'latestSource' AND s.enabled=true
         JOIN rmm_software_vendor_releases r
           ON r.provider_package_id=c.external_key
          AND r.source_key=c.source_metadata->>'latestSource'
          AND r.version=c.target_version
        WHERE c.tenant_id IS NULL
          AND c.status='active'
          AND c.qualification_state='deployment_candidate'
          AND c.source_metadata->>'deploymentMode' IN ('vendor_direct','winget_preferred')
          AND c.source_metadata->>'trustState'='direct_ready'
          AND lower(COALESCE(c.installer_type,'')) IN ('msi','exe')
          AND COALESCE(c.target_version,'')<>''
          AND c.target_version !~* '(alpha|beta|rc|preview|eap|nightly|dev|canary)'
          AND s.last_success_at IS NOT NULL
          AND COALESCE(s.last_error,'')=''
          AND r.trust_state='direct_ready'
          AND lower(COALESCE(r.source_payload->'wingetManifest'->>'scope',''))<>'user'
          AND r.installer_type IN ('msi','exe')
          AND r.installer_url LIKE 'https://%'
          AND r.installer_sha256 ~* '^[a-f0-9]{64}$'
          AND COALESCE(
            NULLIF(c.source_metadata->>'expectedSigner',''),
            NULLIF(r.source_payload->>'expectedSigner',''),
            NULLIF(r.trust_evidence->>'signer','')
          ) IS NOT NULL
          AND c.qualification_evidence->>'vendorReleaseId'=r.id::text
          AND c.qualification_evidence->>'artifactVerificationVersion'=c.target_version
          AND lower(COALESCE(c.qualification_evidence->>'sha256Verified','false'))='true'
          AND lower(COALESCE(c.qualification_evidence->>'authenticodeVerified','false'))='true'
          AND (
            $2::boolean
            OR (
              c.source_metadata->'vulnerabilityIdentityAudit'->>'state'='covered'
              AND EXISTS (
                SELECT 1
                  FROM rmm_software_vulnerability_identities vi
                 WHERE vi.catalogue_id=c.id AND vi.enabled=true
              )
            )
            OR c.source_metadata->'vulnerabilityIdentityAudit'->>'state'='no_published_identity'
          )
          AND NOT EXISTS (
            SELECT 1
              FROM rmm_software_qualification_queue existing
             WHERE existing.catalogue_id=c.id
               AND existing.test_type='clean_install'
               AND NOT (
                 (
                   existing.state='review_required'
                   AND existing.last_error IN (
                     'qualification_artifact_gate_failed',
                     'qualification_source_health_not_ready'
                   )
                 )
                 OR (
                   existing.state='cancelled'
                   AND existing.last_error IN (
                     'manual_revalidation_reset',
                     'qualification_pipeline_paused_for_progression_fix',
                     'completion_first_pipeline_superseded_clean_buffer',
                     'qualification_target_version_changed'
                   )
                 )
               )
          )
        ORDER BY priority DESC,lower(c.canonical_name)
        LIMIT $1
     )
     INSERT INTO rmm_software_qualification_queue
       (catalogue_id,test_type,state,priority,attempt_count,last_error,evidence,created_at,updated_at)
     SELECT catalogue_id,'clean_install','queued',priority,0,'',
            jsonb_build_object(
              'automaticCleanInstallQualification',true,
              'queuedAt',now()
            ),
            now(),now()
       FROM candidates
     ON CONFLICT (catalogue_id,test_type)
     DO UPDATE SET
       state='queued',
       priority=EXCLUDED.priority,
       attempt_count=0,
       runner_agent_device_id=NULL,
       agent_job_id=NULL,
       deployment_id=NULL,
       cleanup_job_id=NULL,
       last_error='',
       evidence=rmm_software_qualification_queue.evidence || EXCLUDED.evidence
         || jsonb_build_object('recoveredGateAt',now()),
       started_at=NULL,
       completed_at=NULL,
       updated_at=now()
     WHERE (
       rmm_software_qualification_queue.state='review_required'
       AND rmm_software_qualification_queue.last_error IN (
         'qualification_artifact_gate_failed',
         'qualification_source_health_not_ready'
       )
     ) OR (
       rmm_software_qualification_queue.state='cancelled'
       AND rmm_software_qualification_queue.last_error IN (
         'manual_revalidation_reset',
         'qualification_pipeline_paused_for_progression_fix',
         'completion_first_pipeline_superseded_clean_buffer',
         'qualification_target_version_changed'
       )
     )
     RETURNING id,catalogue_id,test_type,state,priority`,
    [safeLimit, Boolean(allowUnresolvedVulnerability)],
  )
  return result.rows
}

export async function queueAutomaticUpgradeQualifications({ limit = 12, allowCleanOnly = false } = {}) {
  const safeLimit = Math.max(1, Math.min(50, Number(limit) || 12))
  const result = await pool.query(
    `WITH candidates AS (
       SELECT c.id AS catalogue_id,c.canonical_name,c.target_version,q.priority
         FROM rmm_software_catalogue c
         JOIN rmm_software_qualification_queue q
           ON q.catalogue_id=c.id
          AND q.test_type='clean_install'
          AND q.state='passed'
        WHERE c.tenant_id IS NULL
          AND c.status='active'
          AND c.qualification_state IN ('deployment_candidate','qualified','qualified_limited')
          AND c.source_metadata->>'deploymentMode' IN ('vendor_direct','winget_preferred')
          AND c.source_metadata->>'trustState'='direct_ready'
          AND lower(COALESCE(c.qualification_evidence->>'cleanInstallVerified','false'))='true'
          AND c.qualification_evidence->>'cleanInstallVersion'=c.target_version
          AND lower(COALESCE(c.qualification_evidence->>'uninstallVerified','false'))='true'
          AND ($2::boolean OR COALESCE(q.evidence->>'manualQualificationMode','')<>'clean_only')
          AND EXISTS (
            SELECT 1
              FROM rmm_software_vendor_releases current_release
             WHERE current_release.provider_package_id=c.external_key
               AND current_release.source_key=c.source_metadata->>'latestSource'
               AND current_release.version=c.target_version
               AND current_release.trust_state='direct_ready'
          )
          AND EXISTS (
            SELECT 1
              FROM rmm_software_vendor_releases previous_release
             WHERE previous_release.provider_package_id=c.external_key
               AND previous_release.source_key=c.source_metadata->>'latestSource'
               AND previous_release.version<>c.target_version
               AND previous_release.trust_state='direct_ready'
          )
          AND NOT EXISTS (
            SELECT 1
              FROM rmm_software_qualification_queue existing_upgrade
             WHERE existing_upgrade.catalogue_id=c.id
               AND existing_upgrade.test_type='upgrade'
               AND existing_upgrade.state IN ('queued','running','cleanup_pending','cleanup_running','passed')
          )
        ORDER BY q.priority DESC,lower(c.canonical_name)
        LIMIT $1
     )
     INSERT INTO rmm_software_qualification_queue
       (catalogue_id,test_type,state,priority,attempt_count,last_error,evidence,created_at,updated_at)
     SELECT catalogue_id,'upgrade','queued',priority,0,'',
            jsonb_build_object(
              'automaticUpgradeQualification',true,
              'targetVersion',target_version,
              'queuedAt',now()
            ),
            now(),now()
       FROM candidates
     ON CONFLICT (catalogue_id,test_type)
     DO UPDATE SET
       state='queued',
       priority=EXCLUDED.priority,
       attempt_count=0,
       runner_agent_device_id=NULL,
       agent_job_id=NULL,
       deployment_id=NULL,
       cleanup_job_id=NULL,
       last_error='',
       evidence=(rmm_software_qualification_queue.evidence
         - 'stage'
         - 'baselineInstallCompletedAt'
         - 'upgradePatchDetectionVerified'
         - 'upgradePatchDetectionStatus'
         - 'upgradePatchDetectionInstalledVersion'
         - 'upgradePatchDetectionTargetVersion'
         - 'upgradePatchDetectionVerifiedAt'
         - 'upgradePatchDetectionIdentity') || EXCLUDED.evidence,
       started_at=NULL,
       completed_at=NULL,
       updated_at=now()
     WHERE (
       rmm_software_qualification_queue.state='review_required'
       AND rmm_software_qualification_queue.last_error IN (
         'previous_trusted_release_not_available',
         'qualification_current_trusted_release_not_available'
       )
     ) OR (
       rmm_software_qualification_queue.state='cancelled'
       AND rmm_software_qualification_queue.last_error IN (
         'manual_revalidation_reset',
         'qualification_target_version_changed'
       )
     )
     RETURNING id,catalogue_id,test_type,state,priority`,
    [safeLimit, Boolean(allowCleanOnly)],
  )
  return result.rows
}

export async function queueAutomaticRollbackQualifications({ limit = 8 } = {}) {
  const safeLimit = Math.max(1, Math.min(25, Number(limit) || 8))
  const result = await pool.query(
    `SELECT c.id AS catalogue_id,c.canonical_name,qu.priority
       FROM rmm_software_catalogue c
       JOIN rmm_software_qualification_queue qi
         ON qi.catalogue_id=c.id
        AND qi.test_type='clean_install'
        AND qi.state='passed'
       JOIN rmm_software_qualification_queue qu
         ON qu.catalogue_id=c.id
        AND qu.test_type='upgrade'
        AND qu.state='passed'
      WHERE c.tenant_id IS NULL
        AND c.status='active'
        AND c.qualification_state IN ('deployment_candidate','qualified','qualified_limited')
        AND lower(COALESCE(c.qualification_evidence->>'cleanInstallVerified','false'))='true'
        AND c.qualification_evidence->>'cleanInstallVersion'=c.target_version
        AND lower(COALESCE(c.qualification_evidence->>'uninstallVerified','false'))='true'
        AND lower(COALESCE(c.qualification_evidence->>'upgradeVerified','false'))='true'
        AND c.qualification_evidence->>'upgradeVersion'=c.target_version
        AND lower(COALESCE(c.qualification_evidence->>'upgradePatchDetectionVerified','false'))='true'
        AND c.qualification_evidence->>'upgradePatchDetectionTargetVersion'=c.target_version
        AND NOT EXISTS (
          SELECT 1
            FROM rmm_software_qualification_queue qr
           WHERE qr.catalogue_id=c.id
             AND qr.test_type='rollback'
             AND qr.state IN ('queued','running','cleanup_pending','cleanup_running','passed','review_required')
        )
      ORDER BY qu.priority DESC,lower(c.canonical_name)
      LIMIT $1`,
    [safeLimit],
  )
  const queued = []
  for (const row of result.rows) {
    const outcome = await queueRollbackQualification(row.catalogue_id)
    if (outcome?.queued) {
      await pool.query(
        `UPDATE rmm_software_qualification_queue
            SET evidence=evidence || jsonb_build_object(
                  'automaticRollbackQualification',true,
                  'pipelineQueuedAt',now()
                ),
                updated_at=now()
          WHERE catalogue_id=$1 AND test_type='rollback'`,
        [row.catalogue_id],
      )
      queued.push(outcome)
    }
  }
  return queued
}

export async function promoteAutomaticAdmissionReady({ limit = 12 } = {}) {
  const safeLimit = Math.max(1, Math.min(50, Number(limit) || 12))
  const result = await pool.query(
    `WITH candidates AS (
       SELECT c.id,c.canonical_name,c.target_version,c.qualification_state,
              c.source_metadata,c.qualification_evidence,
              s.metadata AS source_live_metadata,
              (
                c.source_metadata->'vulnerabilityIdentityAudit'->>'state'='covered'
                AND EXISTS (
                  SELECT 1
                    FROM rmm_software_vulnerability_identities vi
                   WHERE vi.catalogue_id=c.id AND vi.enabled=true
                )
              ) AS vulnerability_covered,
              COALESCE(c.source_metadata->'vulnerabilityIdentityAudit'->>'state','') AS vulnerability_audit_state,
              COALESCE(c.source_metadata->'vulnerabilityIdentityAudit'->>'method','') AS vulnerability_audit_method,
              COALESCE(c.source_metadata->'vulnerabilityIdentityAudit'->>'error','') AS vulnerability_audit_error,
              (
                c.source_metadata->'vulnerabilityIdentityAudit'->>'state'='no_published_identity'
                OR (
                  c.source_metadata->'vulnerabilityIdentityAudit'->>'state'='needs_review'
                  AND COALESCE(c.source_metadata->'vulnerabilityIdentityAudit'->>'error','')=''
                  AND COALESCE(c.source_metadata->'vulnerabilityIdentityAudit'->>'method','')<>'transient_identity_source_error'
                )
              ) AS vulnerability_limited,
              (
                s.metadata->>'baselinePreparationState'='previous_stable_installer_unavailable'
                AND s.metadata->>'baselinePreparationTargetVersion'=c.target_version
              ) AS history_limited,
              EXISTS (
                SELECT 1
                  FROM rmm_software_qualification_queue qi
                 WHERE qi.catalogue_id=c.id
                   AND qi.test_type='clean_install'
                   AND qi.state='passed'
              ) AS clean_queue_passed,
              EXISTS (
                SELECT 1
                  FROM rmm_software_qualification_queue qu
                 WHERE qu.catalogue_id=c.id
                   AND qu.test_type='upgrade'
                   AND qu.state='passed'
                   AND lower(COALESCE(c.qualification_evidence->>'upgradeVerified','false'))='true'
                   AND c.qualification_evidence->>'upgradeVersion'=c.target_version
                   AND lower(COALESCE(c.qualification_evidence->>'upgradePatchDetectionVerified','false'))='true'
                   AND c.qualification_evidence->>'upgradePatchDetectionTargetVersion'=c.target_version
              ) AS upgrade_passed,
              EXISTS (
                SELECT 1
                  FROM rmm_software_qualification_queue qrq
                 WHERE qrq.catalogue_id=c.id
                   AND qrq.test_type='rollback'
                   AND qrq.state='passed'
                   AND lower(COALESCE(c.qualification_evidence->>'rollbackVerified','false'))='true'
                   AND c.qualification_evidence->>'rollbackRestoredVersion'=c.target_version
              ) AS rollback_passed,
              EXISTS (
                SELECT 1
                  FROM rmm_patch_deployments d
                  JOIN rmm_agent_devices a
                    ON a.inventory_id=d.inventory_id AND a.disabled_at IS NULL
                  JOIN rmm_software_vendor_qualification_runners qr
                    ON qr.agent_device_id=a.id AND qr.enabled=true
                 WHERE d.catalogue_id=c.id
                   AND d.status='succeeded'
                   AND d.target_version=c.target_version
                   AND lower(COALESCE(d.result->>'verificationPassed',d.result->'verification'->>'meetsTarget','false'))='true'
                   AND COALESCE(
                     NULLIF(d.result->>'intent',''),
                     CASE WHEN COALESCE(d.installed_version,'')='' THEN 'install' ELSE 'update' END
                   )='update'
              ) AS verified_update_deployment
         FROM rmm_software_catalogue c
         JOIN rmm_software_vendor_sources s
           ON s.source_key=c.source_metadata->>'latestSource' AND s.enabled=true
         JOIN rmm_software_vendor_releases r
           ON r.provider_package_id=c.external_key
          AND r.source_key=c.source_metadata->>'latestSource'
          AND r.version=c.target_version
        WHERE c.tenant_id IS NULL
          AND c.status='active'
          AND c.qualification_state IN ('deployment_candidate','qualified_limited')
          AND c.source_metadata->>'deploymentMode' IN ('vendor_direct','winget_preferred')
          AND c.source_metadata->>'trustState'='direct_ready'
          AND lower(COALESCE(c.installer_type,'')) IN ('msi','exe')
          AND s.last_success_at IS NOT NULL
          AND COALESCE(s.last_error,'')=''
          AND r.trust_state='direct_ready'
          AND c.qualification_evidence->>'vendorReleaseId'=r.id::text
          AND c.qualification_evidence->>'artifactVerificationVersion'=c.target_version
          AND lower(COALESCE(c.qualification_evidence->>'sha256Verified','false'))='true'
          AND lower(COALESCE(c.qualification_evidence->>'authenticodeVerified','false'))='true'
          AND lower(COALESCE(c.qualification_evidence->>'cleanInstallVerified','false'))='true'
          AND c.qualification_evidence->>'cleanInstallVersion'=c.target_version
          AND lower(COALESCE(c.qualification_evidence->>'uninstallVerified','false'))='true'
        ORDER BY lower(c.canonical_name)
        LIMIT $1
     ),
     ready AS (
       SELECT *,
              CASE
                WHEN clean_queue_passed THEN 'qualified'
                ELSE ''
              END AS admission_state,
              jsonb_build_object(
                'cleanInstall','verified',
                'uninstall','verified',
                'upgrade',CASE
                  WHEN history_limited THEN 'unavailable_upstream'
                  WHEN upgrade_passed AND verified_update_deployment THEN 'verified'
                  ELSE 'pending'
                END,
                'rollback',CASE
                  WHEN history_limited THEN 'unavailable_upstream'
                  WHEN rollback_passed THEN 'verified'
                  ELSE 'pending'
                END,
                'vulnerabilityCoverage',CASE
                  WHEN vulnerability_covered THEN 'covered'
                  WHEN vulnerability_limited AND vulnerability_audit_state='no_published_identity' THEN 'no_published_identity'
                  WHEN vulnerability_limited THEN 'identity_unresolved'
                  ELSE 'pending'
                END
              ) AS capabilities,
              jsonb_strip_nulls(jsonb_build_object(
                'historicalInstaller',CASE WHEN history_limited THEN jsonb_build_object(
                  'state','unavailable_upstream',
                  'reason',COALESCE(source_live_metadata->>'baselinePreparationReason','historical_artifact_not_retrievable'),
                  'previousVersion',COALESCE(source_live_metadata->>'baselinePreparationPreviousVersion','')
                ) ELSE NULL END,
                'vulnerabilityIdentity',CASE WHEN vulnerability_limited THEN jsonb_build_object(
                  'state',CASE
                    WHEN vulnerability_audit_state='no_published_identity' THEN 'no_published_identity'
                    ELSE 'identity_unresolved'
                  END,
                  'auditState',vulnerability_audit_state,
                  'method',vulnerability_audit_method,
                  'note',COALESCE(
                    NULLIF(source_metadata->'vulnerabilityIdentityAudit'->>'dispositionNote',''),
                    NULLIF(source_metadata->>'vulnerabilityIdentityNote',''),
                    CASE
                      WHEN vulnerability_audit_state='needs_review'
                        THEN 'No unambiguous authoritative vulnerability identity is currently available; NVD/CVE/EPSS coverage remains limited until identity resolution succeeds.'
                      ELSE ''
                    END
                  )
                ) ELSE NULL END
              )) AS limitations
         FROM candidates
     )
     UPDATE rmm_software_catalogue c
        SET qualification_state=ready.admission_state,
            qualification_version=c.target_version,
            qualified_at=now(),
            qualification_notes=CASE
              WHEN COALESCE(c.qualification_notes,'')='' OR c.qualification_state='qualified_limited'
                THEN 'Automatically admitted after trusted current artifact, current-version install verification, and verified uninstall/cleanup.'
              ELSE c.qualification_notes
            END,
            qualification_evidence=c.qualification_evidence || jsonb_build_object(
              'automaticAdmissionVerified',true,
              'automaticAdmissionState',ready.admission_state,
              'automaticAdmissionVersion',c.target_version,
              'automaticAdmissionVerifiedAt',now(),
              'qualificationCapabilities',ready.capabilities,
              'qualificationLimitations',ready.limitations
            ),
            updated_at=now()
       FROM ready
      WHERE c.id=ready.id
        AND ready.admission_state<>''
      RETURNING c.id,c.canonical_name,c.target_version,c.qualification_state,
                c.qualification_evidence->'qualificationCapabilities' AS capabilities,
                c.qualification_evidence->'qualificationLimitations' AS limitations`,
    [safeLimit],
  )
  return result.rows
}
// Only release a qualification lane after endpoint control confirms its PatchHost
// process tree has stopped. A database-only timeout can leave an installer running.
async function stopOverlongQualificationJobs() {
  const rows = await pool.query(
    `SELECT q.id,q.runner_agent_device_id AS agent_device_id,q.agent_job_id,q.started_at,
            j.tenant_id,j.status AS job_status
       FROM rmm_software_qualification_queue q
       JOIN rmm_agent_jobs j ON j.id=q.agent_job_id
      WHERE q.state='running'
        AND j.job_type='patch.software'
        AND j.status='claimed'
        AND COALESCE(j.claimed_at,j.created_at)<now()-interval '10 minutes'
      ORDER BY q.started_at LIMIT 3`,
  )
  for (const row of rows.rows) {
    const controls = await pool.query(
      `SELECT id,status,result,error_message FROM rmm_agent_jobs
        WHERE agent_device_id=$1 AND job_type='custom.command'
          AND request_metadata->>'source'='qualification_runtime_limit'
          AND request_metadata->>'qualification_job_id'=$2
        ORDER BY created_at DESC LIMIT 1`,
      [row.agent_device_id,row.agent_job_id],
    )
    const control=controls.rows[0]
    if (!control) {
      const id=clean(row.agent_job_id)
      if (!/^[a-f0-9-]{36}$/i.test(id)) continue
      const command=[
        "$ErrorActionPreference='Stop'",
        "$needle='"+id+".manifest.dpapi'",
        "$matches=@(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'Hi5CentralPatchHost.exe' -and $_.CommandLine -like ('*'+$needle+'*') })",
        "foreach($process in $matches){& taskkill.exe /T /F /PID $process.ProcessId | Out-Null; if($LASTEXITCODE -ne 0){throw 'targeted_patchhost_stop_failed'}}",
        "if($matches.Count -eq 0){'NO_MATCH'}else{'STOPPED '+$matches.Count}",
      ].join('; ')
      await pool.query(
        `INSERT INTO rmm_agent_jobs
          (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
         VALUES ($1,$2,'custom.command',$3::jsonb,'system','Qualification time limit',$4::jsonb)`,
        [row.tenant_id,row.agent_device_id,
          JSON.stringify({command,timeout_seconds:30}),
          JSON.stringify({source:'qualification_runtime_limit',emergencyWebsocketDispatch:true,
            qualification_job_id:id,qualification_queue_id:row.id})],
      )
      continue
    }
    if (control.status !== 'completed' || !/^(NO_MATCH|STOPPED)/.test(clean(object(control.result).output))) {
      if (control.status === 'failed') {
        await pool.query(
          `UPDATE rmm_software_qualification_queue
             SET last_error='qualification_timeout_control_failed',updated_at=now()
            WHERE id=$1 AND state='running'`,[row.id],
        )
      }
      continue
    }
    await pool.query(
      `UPDATE rmm_agent_jobs
          SET status='failed',error_message='qualification_runtime_limit_exceeded',
              result=jsonb_build_object('success',false,'error','qualification_runtime_limit_exceeded',
                'controlJobId',$2::text,'limitSeconds',600),
              completed_at=now(),updated_at=now()
        WHERE id=$1 AND status='claimed'`,
      [row.agent_job_id,control.id],
    )
  }
}

async function dispatchEmergencyAgentControlJobs({ limit = 3 } = {}) {
  const pending = await pool.query(
    `SELECT id,agent_device_id,job_type,payload,created_at
       FROM rmm_agent_jobs
      WHERE status='queued'
        AND job_type='custom.command'
        AND request_metadata->>'emergencyWebsocketDispatch'='true'
      ORDER BY created_at
      LIMIT $1`,
    [Math.max(1, Math.min(10, Number(limit) || 3))],
  )
  const dispatched = []
  for (const row of pending.rows) {
    const socket = agentSocketForDevice(row.agent_device_id)
    if (!socket || socket.readyState !== 1) continue
    const claimed = await pool.query(
      `UPDATE rmm_agent_jobs
          SET status='claimed',claimed_at=now(),updated_at=now()
        WHERE id=$1 AND status='queued'
        RETURNING id,agent_device_id,job_type,payload,created_at`,
      [row.id],
    )
    if (!claimed.rowCount) continue
    const job = claimed.rows[0]
    const pushed = sendAgentMessage(job.agent_device_id, {
      type: 'job_execute',
      job: {
        id: job.id,
        job_type: job.job_type,
        payload: job.payload,
        created_at: job.created_at,
      },
    })
    if (!pushed) {
      await pool.query(
        `UPDATE rmm_agent_jobs
            SET status='queued',claimed_at=NULL,updated_at=now()
          WHERE id=$1 AND status='claimed'`,
        [job.id],
      )
      continue
    }
    dispatched.push(job.id)
  }
  return dispatched
}

export async function reconcileSoftwareQualificationQueue() {
  await stopOverlongQualificationJobs()
  const emergencyDispatched = await dispatchEmergencyAgentControlJobs()
  const runner = await liveQualificationRunner()
  const active = await pool.query(
    `SELECT id,state,test_type FROM rmm_software_qualification_queue
      WHERE state IN ('running','cleanup_pending','cleanup_running')
      ORDER BY updated_at LIMIT 20`,
  )
  const reconciled = []
  for (const row of active.rows) {
    reconciled.push(row.test_type === 'upgrade'
      ? await reconcileUpgradeQueueRow(row, runner)
      : row.test_type === 'rollback'
        ? await reconcileRollbackQueueRow(row, runner)
        : await reconcileQueueRow(row, runner))
  }
  return {
    runner: runner?.device_name || null,
    runnerDeviceId: runner?.agent_device_id || null,
    reconciled,
    emergencyDispatched,
    activeCount: active.rowCount,
    dispatchAttempted: false,
    dispatched: [],
  }
}

export async function runSoftwareQualificationQueue({ dispatchLimit = 1 } = {}) {
  const reconciliation = await reconcileSoftwareQualificationQueue()
  const runner = await liveQualificationRunner()
  const reconciled = reconciliation.reconciled
  const emergencyDispatched = reconciliation.emergencyDispatched

  if (!runner) return { ...reconciliation, runner: null }

  const stillActive = await pool.query(
    `SELECT count(*)::int AS count
       FROM rmm_software_qualification_queue
      WHERE state IN ('running','cleanup_pending','cleanup_running')`,
  )
  if (Number(stillActive.rows[0]?.count || 0) > 0) {
    return { runner: runner.device_name, reconciled, dispatched: [], emergencyDispatched }
  }

  if (runner.dispatch_enabled === false) {
    return {
      runner: runner.device_name,
      paused: true,
      pauseReason: clean(runner.pause_reason),
      reconciled,
      dispatched: [],
      emergencyDispatched,
    }
  }

  const upgradeEnabled = qualificationStageEnabled('upgrade')
  const rollbackEnabled = qualificationStageEnabled('rollback')
  const queued = await pool.query(
    `SELECT q.id,q.catalogue_id,q.test_type,q.priority,c.canonical_name,c.target_version,c.installer_type
       FROM rmm_software_qualification_queue q
       JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
      WHERE q.state='queued'
        AND COALESCE(NULLIF(q.evidence->>'retryNotBefore','')::timestamptz,'-infinity'::timestamptz) <= now()
        AND c.status='active'
        AND (
          c.qualification_state='deployment_candidate'
          OR (
            q.test_type IN ('upgrade','rollback')
            AND c.qualification_state IN ('qualified','qualified_limited')
          )
        )
        AND (
          q.test_type='clean_install'
          OR (
            $1::boolean
            AND q.test_type='upgrade'
            AND EXISTS (
              SELECT 1 FROM rmm_software_qualification_queue qi
               WHERE qi.catalogue_id=q.catalogue_id
                 AND qi.test_type='clean_install'
                 AND qi.state='passed'
            )
          )
          OR (
            $2::boolean
            AND q.test_type='rollback'
            AND EXISTS (
              SELECT 1 FROM rmm_software_qualification_queue qi
               WHERE qi.catalogue_id=q.catalogue_id
                 AND qi.test_type='clean_install'
                 AND qi.state='passed'
            )
            AND EXISTS (
              SELECT 1 FROM rmm_software_qualification_queue qu
               WHERE qu.catalogue_id=q.catalogue_id
                 AND qu.test_type='upgrade'
                 AND qu.state='passed'
            )
          )
        )
      ORDER BY CASE q.test_type WHEN 'rollback' THEN 0 WHEN 'upgrade' THEN 1 ELSE 2 END,
               q.priority DESC,q.created_at
      LIMIT $3`,
    [
      upgradeEnabled,
      rollbackEnabled,
      Math.max(1, Math.min(3, Number(dispatchLimit) || 1)),
    ],
  )
  const recentMsiBusy = await pool.query(
    `SELECT 1
       FROM rmm_agent_jobs
      WHERE agent_device_id=$1
        AND updated_at > now()-interval '90 seconds'
        AND COALESCE(result->>'exitCode','')='1618'
      LIMIT 1`,
    [runner.agent_device_id],
  )
  const msiBusyBackoff = recentMsiBusy.rowCount > 0
  const dispatched = []
  for (const queue of queued.rows) {
    if (msiBusyBackoff && lower(queue.installer_type) === 'msi') {
      dispatched.push({
        id: queue.id,
        applicationName: queue.canonical_name,
        testType: queue.test_type,
        dispatched: false,
        reason: 'windows_installer_busy_backoff',
      })
      continue
    }
    const result = queue.test_type === 'upgrade'
      ? await dispatchUpgradeBaseline(queue, runner)
      : queue.test_type === 'rollback'
        ? await dispatchRollbackQualification(queue, runner)
        : await dispatchCleanInstall(queue, runner)
    dispatched.push({ id: queue.id, applicationName: queue.canonical_name, testType: queue.test_type, ...result })
    if (result.dispatched) break
  }
  return { runner: runner.device_name, reconciled, dispatched, emergencyDispatched }
}

export async function setQualificationRunnerDispatch(agentDeviceId, {
  dispatchEnabled = true,
  reason = '',
  userId = null,
} = {}) {
  const result = await pool.query(
    `UPDATE rmm_software_vendor_qualification_runners
        SET enabled=true,
            dispatch_enabled=$2,
            pause_reason=CASE WHEN $2 THEN '' ELSE $3 END,
            paused_at=CASE WHEN $2 THEN NULL ELSE now() END,
            paused_by_user_id=CASE WHEN $2 THEN NULL ELSE $4::uuid END,
            updated_at=now()
      WHERE agent_device_id=$1
      RETURNING agent_device_id,enabled,dispatch_enabled,pause_reason,paused_at,updated_at`,
    [clean(agentDeviceId), Boolean(dispatchEnabled), clean(reason).slice(0, 500), userId || null],
  )
  return result.rows[0] || null
}

export async function cancelSoftwareQualificationQueue(queueId, { userId = null } = {}) {
  const result = await pool.query(
    `SELECT id,catalogue_id,test_type,state,runner_agent_device_id,evidence
       FROM rmm_software_qualification_queue WHERE id=$1 LIMIT 1`,
    [clean(queueId)],
  )
  const row = result.rows[0]
  if (!row) return { ok: false, reason: 'qualification_queue_not_found' }
  if (['queued','review_required','passed','cancelled'].includes(clean(row.state))) {
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET state='cancelled',last_error='admin_cancelled',
              evidence=evidence || $2::jsonb,completed_at=now(),updated_at=now()
        WHERE id=$1`,
      [row.id, JSON.stringify({
        adminCancelledAt: new Date().toISOString(),
        adminCancelledByUserId: userId || '',
      })],
    )
    return { ok: true, state: 'cancelled', immediate: true }
  }
  if (['running','cleanup_pending','cleanup_running'].includes(clean(row.state))) {
    await pool.query(
      `UPDATE rmm_software_qualification_queue
          SET last_error='admin_cancel_requested',
              evidence=evidence || $2::jsonb,updated_at=now()
        WHERE id=$1`,
      [row.id, JSON.stringify({
        adminCancelRequested: true,
        adminCancelRequestedAt: new Date().toISOString(),
        adminCancelRequestedByUserId: userId || '',
      })],
    )
    return { ok: true, state: row.state, immediate: false, safeCleanupRequired: true }
  }
  return { ok: false, reason: 'qualification_queue_state_not_cancellable', state: row.state }
}

export async function forceQualificationCleanup(queueId, { userId = null } = {}) {
  const current = await qualificationRow(clean(queueId))
  if (!current) return { ok: false, reason: 'qualification_queue_not_found' }
  if (clean(current.test_type) !== 'clean_install') {
    return { ok: false, reason: 'cleanup_only_supported_for_clean_install' }
  }
  const runner = await liveQualificationRunner()
  if (!runner) return { ok: false, reason: 'qualification_runner_offline' }
  if (current.runner_agent_device_id && clean(current.runner_agent_device_id) !== clean(runner.agent_device_id)) {
    return { ok: false, reason: 'qualification_runner_mismatch' }
  }
  if (clean(current.state) === 'running') {
    const job = await pool.query('SELECT status FROM rmm_agent_jobs WHERE id=$1 LIMIT 1', [current.agent_job_id])
    if (job.rows[0] && ['queued','claimed'].includes(clean(job.rows[0].status))) {
      return { ok: false, reason: 'qualification_install_still_active' }
    }
  }
  const installed = installedMatches(runner.source_payload, current)
  if (!installed.length) {
    return { ok: false, reason: 'qualification_software_not_installed' }
  }
  await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET state='cleanup_pending',runner_agent_device_id=$2,
            cleanup_job_id=NULL,last_error='',
            evidence=evidence || $3::jsonb,
            completed_at=NULL,updated_at=now()
      WHERE id=$1`,
    [current.id, runner.agent_device_id, JSON.stringify({
      adminCleanupOnly: true,
      adminCleanupRequestedAt: new Date().toISOString(),
      adminCleanupRequestedByUserId: userId || '',
      stage: 'cleanup_pending',
      installCompletedAt: clean(object(current.evidence).installCompletedAt) || new Date().toISOString(),
    })],
  )
  const reconciled = await reconcileQueueRow({ id: current.id }, runner)
  return { ok: true, queueId: current.id, reconciled }
}

export async function prioritiseSoftwareQualificationQueue(queueId, { priority = 50000 } = {}) {
  const safePriority = Math.max(1, Math.min(100000, Number(priority) || 50000))
  const result = await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET priority=$2,
            evidence=(evidence - 'retryNotBefore') || jsonb_build_object(
              'adminRunNowRequestedAt',now()
            ),
            updated_at=now()
      WHERE id=$1 AND state='queued'
      RETURNING id,catalogue_id,test_type,state,priority`,
    [clean(queueId), safePriority],
  )
  return result.rows[0] || null
}

export async function setSoftwareQualificationPriority(queueId, {
  priority = 100,
  userId = null,
} = {}) {
  const safePriority = Math.max(1, Math.min(2147480000, Math.trunc(Number(priority) || 100)))
  const result = await pool.query(
    `UPDATE rmm_software_qualification_queue
        SET priority=$2,
            evidence=evidence || jsonb_build_object(
              'adminPriorityUpdatedAt',now(),
              'adminPriorityUpdatedByUserId',$3::text
            ),
            updated_at=now()
      WHERE id=$1 AND state='queued'
      RETURNING id,catalogue_id,test_type,state,priority,created_at,updated_at`,
    [clean(queueId), safePriority, userId || ''],
  )
  return result.rows[0] || null
}

export async function pushSoftwareQualificationToTop(queueId, { userId = null } = {}) {
  const result = await pool.query(
    `WITH current AS (
       SELECT id,test_type FROM rmm_software_qualification_queue
        WHERE id=$1 AND state='queued'
     ),
     next_priority AS (
       SELECT LEAST(2147480000,COALESCE(MAX(q.priority),0)+1000)::int AS priority
         FROM rmm_software_qualification_queue q
         JOIN current c ON c.test_type=q.test_type
        WHERE q.state='queued'
     )
     UPDATE rmm_software_qualification_queue q
        SET priority=np.priority,
            evidence=q.evidence || jsonb_build_object(
              'adminPriorityUpdatedAt',now(),
              'adminPriorityUpdatedByUserId',$2::text,
              'adminPushedToTop',true
            ),
            updated_at=now()
       FROM current c,next_priority np
      WHERE q.id=c.id
      RETURNING q.id,q.catalogue_id,q.test_type,q.state,q.priority,q.created_at,q.updated_at`,
    [clean(queueId), userId || ''],
  )
  return result.rows[0] || null
}

export async function retrySoftwareQualification(catalogueId, { mode = 'full' } = {}) {
  const qualificationMode = mode === 'clean_only' ? 'clean_only' : 'full'
  const ready = await pool.query(
    `SELECT c.id,c.canonical_name,c.target_version,c.installer_type,
            c.source_metadata->>'latestSource' AS source_key,
            s.last_success_at,s.last_error,
            r.id AS release_id,r.trust_state,r.asset_health_state,r.installer_url,r.installer_sha256,
            COALESCE(NULLIF(c.source_metadata->>'expectedSigner',''),NULLIF(r.source_payload->>'expectedSigner',''),NULLIF(r.trust_evidence->>'signer','')) AS expected_signer
       FROM rmm_software_catalogue c
       JOIN rmm_software_vendor_sources s
         ON s.source_key=c.source_metadata->>'latestSource' AND s.enabled=true
       JOIN rmm_software_vendor_releases r
         ON r.provider_package_id=c.external_key
        AND r.source_key=c.source_metadata->>'latestSource'
        AND r.version=c.target_version
      WHERE c.id=$1 AND c.tenant_id IS NULL AND c.status='active'
      LIMIT 1`,
    [catalogueId],
  )
  const row = ready.rows[0]
  if (!row) return { queued: false, reason: 'catalogue_vendor_release_not_found' }
  if (!row.last_success_at || clean(row.last_error)) return { queued: false, reason: 'source_health_not_ready' }
  if (clean(row.trust_state) !== 'direct_ready'
    || clean(row.asset_health_state) === 'dead'
    || !/^https:\/\//i.test(clean(row.installer_url))
    || !/^[a-f0-9]{64}$/i.test(clean(row.installer_sha256))
    || !clean(row.expected_signer)) {
    return { queued: false, reason: 'artifact_validation_not_ready' }
  }

  const active = await pool.query(
    `SELECT id,test_type,state
       FROM rmm_software_qualification_queue
      WHERE catalogue_id=$1
        AND state IN ('running','cleanup_pending','cleanup_running')
      LIMIT 1`,
    [catalogueId],
  )
  if (active.rowCount) return { queued: false, active: true, state: active.rows[0].state }

  const queue = await withTransaction(async (client) => {
    await client.query(
      `UPDATE rmm_software_catalogue
          SET qualification_state='deployment_candidate',
              qualification_version='',
              qualified_at=NULL,
              qualification_evidence=qualification_evidence
                - 'cleanInstallVerified'
                - 'cleanInstallVersion'
                - 'cleanInstallVerifiedAt'
                - 'uninstallVerified'
                - 'uninstallVerifiedAt'
                - 'upgradeVerified'
                - 'upgradeFromVersion'
                - 'upgradeVersion'
                - 'upgradeVerifiedAt'
                - 'upgradePatchDetectionVerified'
                - 'upgradePatchDetectionInstalledVersion'
                - 'upgradePatchDetectionTargetVersion'
                - 'upgradePatchDetectionVerifiedAt'
                - 'rollbackVerified'
                - 'rollbackFromVersion'
                - 'rollbackPreviousVersion'
                - 'rollbackRestoredVersion'
                - 'rollbackVerifiedAt'
                - 'rollbackCurrentInstallVerified'
                - 'rollbackCurrentUninstallVerified'
                - 'rollbackPreviousInstallVerified'
                - 'rollbackPreviousInventoryVerified'
                - 'rollbackRestorePatchDetectionVerified'
                - 'rollbackRestorePatchDetectionInstalledVersion'
                - 'rollbackRestorePatchDetectionTargetVersion'
                - 'rollbackRestoreVerified'
                - 'rollbackFinalUninstallVerified'
                - 'rollbackQualificationQueueId'
                - 'rollbackResidueCleanupVerified'
                - 'rollbackResidueCleanupVerifiedAt'
                - 'rollbackResidueCleanupReclaimedMiB'
                || jsonb_build_object('manualRequalificationRequestedAt',now()),
              updated_at=now()
        WHERE id=$1`,
      [catalogueId],
    )
    await client.query(
      `UPDATE rmm_software_qualification_queue
          SET state='cancelled',last_error='manual_revalidation_reset',
              completed_at=now(),updated_at=now()
        WHERE catalogue_id=$1 AND test_type IN ('upgrade','rollback')
          AND state NOT IN ('running','cleanup_pending','cleanup_running')`,
      [catalogueId],
    )
    const result = await client.query(
      `INSERT INTO rmm_software_qualification_queue
        (catalogue_id,test_type,state,priority,attempt_count,last_error,evidence,created_at,updated_at)
       VALUES ($1,'clean_install','queued',
               CASE WHEN lower(COALESCE($2,''))='msi' THEN 120 ELSE 110 END,
               0,'',jsonb_build_object(
                 'manualRequalification',true,
                 'manualQualificationMode',$3::text,
                 'queuedAt',now()
               ),now(),now())
       ON CONFLICT (catalogue_id,test_type)
       DO UPDATE SET state='queued',
         priority=EXCLUDED.priority,
         attempt_count=0,
         runner_agent_device_id=NULL,
         agent_job_id=NULL,
         deployment_id=NULL,
         cleanup_job_id=NULL,
         last_error='',
         evidence=EXCLUDED.evidence,
         started_at=NULL,
         completed_at=NULL,
         updated_at=now()
       RETURNING id,state,priority`,
      [catalogueId, row.installer_type, qualificationMode],
    )
    return result.rows[0]
  })
  return { queued: true, catalogueId, applicationName: row.canonical_name, targetVersion: row.target_version, mode: qualificationMode, queue }
}

export async function queueUpgradeQualification(catalogueId) {
  const ready = await pool.query(
    `SELECT c.id,c.canonical_name,c.target_version,c.installer_type,
            c.source_metadata->>'latestSource' AS source_key,
            c.qualification_evidence,
            qi.state AS clean_state
       FROM rmm_software_catalogue c
       LEFT JOIN rmm_software_qualification_queue qi
         ON qi.catalogue_id=c.id AND qi.test_type='clean_install'
      WHERE c.id=$1
        AND c.tenant_id IS NULL
        AND c.status='active'
        AND c.source_metadata->>'deploymentMode' IN ('vendor_direct','winget_preferred')
        AND c.source_metadata->>'trustState'='direct_ready'
      LIMIT 1`,
    [catalogueId],
  )
  const row = ready.rows[0]
  if (!row) return { queued: false, reason: 'catalogue_vendor_release_not_ready' }
  const cleanEvidence = object(row.qualification_evidence)
  if (clean(row.clean_state) !== 'passed'
    || cleanEvidence.cleanInstallVerified !== true
    || clean(cleanEvidence.cleanInstallVersion) !== clean(row.target_version)
    || cleanEvidence.uninstallVerified !== true) {
    return { queued: false, reason: 'clean_install_not_passed_for_current_target' }
  }

  const active = await pool.query(
    `SELECT id,test_type,state
       FROM rmm_software_qualification_queue
      WHERE catalogue_id=$1
        AND state IN ('running','cleanup_pending','cleanup_running')
      LIMIT 1`,
    [catalogueId],
  )
  if (active.rowCount) return { queued: false, active: true, state: active.rows[0].state }

  const pair = await upgradeReleasePair(catalogueId)
  if (!pair.target) return { queued: false, reason: 'qualification_current_trusted_release_not_available' }
  if (!pair.previous) return { queued: false, reason: 'previous_trusted_release_not_available' }

  const queue = await withTransaction(async (client) => {
    await client.query(
      `UPDATE rmm_software_catalogue
          SET qualification_evidence=qualification_evidence
                - 'upgradeVerified'
                - 'upgradeFromVersion'
                - 'upgradeVersion'
                - 'upgradeVerifiedAt'
                - 'upgradePatchDetectionVerified'
                - 'upgradePatchDetectionInstalledVersion'
                - 'upgradePatchDetectionTargetVersion'
                - 'upgradePatchDetectionVerifiedAt'
                - 'rollbackVerified'
                - 'rollbackFromVersion'
                - 'rollbackPreviousVersion'
                - 'rollbackRestoredVersion'
                - 'rollbackVerifiedAt'
                - 'rollbackCurrentInstallVerified'
                - 'rollbackCurrentUninstallVerified'
                - 'rollbackPreviousInstallVerified'
                - 'rollbackPreviousInventoryVerified'
                - 'rollbackRestorePatchDetectionVerified'
                - 'rollbackRestorePatchDetectionInstalledVersion'
                - 'rollbackRestorePatchDetectionTargetVersion'
                - 'rollbackRestoreVerified'
                - 'rollbackFinalUninstallVerified'
                - 'rollbackQualificationQueueId'
                - 'rollbackResidueCleanupVerified'
                - 'rollbackResidueCleanupVerifiedAt'
                - 'rollbackResidueCleanupReclaimedMiB'
                || jsonb_build_object('manualUpgradeQualificationRequestedAt',now()),
              updated_at=now()
        WHERE id=$1`,
      [catalogueId],
    )
    await client.query(
      `UPDATE rmm_software_qualification_queue
          SET state='cancelled',last_error='upgrade_revalidation_reset',
              completed_at=now(),updated_at=now()
        WHERE catalogue_id=$1 AND test_type='rollback'
          AND state NOT IN ('running','cleanup_pending','cleanup_running')`,
      [catalogueId],
    )
    const result = await client.query(
      `INSERT INTO rmm_software_qualification_queue
        (catalogue_id,test_type,state,priority,attempt_count,last_error,evidence,created_at,updated_at)
       VALUES ($1,'upgrade',
               'queued',
               CASE WHEN lower(COALESCE($2,''))='msi' THEN 120 ELSE 110 END,
               0,'',jsonb_build_object(
                 'manualUpgradeQualification',true,
                 'manualQualificationMode','upgrade_only',
                 'queuedAt',now()
               ),now(),now())
       ON CONFLICT (catalogue_id,test_type)
       DO UPDATE SET
         state='queued',
         priority=EXCLUDED.priority,
         attempt_count=0,
         runner_agent_device_id=NULL,
         agent_job_id=NULL,
         deployment_id=NULL,
         cleanup_job_id=NULL,
         last_error='',
         evidence=EXCLUDED.evidence,
         started_at=NULL,
         completed_at=NULL,
         updated_at=now()
       RETURNING id,state,priority`,
      [catalogueId, row.installer_type],
    )
    return result.rows[0]
  })
  return {
    queued: true,
    catalogueId,
    applicationName: row.canonical_name,
    targetVersion: row.target_version,
    previousVersion: clean(pair.previous.release_version),
    queue,
  }
}

export async function queueRollbackQualification(catalogueId) {
  const ready = await pool.query(
    `SELECT c.id,c.canonical_name,c.target_version,c.installer_type,c.qualification_state,
            c.qualification_evidence,
            qi.state AS clean_state,
            qu.state AS upgrade_state
       FROM rmm_software_catalogue c
       LEFT JOIN rmm_software_qualification_queue qi
         ON qi.catalogue_id=c.id AND qi.test_type='clean_install'
       LEFT JOIN rmm_software_qualification_queue qu
         ON qu.catalogue_id=c.id AND qu.test_type='upgrade'
      WHERE c.id=$1
        AND c.tenant_id IS NULL
        AND c.status='active'
        AND c.source_metadata->>'deploymentMode' IN ('vendor_direct','winget_preferred')
        AND c.source_metadata->>'trustState'='direct_ready'
      LIMIT 1`,
    [catalogueId],
  )
  const row = ready.rows[0]
  if (!row) return { queued: false, reason: 'catalogue_vendor_release_not_ready' }

  const evidence = object(row.qualification_evidence)
  if (clean(row.clean_state) !== 'passed'
    || evidence.cleanInstallVerified !== true
    || clean(evidence.cleanInstallVersion) !== clean(row.target_version)
    || evidence.uninstallVerified !== true) {
    return { queued: false, reason: 'clean_install_not_passed_for_current_target' }
  }
  if (clean(row.upgrade_state) !== 'passed'
    || evidence.upgradeVerified !== true
    || clean(evidence.upgradeVersion) !== clean(row.target_version)) {
    return { queued: false, reason: 'upgrade_not_passed_for_current_target' }
  }
  if (evidence.upgradePatchDetectionVerified !== true
    || clean(evidence.upgradePatchDetectionTargetVersion) !== clean(row.target_version)) {
    return { queued: false, reason: 'upgrade_patch_detection_not_verified_for_current_target' }
  }

  const active = await pool.query(
    `SELECT id,test_type,state
       FROM rmm_software_qualification_queue
      WHERE catalogue_id=$1
        AND state IN ('running','cleanup_pending','cleanup_running')
      LIMIT 1`,
    [catalogueId],
  )
  if (active.rowCount) return { queued: false, active: true, state: active.rows[0].state }

  const pair = await upgradeReleasePair(catalogueId)
  if (!pair.target) return { queued: false, reason: 'qualification_current_trusted_release_not_available' }
  if (!pair.previous) return { queued: false, reason: 'previous_trusted_release_not_available' }
  if (!strictDirectArtifactReady(pair.target) || !strictDirectArtifactReady(pair.previous)) {
    return { queued: false, reason: 'qualification_rollback_artifact_gate_failed' }
  }

  const queue = await withTransaction(async (client) => {
    await client.query(
      `UPDATE rmm_software_catalogue
          SET qualification_evidence=qualification_evidence
                - 'rollbackVerified'
                - 'rollbackFromVersion'
                - 'rollbackPreviousVersion'
                - 'rollbackRestoredVersion'
                - 'rollbackVerifiedAt'
                - 'rollbackCurrentInstallVerified'
                - 'rollbackCurrentUninstallVerified'
                - 'rollbackPreviousInstallVerified'
                - 'rollbackPreviousInventoryVerified'
                - 'rollbackRestorePatchDetectionVerified'
                - 'rollbackRestorePatchDetectionInstalledVersion'
                - 'rollbackRestorePatchDetectionTargetVersion'
                - 'rollbackRestoreVerified'
                - 'rollbackFinalUninstallVerified'
                - 'rollbackQualificationQueueId'
                - 'rollbackResidueCleanupVerified'
                - 'rollbackResidueCleanupVerifiedAt'
                - 'rollbackResidueCleanupReclaimedMiB'
                || jsonb_build_object('manualRollbackQualificationRequestedAt',now()),
              updated_at=now()
        WHERE id=$1`,
      [catalogueId],
    )
    const result = await client.query(
      `INSERT INTO rmm_software_qualification_queue
        (catalogue_id,test_type,state,priority,attempt_count,last_error,evidence,created_at,updated_at)
       VALUES ($1,'rollback','queued',
               CASE WHEN lower(COALESCE($2,''))='msi' THEN 105 ELSE 95 END,
               0,'',jsonb_build_object(
                 'manualRollbackQualification',true,
                 'manualQualificationMode','rollback_only',
                 'targetVersion',$3::text,
                 'previousVersion',$4::text,
                 'queuedAt',now()
               ),now(),now())
       ON CONFLICT (catalogue_id,test_type)
       DO UPDATE SET
         state='queued',
         priority=EXCLUDED.priority,
         attempt_count=0,
         runner_agent_device_id=NULL,
         agent_job_id=NULL,
         deployment_id=NULL,
         cleanup_job_id=NULL,
         last_error='',
         evidence=EXCLUDED.evidence,
         started_at=NULL,
         completed_at=NULL,
         updated_at=now()
       RETURNING id,state,priority`,
      [catalogueId, row.installer_type, clean(pair.target.release_version), clean(pair.previous.release_version)],
    )
    return result.rows[0]
  })

  return {
    queued: true,
    catalogueId,
    applicationName: row.canonical_name,
    qualificationState: row.qualification_state,
    targetVersion: clean(pair.target.release_version),
    previousVersion: clean(pair.previous.release_version),
    queue,
  }
}

export async function qualificationQueueSummary(tenantId) {
  const hasRunner = await pool.query(
    `SELECT 1
       FROM rmm_software_vendor_qualification_runners q
       JOIN rmm_agent_devices a ON a.id=q.agent_device_id
      WHERE q.enabled=true AND a.tenant_id=$1
      LIMIT 1`,
    [tenantId],
  )
  if (!hasRunner.rowCount) return []

  const result = await pool.query(
    `SELECT q.id,q.catalogue_id,q.test_type,q.state,q.priority,q.attempt_count,
            q.runner_agent_device_id,q.agent_job_id,q.deployment_id,q.cleanup_job_id,
            q.last_error,q.evidence,q.started_at,q.completed_at,q.created_at,q.updated_at,
            c.canonical_name,c.target_version,c.qualification_state,c.installer_type,
            c.source_metadata->>'installerTechnology' AS installer_technology,
            i.name AS runner_device_name
       FROM rmm_software_qualification_queue q
       JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
       LEFT JOIN rmm_agent_devices a ON a.id=q.runner_agent_device_id
       LEFT JOIN rmm_device_inventory i ON i.id=a.inventory_id
      ORDER BY CASE q.state
        WHEN 'review_required' THEN 0
        WHEN 'running' THEN 1
        WHEN 'cleanup_pending' THEN 2
        WHEN 'cleanup_running' THEN 3
        WHEN 'queued' THEN 4
        ELSE 5 END,
        q.priority DESC,q.updated_at DESC`,
  )
  return result.rows
}
