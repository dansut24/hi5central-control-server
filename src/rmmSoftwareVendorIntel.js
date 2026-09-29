import { pool, withTransaction } from './db.js'
import {
  evaluateVendorHtmlAutomation,
  fetchPublicJson,
  fetchPublicText,
  globMatcher,
  githubApiHeaders,
  githubApiToken,
  installerType as detectInstallerType,
  jsonPathValue,
  latestGithubRelease,
  normalizedSha256,
  publicHttpsUrl,
  resolveAllowedPublicDownload,
  publishedChecksum,
  releaseDate as normalizedReleaseDate,
  releaseVersion,
  repositoryName,
} from './rmmTenantVendorSources.js'
import { recalculateAllTenantVulnerabilityExposures } from './rmmVulnerabilityExposure.js'
import { resolvePreviousWingetVendorInstaller, resolveWingetVendorInstaller, syncAutomaticWingetFallbacks, wingetEnterpriseSeedMatches } from './rmmWingetFallback.js'
import { importCuratedSoftwareCatalogue } from './rmmCuratedSoftwareCatalogue.js'
import { syncEvergreenCorroboration } from './rmmEvergreenIntel.js'
import { promoteAutomaticAdmissionReady, queueAutomaticCleanInstallQualifications, queueAutomaticRollbackQualifications, queueAutomaticUpgradeQualifications, queueCommonSoftwareQualifications, resetStaleQualificationQueuesForCurrentTargets, runSoftwareQualificationQueue } from './rmmSoftwareQualification.js'
import { BUSINESS_ESSENTIAL_WINGET_PACKAGES, COMMON_WINDOWS_SOFTWARE_LOWER } from './rmmCommonSoftware.js'
import { htmlHostAllowed, parseVendorHtmlReleases } from './vendorHtmlRecipe.js'
import {
  classifyGithubReleaseBacklog,
  discoverGithubWindowsInstaller,
  runVendorArtifactQualification,
  rankWindowsInstallerAssets,
  selectChecksumAsset,
  selectWindowsInstallerAsset,
  vendorReleaseTrustProfile,
} from './rmmVendorReleaseEnrichment.js'

function clean(value = '') { return String(value ?? '').trim() }

function qualificationStageEnabled(stage) {
  const key = `RMM_QUALIFICATION_${clean(stage).toUpperCase()}_ENABLED`
  return !['0', 'false', 'off', 'no']
    .includes(clean(process.env[key] ?? 'true').toLowerCase())
}
function lower(value = '') { return clean(value).toLowerCase() }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function versionNumbers(value = '') { return clean(value).match(/\d+/g)?.map(Number) || [] }
function compareVersionValues(a, b) {
  const left = versionNumbers(a), right = versionNumbers(b)
  const size = Math.max(left.length, right.length)
  for (let i = 0; i < size; i += 1) {
    const delta = (left[i] || 0) - (right[i] || 0)
    if (delta) return delta
  }
  return clean(a).localeCompare(clean(b))
}

async function fetchText(url, accept = '*/*') {
  const response = await fetch(url, {
    headers: { Accept: accept, 'User-Agent': 'Hi5Central-Software-Catalogue/1.0' },
    signal: AbortSignal.timeout(60_000),
  })
  if (!response.ok) throw new Error('HTTP ' + response.status + ' from ' + url)
  return response.text()
}

async function fetchJson(url) {
  const text = await fetchText(url, 'application/json')
  return JSON.parse(text)
}

function stripHtml(value = '') {
  return String(value)
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/\s+/g, ' ')
    .trim()
}

function parseLooseDate(value = '') {
  const parsed = Date.parse(clean(value))
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : null
}

async function sourceState(sourceKey) {
  const result = await pool.query(
    `SELECT source_key,display_name,source_type,source_url,enabled,priority,poll_minutes,cursor_value,
            last_attempt_at,last_success_at,last_error,records_seen,metadata
       FROM rmm_software_vendor_sources
      WHERE source_key=$1 LIMIT 1`,
    [sourceKey],
  )
  return result.rows[0] || null
}

async function markAttempt(sourceKey) {
  await pool.query(
    'UPDATE rmm_software_vendor_sources SET last_attempt_at=now(),updated_at=now() WHERE source_key=$1',
    [sourceKey],
  )
}

async function markFailure(sourceKey, error) {
  await pool.query(
    `UPDATE rmm_software_vendor_sources
        SET last_error=$2,updated_at=now()
      WHERE source_key=$1`,
    [sourceKey, clean(error?.message || error).slice(0, 2000)],
  ).catch(() => null)
}
async function upsertRelease({
  sourceKey,
  packageId,
  canonicalName,
  publisher,
  channel = 'stable',
  platform = 'windows',
  architecture = 'x64',
  version,
  releaseDate = null,
  installerUrl = '',
  installerSha256 = '',
  installerType = '',
  releaseUrl = '',
  assetName = '',
  trustState = 'version_only',
  trustEvidence = {},
  qualificationState = 'intelligence_only',
  qualificationEvidence = {},
  qualificationNotes = '',
  sourcePriority = 100,
  payload = {},
  catalogueProvider = 'winget',
  verification = {},
  execution = {},
  catalogueMetadata = {},
}) {
  const normalizedVersion = clean(version)
  if (!normalizedVersion) throw new Error(sourceKey + ' returned an empty version')

  const legacyWingetFallback = catalogueProvider === 'winget'
    && clean(packageId)
    && !clean(packageId).startsWith('vendor:')
  if (legacyWingetFallback) {
    verification = {
      method: 'winget',
      packageId: clean(packageId),
      productCode: '',
      displayNameContains: clean(canonicalName),
      publisherContains: clean(publisher),
      filePath: '',
      ...object(verification),
    }
    trustState = trustState === 'version_only' ? 'winget_ready' : trustState
    trustEvidence = {
      sourceOfTruth: 'vendor_feed',
      deploymentTransport: 'winget',
      ...object(trustEvidence),
    }
    qualificationState = qualificationState === 'intelligence_only' ? 'deployment_candidate' : qualificationState
    qualificationEvidence = {
      vendorAuthoritativeVersion: true,
      wingetFallback: true,
      ...object(qualificationEvidence),
    }
    qualificationNotes = qualificationNotes
      || 'Vendor feed is authoritative for the target version; WinGet is used only as the deployment transport.'
    catalogueMetadata = {
      deploymentMode: 'winget_preferred',
      trustState,
      wingetPackageId: clean(packageId),
      hasWingetFallback: true,
      automaticVendorRelease: true,
      ...object(catalogueMetadata),
    }
  }

  return withTransaction(async (client) => {
    await client.query(
      `INSERT INTO rmm_software_vendor_releases
        (source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,
         version,release_date,installer_url,installer_sha256,installer_type,release_url,asset_name,
         trust_state,trust_evidence,source_priority,source_payload,last_seen_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18::jsonb,now())
       ON CONFLICT (source_key,provider_package_id,channel,platform,architecture,version)
       DO UPDATE SET release_date=COALESCE(EXCLUDED.release_date,rmm_software_vendor_releases.release_date),
         asset_health_state=CASE WHEN rmm_software_vendor_releases.installer_url IS DISTINCT FROM EXCLUDED.installer_url THEN 'unknown' ELSE rmm_software_vendor_releases.asset_health_state END,
         asset_last_checked_at=CASE WHEN rmm_software_vendor_releases.installer_url IS DISTINCT FROM EXCLUDED.installer_url THEN NULL ELSE rmm_software_vendor_releases.asset_last_checked_at END,
         asset_failure_count=CASE WHEN rmm_software_vendor_releases.installer_url IS DISTINCT FROM EXCLUDED.installer_url THEN 0 ELSE rmm_software_vendor_releases.asset_failure_count END,
         asset_final_url=CASE WHEN rmm_software_vendor_releases.installer_url IS DISTINCT FROM EXCLUDED.installer_url THEN '' ELSE rmm_software_vendor_releases.asset_final_url END,
         asset_health_error=CASE WHEN rmm_software_vendor_releases.installer_url IS DISTINCT FROM EXCLUDED.installer_url THEN '' ELSE rmm_software_vendor_releases.asset_health_error END,
         installer_url=EXCLUDED.installer_url,
         installer_sha256=CASE
           WHEN EXCLUDED.installer_sha256<>'' THEN EXCLUDED.installer_sha256
           WHEN rmm_software_vendor_releases.installer_url IS NOT DISTINCT FROM EXCLUDED.installer_url
             THEN rmm_software_vendor_releases.installer_sha256
           ELSE ''
         END,
         installer_type=EXCLUDED.installer_type,
         release_url=EXCLUDED.release_url,
         asset_name=EXCLUDED.asset_name,
         trust_state=CASE
           WHEN rmm_software_vendor_releases.trust_state IN ('rejected','signer_review_required','installer_review_required')
             THEN rmm_software_vendor_releases.trust_state
           WHEN rmm_software_vendor_releases.trust_state='direct_ready'
             AND EXCLUDED.trust_state<>'direct_ready'
             AND rmm_software_vendor_releases.installer_url IS NOT DISTINCT FROM EXCLUDED.installer_url
             THEN 'direct_ready'
           ELSE EXCLUDED.trust_state
         END,
         trust_evidence=rmm_software_vendor_releases.trust_evidence || EXCLUDED.trust_evidence,
         source_priority=EXCLUDED.source_priority,
         source_payload=(rmm_software_vendor_releases.source_payload || EXCLUDED.source_payload)
           || jsonb_build_object(
             'trustState',
             CASE
               WHEN rmm_software_vendor_releases.trust_state IN ('rejected','signer_review_required','installer_review_required')
                 THEN rmm_software_vendor_releases.trust_state
               WHEN rmm_software_vendor_releases.trust_state='direct_ready'
                 AND EXCLUDED.trust_state<>'direct_ready'
                 AND rmm_software_vendor_releases.installer_url IS NOT DISTINCT FROM EXCLUDED.installer_url
                 THEN 'direct_ready'
               ELSE EXCLUDED.trust_state
             END
           ),
         last_seen_at=now()
       RETURNING id,trust_state,trust_evidence,source_payload`,
      [
        sourceKey, packageId, canonicalName, publisher, channel, platform, architecture,
        normalizedVersion, releaseDate, installerUrl, installerSha256, installerType,
        releaseUrl, assetName, trustState, JSON.stringify(trustEvidence || {}),
        sourcePriority, JSON.stringify(payload),
      ],
    )

    const existing = await client.query(
      `SELECT id FROM rmm_software_catalogue
        WHERE tenant_id IS NULL AND catalogue_source='vendor' AND external_key=$1
          ORDER BY (status='active') DESC,created_at LIMIT 1`,
      [packageId],
    )
    if (existing.rowCount) {
      await client.query(
        `UPDATE rmm_software_catalogue
            SET status=CASE
                  WHEN status='archived'
                   AND source_metadata->>'catalogueArchivePolicy'='business_focused_structural_cleanup_v1'
                   AND $15 IN ('deployment_candidate','qualified','qualified_limited')
                    THEN 'active'
                  ELSE status
                END,
                canonical_name=$2,publisher=$3,
                name_pattern=COALESCE(NULLIF($8,''),NULLIF($12::jsonb->>'displayNameContains',''),NULLIF(name_pattern,''),$2),
                publisher_pattern=COALESCE(NULLIF($9,''),NULLIF($12::jsonb->>'publisherContains',''),NULLIF(publisher_pattern,''),$3),
                provider=$10,provider_package_id=$1,target_version=$4,
                release_channel=$5,installer_type=$11,verification=$12::jsonb,execution=$13::jsonb,source_revision=$4,
                source_metadata=(source_metadata || $6::jsonb || $14::jsonb)
                  || jsonb_build_object(
                    'trustState',
                    CASE
                      WHEN source_revision=$4
                        AND source_metadata->>'trustState' IN ('rejected','signer_review_required','installer_review_required')
                        THEN source_metadata->>'trustState'
                      WHEN source_revision=$4
                        AND source_metadata->>'trustState'='direct_ready'
                        AND COALESCE($14::jsonb->>'trustState','')<>'direct_ready'
                        THEN 'direct_ready'
                      ELSE COALESCE(NULLIF($14::jsonb->>'trustState',''),source_metadata->>'trustState','version_only')
                    END,
                    'deploymentMode',
                    CASE
                      WHEN source_revision=$4
                        AND source_metadata->>'trustState' IN ('rejected','signer_review_required','installer_review_required')
                        THEN 'intelligence_only'
                      WHEN source_revision=$4
                        AND source_metadata->>'trustState'='direct_ready'
                        AND COALESCE($14::jsonb->>'trustState','')<>'direct_ready'
                        THEN 'vendor_direct'
                      ELSE COALESCE(NULLIF($14::jsonb->>'deploymentMode',''),source_metadata->>'deploymentMode','intelligence_only')
                    END
                  ),
                qualification_state=CASE
                  WHEN qualification_state='blocked' THEN qualification_state
                  WHEN source_revision IS DISTINCT FROM $4 THEN
                    CASE
                      WHEN COALESCE($14::jsonb->>'trustState','') IN ('rejected','signer_review_required','installer_review_required')
                        THEN 'intelligence_only'
                      ELSE 'deployment_candidate'
                    END
                  WHEN qualification_state IN ('qualified','qualified_limited') THEN qualification_state
                  WHEN source_revision=$4 AND source_metadata->>'trustState'='direct_ready' THEN 'deployment_candidate'
                  WHEN source_revision=$4
                    AND source_metadata->>'trustState' IN ('rejected','signer_review_required','installer_review_required') THEN 'intelligence_only'
                  ELSE $15
                END,
                qualification_version=CASE WHEN source_revision IS DISTINCT FROM $4 THEN '' ELSE qualification_version END,
                qualified_at=CASE WHEN source_revision IS DISTINCT FROM $4 THEN NULL ELSE qualified_at END,
                qualification_evidence=(
                  CASE WHEN source_revision IS DISTINCT FROM $4 THEN
                    qualification_evidence
                      - 'vendorReleaseId'
                      - 'artifactInspectionJobId'
                      - 'artifactVerificationVersion'
                      - 'artifactVerifiedAt'
                      - 'authenticodeVerified'
                      - 'sha256Verified'
                      - 'signer'
                      - 'hashProvenance'
                      - 'cleanInstallVerified'
                      - 'cleanInstallVersion'
                      - 'cleanInstallVerifiedAt'
                      - 'uninstallVerified'
                      - 'uninstallVerifiedAt'
                      - 'residueCleanupVerified'
                      - 'residueCleanupVerifiedAt'
                      - 'residueCleanupReclaimedMiB'
                      - 'automaticAdmissionVerified'
                      - 'automaticAdmissionState'
                      - 'automaticAdmissionVersion'
                      - 'automaticAdmissionVerifiedAt'
                      - 'qualificationCapabilities'
                      - 'qualificationLimitations'
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
                    ELSE qualification_evidence
                  END
                ) || $16::jsonb,
                qualification_notes=CASE WHEN qualification_notes<>'' THEN qualification_notes ELSE $17 END,
                updated_at=now()
          WHERE id=$7`,
        [
          packageId, canonicalName, publisher, normalizedVersion, channel,
          JSON.stringify({ latestSource: sourceKey, releaseDate, vendorPriority: sourcePriority }),
          existing.rows[0].id,
          clean(catalogueMetadata.namePattern),
          clean(catalogueMetadata.publisherPattern),
          catalogueProvider,
          installerType,
          JSON.stringify(verification || {}),
          JSON.stringify(execution || {}),
          JSON.stringify(catalogueMetadata || {}),
          qualificationState,
          JSON.stringify(qualificationEvidence || {}),
          clean(qualificationNotes).slice(0, 1000),
        ],
      )
    } else {
      await client.query(
        `INSERT INTO rmm_software_catalogue
          (tenant_id,canonical_name,publisher,name_pattern,publisher_pattern,provider,provider_package_id,
           target_version,release_channel,installer_type,verification,execution,catalogue_source,external_key,source_revision,source_metadata,
           qualification_state,qualification_evidence,qualification_notes)
         VALUES (NULL,$2,$3,
           COALESCE(NULLIF($7,''),NULLIF($11::jsonb->>'displayNameContains',''),$2),
           COALESCE(NULLIF($8,''),NULLIF($11::jsonb->>'publisherContains',''),$3),
           $9,$1,$4,$5,$10,$11::jsonb,$12::jsonb,'vendor',$1,$4,
           $6::jsonb || $13::jsonb,$14,$15::jsonb,$16)`,
        [
          packageId, canonicalName, publisher, normalizedVersion, channel,
          JSON.stringify({ latestSource: sourceKey, releaseDate, vendorPriority: sourcePriority }),
          clean(catalogueMetadata.namePattern),
          clean(catalogueMetadata.publisherPattern),
          catalogueProvider,
          installerType,
          JSON.stringify(verification || {}),
          JSON.stringify(execution || {}),
          JSON.stringify(catalogueMetadata || {}),
          qualificationState,
          JSON.stringify(qualificationEvidence || {}),
          clean(qualificationNotes).slice(0, 1000),
        ],
      )
    }

    await client.query(
      `UPDATE rmm_software_vendor_sources
          SET cursor_value=$2,last_success_at=now(),last_error='',records_seen=records_seen+1,
              metadata=metadata || $3::jsonb,updated_at=now()
        WHERE source_key=$1`,
      [sourceKey, normalizedVersion, JSON.stringify({ latestVersion: normalizedVersion, releaseDate })],
    )

    return normalizedVersion
  })
}
async function binding(sourceKey) {
  const result = await pool.query(
    `SELECT b.source_key,b.provider_package_id,b.canonical_name,b.publisher,b.channel,b.platform,b.architecture,
            b.metadata AS binding_metadata,s.priority,s.poll_minutes,s.source_url,s.source_type,s.metadata AS source_metadata
       FROM rmm_software_vendor_bindings b
       JOIN rmm_software_vendor_sources s ON s.source_key=b.source_key
      WHERE b.source_key=$1 AND b.enabled=true AND s.enabled=true
      ORDER BY b.id LIMIT 1`,
    [sourceKey],
  )
  return result.rows[0] || null
}

async function latestGithubTagViaRedirect(repository) {
  let current = await publicHttpsUrl('https://github.com/' + repository + '/releases/latest')
  for (let redirects = 0; redirects <= 3; redirects += 1) {
    const response = await fetch(current, {
      headers: { 'User-Agent': 'Hi5Central-Software-Catalogue/1.0' },
      redirect: 'manual',
      signal: AbortSignal.timeout(30_000),
    })
    if ([301,302,303,307,308].includes(response.status)) {
      const location = clean(response.headers.get('location'))
      if (!location) throw new Error('GitHub latest release redirected without a location')
      current = await publicHttpsUrl(new URL(location, current).toString())
      continue
    }
    if (!response.ok) {
      if (response.status >= 500) {
        try {
          const fallback = await latestGithubRelease(repository)
          const fallbackTag = clean(fallback?.tag_name || fallback?.name)
          const fallbackUrl = clean(fallback?.html_url)
          if (fallbackTag && fallbackUrl) {
            return {
              tag: fallbackTag,
              releaseUrl: (await publicHttpsUrl(fallbackUrl)).toString(),
            }
          }
        } catch {}
      }
      throw new Error('GitHub latest release HTTP ' + response.status)
    }
    const match = current.pathname.match(/\/releases\/tag\/(.+)$/)
    if (!match) throw new Error(repository + ' has no usable latest GitHub release')
    return {
      tag: decodeURIComponent(match[1]),
      releaseUrl: current.toString(),
    }
  }
  throw new Error('GitHub latest release redirected too many times')
}

function normalizedGithubVersion(value = '') {
  const raw = clean(value)
  if (/^v?\d/i.test(raw)) return releaseVersion(raw)
  const numeric = raw.match(/\d+(?:[._]\d+)+/)
  return numeric ? numeric[0].replaceAll('_', '.') : releaseVersion(raw)
}

async function matchingGithubRelease(repository, pattern) {
  const matcher = globMatcher(pattern)
  if (!matcher) throw new Error(repository + ' has an invalid releaseTagPattern')
  const response = await fetch('https://api.github.com/repos/' + repository + '/releases?per_page=50', {
    headers: githubApiHeaders(),
    signal: AbortSignal.timeout(30_000),
  })
  if (!response.ok) throw new Error('GitHub Releases HTTP ' + response.status)
  const releases = await response.json()
  const release = (Array.isArray(releases) ? releases : [])
    .find((item) => !item?.draft && matcher.test(clean(item?.tag_name)))
  if (!release) throw new Error(repository + ' has no release matching ' + pattern)
  return release
}

async function retainPreviousGithubReleaseCandidate({ sourceKey, binding: b, config, repository, currentVersion }) {
  if (!repository || !currentVersion || !['windows','cross_platform'].includes(clean(b.platform))) return null

  const eligible = await pool.query(
    `SELECT c.id FROM rmm_software_catalogue c
      WHERE c.tenant_id IS NULL AND c.status='active'
        AND c.qualification_state='deployment_candidate'
        AND c.external_key=$1 AND c.target_version=$2
        AND c.source_metadata->>'latestSource'=$3
        AND c.source_metadata->>'trustState'='direct_ready'
      LIMIT 1`,
    [b.provider_package_id, currentVersion, sourceKey],
  )
  if (!eligible.rowCount) return null
  const retained = await pool.query(
    `SELECT version FROM rmm_software_vendor_releases
      WHERE provider_package_id=$1 AND source_key=$2
        AND channel=$3 AND platform=$4 AND architecture=$5
        AND trust_state IN ('asset_candidate','direct_ready')
        AND asset_health_state IS DISTINCT FROM 'dead'
        AND installer_type IN ('msi','exe')`,
    [b.provider_package_id, sourceKey, b.channel, b.platform, b.architecture],
  )
  if (retained.rows.some((r) => !/(alpha|beta|preview|nightly|canary|rc)/i.test(r.version)
    && compareVersionValues(r.version, currentVersion) < 0)) return null

  const response = await fetch('https://api.github.com/repos/' + repository + '/releases?per_page=30', {
    headers: githubApiHeaders(),
    signal: AbortSignal.timeout(30_000),
  })
  if (!response.ok) throw new Error('GitHub release history HTTP ' + response.status)
  const payload = await response.json()
  const matcher = clean(config.releaseTagPattern) ? globMatcher(config.releaseTagPattern) : null
  if (clean(config.releaseTagPattern) && !matcher) throw new Error(repository + ' has an invalid releaseTagPattern')

  const previous = (Array.isArray(payload) ? payload : [])
    .filter((item) => !item?.draft && !item?.prerelease)
    .filter((item) => !matcher || matcher.test(clean(item?.tag_name)))
    .map((item) => ({ item, version: normalizedGithubVersion(item?.tag_name || item?.name) }))
    .filter((item) => item.version && !/(alpha|beta|preview|nightly|canary|rc)/i.test(item.version) && compareVersionValues(item.version, currentVersion) < 0)
    .filter(({ item }) => {
      const assets = Array.isArray(item?.assets) ? item.assets : []
      const pattern = globMatcher(config.assetPattern)
      const asset = pattern ? assets.find(a => pattern.test(clean(a?.name))) : selectWindowsInstallerAsset(assets, b.canonical_name)
      return asset?.browser_download_url && ['msi','exe'].includes(detectInstallerType(asset.name, clean(config.installerType).toLowerCase()))
    })
    .sort((a, bValue) => compareVersionValues(bValue.version, a.version))[0]
  if (!previous) return null

  const assets = Array.isArray(previous.item?.assets) ? previous.item.assets : []
  const installerMatch = globMatcher(config.assetPattern)
  const checksumMatch = globMatcher(config.checksumAssetPattern)
  const installer = installerMatch
    ? assets.find((asset) => installerMatch.test(clean(asset?.name)))
    : selectWindowsInstallerAsset(assets, b.canonical_name)
  const checksum = checksumMatch
    ? assets.find((asset) => checksumMatch.test(clean(asset?.name)))
    : selectChecksumAsset(assets)
  if (!installer?.browser_download_url) return null

  const installerUrl = (await publicHttpsUrl(installer.browser_download_url)).toString()
  const installerType = detectInstallerType(installer?.name, clean(config.installerType).toLowerCase())
  if (!['msi','exe'].includes(installerType)) return null
  let installerSha256 = ''
  if (checksum?.browser_download_url) {
    installerSha256 = normalizedSha256(
      await publishedChecksum(checksum.browser_download_url, installer.name).catch(() => ''),
    )
  }

  const expectedSigner = clean(config.autoExpectedSigner || config.expectedSigner || config.signerBaseline)
  const verification = { ...object(config.verificationConfig) }
  const selectedAssetReason = installerMatch ? 'configured_asset_pattern' : clean(installer?.selectionReason)
  const sourcePayload = {
    historicalReleaseCandidate: true,
    historicalRole: 'upgrade_baseline',
    github: {
      id: previous.item?.id,
      tag_name: previous.item?.tag_name,
      html_url: previous.item?.html_url,
      historical: true,
      selectedAsset: clean(installer?.name),
      selectedAssetReason,
      checksumAsset: clean(checksum?.name),
    },
    releaseUrl: clean(previous.item?.html_url),
    expectedSigner,
    signerBaseline: expectedSigner,
    deploymentMode: 'intelligence_only',
    verification,
    installArguments: clean(config.installArguments),
    trustEvidence: {
      source: 'github_release_history',
      historicalReleaseCandidate: true,
      vendorChecksumPresent: Boolean(installerSha256),
      selectedAsset: clean(installer?.name),
      selectedAssetReason,
    },
  }

  const inserted = await pool.query(
    `INSERT INTO rmm_software_vendor_releases
      (source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,
       version,release_date,installer_url,installer_sha256,installer_type,release_url,asset_name,
       trust_state,trust_evidence,source_priority,source_payload,last_seen_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18::jsonb,now())
     ON CONFLICT (source_key,provider_package_id,channel,platform,architecture,version)
     DO UPDATE SET release_date=COALESCE(EXCLUDED.release_date,rmm_software_vendor_releases.release_date),
       asset_health_state=CASE WHEN rmm_software_vendor_releases.installer_url IS DISTINCT FROM EXCLUDED.installer_url THEN 'unknown' ELSE rmm_software_vendor_releases.asset_health_state END,
       asset_last_checked_at=CASE WHEN rmm_software_vendor_releases.installer_url IS DISTINCT FROM EXCLUDED.installer_url THEN NULL ELSE rmm_software_vendor_releases.asset_last_checked_at END,
       asset_failure_count=CASE WHEN rmm_software_vendor_releases.installer_url IS DISTINCT FROM EXCLUDED.installer_url THEN 0 ELSE rmm_software_vendor_releases.asset_failure_count END,
       installer_url=EXCLUDED.installer_url,
       installer_sha256=CASE WHEN EXCLUDED.installer_sha256<>'' THEN EXCLUDED.installer_sha256 ELSE rmm_software_vendor_releases.installer_sha256 END,
       installer_type=EXCLUDED.installer_type,
       release_url=EXCLUDED.release_url,
       asset_name=EXCLUDED.asset_name,
       trust_state=CASE
         WHEN rmm_software_vendor_releases.trust_state IN ('direct_ready','rejected','signer_review_required','installer_review_required')
           THEN rmm_software_vendor_releases.trust_state
         ELSE 'asset_candidate'
       END,
       trust_evidence=rmm_software_vendor_releases.trust_evidence || EXCLUDED.trust_evidence,
       source_payload=rmm_software_vendor_releases.source_payload || EXCLUDED.source_payload,
       last_seen_at=now()
     RETURNING id,version,trust_state`,
    [
      sourceKey,b.provider_package_id,b.canonical_name,b.publisher,b.channel,b.platform,b.architecture,
      previous.version,normalizedReleaseDate(previous.item?.published_at || previous.item?.created_at),
      installerUrl,installerSha256,installerType,clean(previous.item?.html_url),clean(installer?.name),
      'asset_candidate',JSON.stringify(sourcePayload.trustEvidence),b.priority,JSON.stringify(sourcePayload),
    ],
  )

  await pool.query(
    `UPDATE rmm_software_vendor_sources
        SET metadata=metadata || $2::jsonb,updated_at=now()
      WHERE source_key=$1`,
    [sourceKey, JSON.stringify({
      retainedPreviousRelease: previous.version,
      retainedPreviousReleaseAt: new Date().toISOString(),
      retainedPreviousReleaseState: inserted.rows[0]?.trust_state || 'asset_candidate',
    })],
  )
  return inserted.rows[0] || null
}

export function jetbrainsVendorBuild(sourceKey, version, installerUrl) {
  if (!/^jetbrains_[a-z]+$/.test(sourceKey)) return ''
  if (!/^20\d{2}\.\d+(?:\.\d+)?$/.test(version)) return ''
  let url
  try { url=new URL(installerUrl) } catch { return '' }
  if (url.protocol !== 'https:' || url.hostname !== 'download.jetbrains.com') return ''
  const product=sourceKey.slice('jetbrains_'.length)
  const file=decodeURIComponent(url.pathname.split('/').at(-1) || '')
  const match=/^([a-z]+)-(\d{2})(\d)\.(\d+)\.(\d+)\.exe$/i.exec(file)
  if (!match || match[1].toLowerCase() !== product) return ''
  const major='20'+match[2]+'.'+Number(match[3])
  if (version !== major && !version.startsWith(major+'.')) return ''
  return match[2]+match[3]+'.'+match[4]+'.'+match[5]
}

async function githubInstallerContinuityCandidates(assets = [], productName = '', checksum = null) {
  const ranked = Array.isArray(assets) ? assets : []
  const candidates = []
  const seenTypes = new Set()
  for (const asset of ranked) {
    const installerType = clean(asset?.installerType || detectInstallerType(asset?.name)).toLowerCase()
    if (!['msi', 'exe'].includes(installerType) || seenTypes.has(installerType)) continue
    const rawUrl = clean(asset?.browser_download_url)
    if (!rawUrl) continue
    const installerUrl = (await publicHttpsUrl(rawUrl)).toString()
    const githubDigest = normalizedSha256(asset?.digest)
    const installerSha256 = githubDigest || normalizedSha256(
      checksum?.browser_download_url
        ? await publishedChecksum(checksum.browser_download_url, clean(asset?.name)).catch(() => '')
        : '',
    )
    if (!installerSha256) continue
    seenTypes.add(installerType)
    candidates.push({
      name: clean(asset?.name),
      url: installerUrl,
      sha256: installerSha256,
      installerType,
      installerTechnology: installerType === 'msi' ? 'msi' : 'generic',
      selectionReason: clean(asset?.selectionReason),
    })
  }
  return candidates
}

async function syncGenericConfigured(sourceKey, state) {
  const b = await binding(sourceKey)
  if (!b) return null
  const config = { ...object(b.source_metadata), ...object(b.binding_metadata) }
  const parser = object(config.parserConfig)
  let version = ''
  let releaseDate = null
  let installerUrl = ''
  let installerSha256 = ''
  let resolvedInstallerType = clean(config.installerType).toLowerCase()
  let releaseUrl = ''
  let verificationProductCode = ''
  let verificationVendorBuild = ''
  let selectedAssetReason = ''
  let installerContinuityCandidates = []
  let payload = {}

  if (state.source_type === 'winget_manifest') {
    const packageId = clean(config.wingetPackageId || config.packageId)
    if (!packageId) throw new Error(sourceKey + ' has no WinGet package ID')
    const resolved = await resolveWingetVendorInstaller(packageId)
    if (!resolved.ok) throw new Error(sourceKey + ' WinGet manifest: ' + clean(resolved.reason || 'installer unavailable'))
    version = clean(resolved.version)
    installerUrl = (await publicHttpsUrl(resolved.installerUrl)).toString()
    installerSha256 = normalizedSha256(resolved.installerSha256)
    resolvedInstallerType = clean(resolved.installerType)
    config.installerTechnology = clean(resolved.installerTechnology || config.installerTechnology)
    releaseUrl = clean(resolved.manifestUrl)
    verificationProductCode = clean(resolved.productCode)
    selectedAssetReason = 'winget_manifest_upstream_installer'
    payload = {
      wingetManifest: {
        packageId: resolved.packageId,
        packageName: resolved.name,
        version: resolved.version,
        manifestUrl: resolved.manifestUrl,
        upstreamHost: resolved.upstreamHost,
        architecture: resolved.architecture,
        installerTechnology: resolved.installerTechnology,
        productCode: clean(resolved.productCode),
        scope: resolved.scope,
      },
    }
    if (
      clean(resolved.installArguments)
      && (
        !clean(config.installArguments)
        || lower(packageId) === '3dconnexion.3dxware.10'
      )
    ) {
      config.installArguments = clean(resolved.installArguments)
    }
  } else if (state.source_type === 'github_releases') {
    const repository = repositoryName(config.repository || state.source_url)
    if (!repository) throw new Error(sourceKey + ' has no valid GitHub repository')
    if (!clean(config.releaseTagPattern) && !clean(config.assetPattern) && !clean(config.checksumAssetPattern)) {
      const lightweight = await latestGithubTagViaRedirect(repository)
      version = normalizedGithubVersion(lightweight.tag)
      releaseUrl = lightweight.releaseUrl
      const discovery = await discoverGithubWindowsInstaller(repository, lightweight.tag, b.canonical_name)
      const installer = discovery.installer
      const checksum = discovery.checksum
      selectedAssetReason = clean(installer?.selectionReason)
      installerUrl = clean(installer?.browser_download_url)
      if (installer && checksum) {
        installerSha256 = await publishedChecksum(checksum.browser_download_url, installer.name).catch(() => '')
      }
      installerContinuityCandidates = await githubInstallerContinuityCandidates(
        discovery.installers,
        b.canonical_name,
        checksum,
      )
      resolvedInstallerType = detectInstallerType(installer?.name, resolvedInstallerType)
      payload = { github: {
        tag_name: lightweight.tag,
        html_url: lightweight.releaseUrl,
        lightweight: true,
        automaticAssetDiscovery: true,
        assetsSeen: discovery.assetsSeen,
        selectedAsset: clean(installer?.name),
        selectedAssetReason,
        checksumAsset: clean(checksum?.name),
        installers: installerContinuityCandidates,
      } }
    } else {
      const release = clean(config.releaseTagPattern)
        ? await matchingGithubRelease(repository, config.releaseTagPattern)
        : await latestGithubRelease(repository)
      version = normalizedGithubVersion(release?.tag_name || release?.name)
      releaseDate = normalizedReleaseDate(release?.published_at || release?.created_at)
      releaseUrl = clean(release?.html_url)
      const assets = Array.isArray(release?.assets) ? release.assets : []
      const installerMatch = globMatcher(config.assetPattern)
      const checksumMatch = globMatcher(config.checksumAssetPattern)
      const installer = installerMatch
        ? assets.find((asset) => installerMatch.test(clean(asset?.name)))
        : selectWindowsInstallerAsset(assets, b.canonical_name)
      const checksum = checksumMatch
        ? assets.find((asset) => checksumMatch.test(clean(asset?.name)))
        : selectChecksumAsset(assets)
      selectedAssetReason = installerMatch ? 'configured_asset_pattern' : clean(installer?.selectionReason)
      installerUrl = clean(installer?.browser_download_url)
      if (installer && checksum) {
        installerSha256 = await publishedChecksum(checksum.browser_download_url, installer.name).catch(() => '')
      }
      installerContinuityCandidates = await githubInstallerContinuityCandidates(
        rankWindowsInstallerAssets(assets, b.canonical_name),
        b.canonical_name,
        checksum,
      )
      resolvedInstallerType = detectInstallerType(installer?.name, resolvedInstallerType)
      payload = { github: {
        id: release?.id,
        tag_name: release?.tag_name,
        html_url: release?.html_url,
        lightweight: false,
        releaseTagPattern: clean(config.releaseTagPattern),
        selectedAsset: clean(installer?.name),
        selectedAssetReason,
        checksumAsset: clean(checksum?.name),
        installers: installerContinuityCandidates,
      } }
    }
  } else if (state.source_type === 'gitlab_releases') {
    const releases = await fetchPublicJson(state.source_url)
    const release = Array.isArray(releases) ? releases[0] : null
    if (!release) throw new Error(sourceKey + ' returned no GitLab releases')
    const rawVersion = clean(release.tag_name || release.name)
    const numeric = rawVersion.match(/\d+(?:[._-]\d+)+/)
    version = releaseVersion(numeric ? numeric[0].replaceAll('_', '.') : rawVersion)
    releaseDate = normalizedReleaseDate(release.released_at || release.created_at)
    releaseUrl = clean(release?._links?.self || release?._links?.tag || '')
    payload = { gitlab: { name: release.name, tag_name: release.tag_name, released_at: release.released_at } }
  } else if (state.source_type === 'vendor_html') {
    const recipe = object(config.htmlRecipe)
    const compliance = await evaluateVendorHtmlAutomation(
      state.source_url,
      object(config.automationPolicy),
      state.poll_minutes,
    )
    await pool.query(
      `UPDATE rmm_software_vendor_sources
          SET metadata=metadata || $2::jsonb,updated_at=now()
        WHERE source_key=$1`,
      [sourceKey, JSON.stringify({ automationCompliance: compliance })],
    )
    const body = await fetchPublicText(state.source_url, {
      accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
      maxBytes: 8 * 1024 * 1024,
    })
    const candidates = parseVendorHtmlReleases(body, state.source_url, recipe)
    if (!candidates.length) throw new Error(sourceKey + ' HTML recipe returned no stable Windows installer candidates')
    const latest = candidates.at(-1)
    if (!htmlHostAllowed(state.source_url, recipe.allowedHosts)) {
      throw new Error(sourceKey + ' source page host is not allowed by htmlRecipe.allowedHosts')
    }
    if (!htmlHostAllowed(latest.installerUrl, recipe.allowedHosts)) {
      throw new Error(sourceKey + ' installer host is not allowed by htmlRecipe.allowedHosts')
    }
    const downloadProbe = await resolveAllowedPublicDownload(latest.installerUrl, recipe.allowedHosts)
    version = clean(latest.version)
    installerUrl = downloadProbe.url
    installerSha256 = normalizedSha256(latest.installerSha256)
    resolvedInstallerType = detectInstallerType(latest.assetName || new URL(installerUrl).pathname, resolvedInstallerType)
    releaseDate = normalizedReleaseDate(latest.releaseDate)
    releaseUrl = latest.releaseUrl ? (await publicHttpsUrl(latest.releaseUrl)).toString() : state.source_url
    selectedAssetReason = 'vendor_html_recipe'
    payload = {
      html: {
        recipeVersion: 1,
        compliance,
        sourceUrl: state.source_url,
        selected: {
          version,
          installerUrl,
          installerSha256,
          installerType: resolvedInstallerType,
          assetName: latest.assetName,
          releaseDate,
          releaseUrl,
          finalDownloadUrl: downloadProbe.url,
          downloadContentType: downloadProbe.contentType,
          downloadContentLength: downloadProbe.contentLength,
        },
        candidatesSeen: candidates.slice(-Math.max(2, Number(recipe.previousStableCount || 1) + 1)).map((item) => ({
          version: item.version,
          installerUrl: item.installerUrl,
          assetName: item.assetName,
          releaseDate: item.releaseDate,
          sha256Present: Boolean(item.installerSha256),
        })),
        allowedHosts: recipe.allowedHosts,
      },
    }
  } else if (state.source_type === 'vendor_json') {
    let vendorJsonUrl = state.source_url
    if (/^jetbrains_[a-z0-9_]+$/.test(sourceKey)) {
      const historyUrl = new URL(state.source_url)
      historyUrl.searchParams.delete('latest')
      vendorJsonUrl = historyUrl.toString()
    }
    const response = await fetchPublicJson(vendorJsonUrl)
    if (/^jetbrains_[a-z0-9_]+$/.test(sourceKey)) {
      const product = Array.isArray(response) ? response[0] : response
      const releases = (Array.isArray(product?.releases) ? product.releases : [])
        .filter((item) => lower(item?.type) === 'release')
        .filter((item) => /^20\d{2}\.\d+(?:\.\d+)?$/.test(clean(item?.version)))
        .filter((item) => clean(item?.downloads?.windows?.link))
        .sort((a, b) => compareVersionValues(clean(a.version), clean(b.version)))
      const latest = releases.at(-1)
      if (!latest) throw new Error(sourceKey + ' returned no stable JetBrains Windows release')
      version = clean(latest.version)
      releaseDate = normalizedReleaseDate(latest.date)
      const windows = object(latest.downloads?.windows)
      installerUrl = (await publicHttpsUrl(clean(windows.link))).toString()
      const checksumUrl = clean(windows.checksumLink)
      if (checksumUrl) {
        const checksumText = await fetchPublicText(checksumUrl, { maxBytes: 1024 * 1024 })
        installerSha256 = normalizedSha256(clean(checksumText).split(/\s+/)[0])
      }
      if (!installerSha256) throw new Error(sourceKey + ' stable Windows release did not include a usable SHA-256')
      resolvedInstallerType = detectInstallerType(new URL(installerUrl).pathname, resolvedInstallerType)
      releaseUrl = vendorJsonUrl
      verificationVendorBuild = clean(latest.build)
      selectedAssetReason = 'vendor_stable_release'
      payload = { jetbrains: {
        version,
        build: verificationVendorBuild,
        type: clean(latest.type),
        date: clean(latest.date),
        installerUrl,
        checksumUrl,
        stable: true,
      } }
    } else if (sourceKey === 'go_golang') {
      const releases = Array.isArray(response) ? response : []
      const latest = releases.find((item) => item?.stable !== false) || releases[0]
      if (!latest?.version) throw new Error('Go release feed returned no stable release')
      version = clean(latest.version)
      const file = (Array.isArray(latest.files) ? latest.files : []).find((item) =>
        clean(item?.os) === 'windows'
        && clean(item?.arch) === 'amd64'
        && clean(item?.kind) === 'installer'
        && clean(item?.filename).toLowerCase().endsWith('.msi')
      )
      if (!file) throw new Error('Go release feed returned no Windows amd64 MSI installer')
      installerUrl = (await publicHttpsUrl('https://go.dev/dl/' + clean(file.filename))).toString()
      installerSha256 = normalizedSha256(file.sha256)
      resolvedInstallerType = 'msi'
      releaseUrl = 'https://go.dev/dl/'
      selectedAssetReason = 'vendor_published_installer'
      payload = { go: { version: latest.version, filename: file.filename, sha256: file.sha256, kind: file.kind } }
    } else if (sourceKey === 'nodejs') {
      const releases = Array.isArray(response) ? response : []
      const latest = releases[0]
      const rawVersion = clean(latest?.version)
      if (!rawVersion) throw new Error('Node.js release feed returned no current release')
      version = releaseVersion(rawVersion)
      const files = Array.isArray(latest?.files) ? latest.files : []
      if (!files.includes('win-x64-msi')) throw new Error('Node.js release feed did not advertise a Windows x64 MSI')
      const filename = 'node-' + rawVersion + '-x64.msi'
      const distBase = 'https://nodejs.org/dist/' + rawVersion + '/'
      installerUrl = (await publicHttpsUrl(distBase + filename)).toString()
      const shasums = await fetchPublicText(distBase + 'SHASUMS256.txt', { maxBytes: 2 * 1024 * 1024 })
      const checksumLine = shasums.split(/\r?\n/).find((line) => line.trim().endsWith('  ' + filename))
      installerSha256 = normalizedSha256(clean(checksumLine).split(/\s+/)[0])
      if (!installerSha256) throw new Error('Node.js SHASUMS256.txt did not contain ' + filename)
      resolvedInstallerType = 'msi'
      releaseDate = normalizedReleaseDate(latest?.date)
      releaseUrl = distBase
      selectedAssetReason = 'vendor_published_installer'
      payload = { nodejs: { version: rawVersion, filename, sha256: installerSha256, files } }
    } else {
      version = releaseVersion(jsonPathValue(response, parser.versionPath))
      releaseDate = normalizedReleaseDate(jsonPathValue(response, parser.releaseDatePath))
      releaseUrl = clean(jsonPathValue(response, parser.releaseUrlPath))
      const rawInstaller = clean(jsonPathValue(response, parser.installerUrlPath))
      if (rawInstaller) installerUrl = (await publicHttpsUrl(new URL(rawInstaller, state.source_url).toString())).toString()
      installerSha256 = normalizedSha256(jsonPathValue(response, parser.sha256Path))
      verificationProductCode = clean(jsonPathValue(response, parser.productCodePath))
      if (verificationProductCode && !/^\{[0-9A-Fa-f-]{36}\}$/.test(verificationProductCode)) {
        throw new Error(sourceKey + ' returned an invalid MSI ProductCode')
      }
      resolvedInstallerType = detectInstallerType(installerUrl ? new URL(installerUrl).pathname : '', resolvedInstallerType)
      payload = { json: { paths: parser, selected: { version, releaseDate, releaseUrl, installerUrl: rawInstaller, productCode: verificationProductCode } } }
    }
  } else if (state.source_type === 'python_releases') {
    const releases = await fetchPublicJson(state.source_url)
    const candidates = (Array.isArray(releases) ? releases : [])
      .filter((item) => item?.is_published !== false && !item?.pre_release)
      .map((item) => ({ item, version: clean(item?.name).match(/^Python\s+(\d+\.\d+\.\d+)$/i)?.[1] || '' }))
      .filter((item) => item.version)
      .sort((a, b) => compareVersionValues(a.version, b.version))
    const latest = candidates.at(-1)
    if (!latest) throw new Error(sourceKey + ' returned no stable Python release')
    version = latest.version
    releaseDate = normalizedReleaseDate(latest.item.release_date)
    const releaseId = clean(latest.item.resource_uri).match(/\/release\/(\d+)\/?$/)?.[1] || ''
    if (!releaseId) throw new Error(sourceKey + ' latest Python release has no usable release ID')
    const files = await fetchPublicJson('https://www.python.org/api/v2/downloads/release_file/?release=' + releaseId)
    const installer = (Array.isArray(files) ? files : []).find((item) =>
      /^Windows installer \(64-bit\)$/i.test(clean(item?.name))
      && clean(item?.url).toLowerCase().endsWith('-amd64.exe')
    )
    if (!installer?.url) throw new Error(sourceKey + ' returned no Windows 64-bit installer')
    installerUrl = (await publicHttpsUrl(installer.url)).toString()
    installerSha256 = normalizedSha256(installer.sha256_sum)
    if (!installerSha256) throw new Error(sourceKey + ' Windows installer did not include SHA-256')
    resolvedInstallerType = 'exe'
    releaseUrl = clean(latest.item.resource_uri)
    selectedAssetReason = 'vendor_published_installer'
    payload = {
      python: {
        name: latest.item.name,
        slug: latest.item.slug,
        release_date: latest.item.release_date,
        releaseId,
        installer: installer.name,
        sha256: installer.sha256_sum,
      },
    }
  } else if (state.source_type === 'hashicorp_releases') {
    const response = JSON.parse(await fetchPublicText(state.source_url, {
      accept: 'application/vnd+hashicorp.releases-api.v0+json, application/json',
      maxBytes: 5 * 1024 * 1024,
    }))
    const versions = Object.keys(object(response?.versions))
      .filter((item) => /^\d+\.\d+\.\d+$/.test(item))
      .sort(compareVersionValues)
    version = versions.at(-1) || ''
    const selected = object(response?.versions?.[version])
    const build = (Array.isArray(selected.builds) ? selected.builds : [])
      .find((item) => clean(item?.os) === 'windows' && clean(item?.arch) === 'amd64')
    installerUrl = build?.url ? (await publicHttpsUrl(build.url)).toString() : ''
    releaseUrl = version ? new URL(version + '/', new URL('.', state.source_url)).toString() : ''
    payload = { hashicorp: { version, filename: build?.filename || '', shasums: selected.shasums || '' } }
  } else if (state.source_type === 'adoptium') {
    const info = await fetchPublicJson(state.source_url)
    const lts = Number(info?.most_recent_lts || 0)
    if (!lts) throw new Error(sourceKey + ' returned no current Adoptium LTS')
    const assetsUrl = 'https://api.adoptium.net/v3/assets/latest/' + lts + '/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse'
    const assets = await fetchPublicJson(assetsUrl)
    const asset = Array.isArray(assets) ? assets[0] : null
    if (!asset) throw new Error(sourceKey + ' returned no Windows x64 JDK asset')
    version = clean(asset?.version?.openjdk_version || asset?.version?.semver || asset?.release_name)
    releaseDate = normalizedReleaseDate(asset?.binary?.updated_at)
    releaseUrl = clean(asset?.release_link)
    const installer = asset?.binary?.installer
    installerUrl = installer?.link ? (await publicHttpsUrl(installer.link)).toString() : ''
    installerSha256 = normalizedSha256(installer?.checksum)
    resolvedInstallerType = detectInstallerType(installer?.name, resolvedInstallerType)
    payload = { adoptium: { lts, release_name: asset.release_name, installer: installer?.name || '' } }
  } else if (state.source_type === 'package_registry') {
    const registry = clean(config.registry).toLowerCase()
    const registryPackage = clean(config.registryPackage)
    if (registry === 'chocolatey') {
      const body = await fetchPublicText(state.source_url, {
        accept: 'application/atom+xml, application/xml',
        maxBytes: 5 * 1024 * 1024,
      })
      const entries = [...body.matchAll(/<entry>[\s\S]*?<\/entry>/gi)].map((match) => match[0])
      const latest = entries.find((entry) =>
        /<d:IsLatestVersion[^>]*>true<\/d:IsLatestVersion>/i.test(entry)
        && /<d:IsPrerelease[^>]*>false<\/d:IsPrerelease>/i.test(entry)
      ) || entries[0] || ''
      version = clean(latest.match(/<d:Version[^>]*>([^<]+)<\/d:Version>/i)?.[1])
      releaseDate = normalizedReleaseDate(latest.match(/<d:Published[^>]*>([^<]+)<\/d:Published>/i)?.[1])
      releaseUrl = clean(latest.match(/<d:GalleryDetailsUrl[^>]*>([^<]+)<\/d:GalleryDetailsUrl>/i)?.[1])
      payload = { registry: { registry, package: registryPackage, latest: version } }
    } else {
      let response
      if (registry === 'snapcraft') {
        const url = await publicHttpsUrl(state.source_url)
        const raw = await fetch(url, {
          headers: {
            Accept: 'application/json',
            'Snap-Device-Series': '16',
            'User-Agent': 'Hi5Central-Software-Catalogue/1.0',
          },
          signal: AbortSignal.timeout(60_000),
        })
        if (!raw.ok) throw new Error('Snapcraft HTTP ' + raw.status)
        response = await raw.json()
      } else {
        response = await fetchPublicJson(state.source_url)
      }

      if (registry === 'npm') {
        version = clean(response?.version)
        releaseUrl = clean(response?.homepage || response?.repository?.url)
      } else if (registry === 'pypi') {
        version = clean(response?.info?.version)
        releaseUrl = clean(response?.info?.project_url || response?.info?.package_url || response?.info?.home_page)
      } else if (registry === 'crates') {
        version = clean(response?.crate?.max_stable_version || response?.crate?.max_version || response?.crate?.newest_version)
        releaseUrl = clean(response?.crate?.repository || response?.crate?.homepage)
      } else if (registry === 'rubygems') {
        version = clean(response?.version)
        releaseDate = normalizedReleaseDate(response?.version_created_at)
        releaseUrl = clean(response?.project_uri || response?.homepage_uri)
      } else if (registry === 'nuget') {
        const versions = (Array.isArray(response?.versions) ? response.versions : [])
          .filter((item) => /^\d+(?:\.\d+)+(?:\.\d+)?$/.test(clean(item)))
          .sort(compareVersionValues)
        version = clean(versions.at(-1))
      } else if (registry === 'packagist') {
        const releases = Array.isArray(response?.packages?.[registryPackage])
          ? response.packages[registryPackage]
          : []
        const stable = releases.find((item) => /^v?\d+(?:\.\d+)+$/.test(clean(item?.version)))
          || releases.find((item) => !/[A-Za-z-](?:dev|alpha|beta|rc)/i.test(clean(item?.version)))
          || releases[0]
        version = releaseVersion(clean(stable?.version_normalized || stable?.version).replace(/\.0$/, ''))
        releaseDate = normalizedReleaseDate(stable?.['published-time'] || stable?.time)
        releaseUrl = clean(stable?.source?.url || stable?.support?.source)
      } else if (registry === 'snapcraft') {
        const channels = Array.isArray(response?.['channel-map']) ? response['channel-map'] : []
        const stable = channels.find((item) =>
          clean(item?.channel?.architecture).toLowerCase() === 'amd64'
          && clean(item?.channel?.risk).toLowerCase() === 'stable'
          && clean(item?.channel?.track).toLowerCase() === 'latest'
        ) || channels.find((item) => clean(item?.channel?.risk).toLowerCase() === 'stable')
        version = clean(stable?.version)
        releaseDate = normalizedReleaseDate(stable?.channel?.['released-at'] || stable?.['created-at'])
      } else if (registry === 'flathub') {
        const releases = (Array.isArray(response?.releases) ? response.releases : [])
          .filter((item) => clean(item?.type).toLowerCase() !== 'development')
          .sort((a, b) => Number(a?.timestamp || 0) - Number(b?.timestamp || 0))
        const latest = releases.at(-1) || releases[0]
        version = clean(latest?.version)
        if (latest?.timestamp) releaseDate = new Date(Number(latest.timestamp) * 1000).toISOString()
        releaseUrl = clean(response?.urls?.homepage || response?.urls?.bugtracker)
      } else if (registry === 'apple') {
        const results = Array.isArray(response?.results) ? response.results : []
        const expected = clean(b.canonical_name).toLowerCase()
        const latest = results.find((item) =>
          clean(item?.trackName || item?.trackCensoredName).toLowerCase() === expected
        ) || results[0]
        version = clean(latest?.version)
        releaseDate = normalizedReleaseDate(latest?.currentVersionReleaseDate)
        releaseUrl = clean(latest?.trackViewUrl)
        if (latest?.bundleId) payload = { registry: { registry, package: latest.bundleId, searchedFor: registryPackage, latest: version } }
      } else if (registry === 'go') {
        version = releaseVersion(clean(response?.Version))
        releaseDate = normalizedReleaseDate(response?.Time)
        releaseUrl = clean(response?.Origin?.URL)
      } else if (registry === 'maven') {
        const latest = Array.isArray(response?.response?.docs) ? response.response.docs[0] : null
        version = clean(latest?.latestVersion)
        releaseDate = latest?.timestamp ? new Date(Number(latest.timestamp)).toISOString() : null
      } else if (registry === 'homebrew') {
        version = clean(response?.version)
        releaseUrl = clean(response?.homepage)
      } else {
        throw new Error(sourceKey + ' uses unsupported package registry ' + registry)
      }
      payload = {
        registry: {
          registry,
          package: registryPackage,
          group: clean(config.registryGroup),
          artifact: clean(config.registryArtifact),
          latest: version,
          osvEcosystem: clean(config.osvEcosystem),
          osvPackage: clean(config.osvPackage),
        },
      }
    }
  } else if (state.source_type === 'vendor_text') {
    const body = await fetchPublicText(state.source_url, { maxBytes: 5 * 1024 * 1024 })
    if (config.adapter === 'signal_yaml') {
      version = clean(body.match(/^version:\s*([^\s]+)\s*$/mi)?.[1])
      releaseDate = normalizedReleaseDate(body.match(/^releaseDate:\s*['"]?([^'"\r\n]+)['"]?\s*$/mi)?.[1])
      const path = clean(body.match(/^path:\s*([^\s]+)\s*$/mi)?.[1])
      installerUrl = path ? (await publicHttpsUrl(new URL(path, state.source_url).toString())).toString() : ''
      resolvedInstallerType = detectInstallerType(path, resolvedInstallerType)
      payload = { text: { adapter: config.adapter, path } }
    } else if (config.adapter === 'vlc_directory') {
      const match = body.match(/vlc-([0-9]+(?:\.[0-9]+)+)-win64\.exe/i)
      version = clean(match?.[1])
      const name = match?.[0] || ''
      installerUrl = name ? (await publicHttpsUrl(new URL(name, state.source_url).toString())).toString() : ''
      resolvedInstallerType = detectInstallerType(name, resolvedInstallerType)
      payload = { text: { adapter: config.adapter, filename: name } }
    } else if (config.adapter === 'element_windows_index') {
      const candidates = [...body.matchAll(
        /href="(Element Setup ([0-9]+(?:\.[0-9]+)+)\.exe)"[\s\S]{0,350}?<td class="date">([^<]+)<\/td>/gi,
      )].map((match) => ({
        name: clean(match[1]),
        version: clean(match[2]),
        date: clean(match[3]),
      })).filter((item) => item.name && item.version)
      candidates.sort((a, b) => compareVersionValues(a.version, b.version))
      const latest = candidates.at(-1)
      if (!latest) throw new Error(sourceKey + ' returned no versioned Windows x64 Element installer')
      version = latest.version
      releaseDate = normalizedReleaseDate(latest.date)
      installerUrl = (await publicHttpsUrl(new URL(latest.name, state.source_url).toString())).toString()
      resolvedInstallerType = 'exe'
      releaseUrl = state.source_url
      selectedAssetReason = 'official_vendor_channel_installer'
      payload = { text: { adapter: config.adapter, filename: latest.name, version, releaseDate } }
    } else if (config.adapter === 'grafana_windows_download') {
      const match = body.match(
        /SHA256:\s*(?:<!-- -->)?([a-f0-9]{64})[\s\S]{0,1000}?href="(https:\/\/dl\.grafana\.com\/grafana\/release\/([0-9.]+)\/grafana_[^"]+_windows_amd64\.msi)"/i,
      )
      if (!match) throw new Error(sourceKey + ' returned no Grafana Windows amd64 MSI metadata')
      installerSha256 = normalizedSha256(match[1])
      installerUrl = (await publicHttpsUrl(match[2])).toString()
      version = clean(match[3])
      resolvedInstallerType = 'msi'
      releaseUrl = state.source_url
      selectedAssetReason = 'vendor_published_installer'
      payload = { text: { adapter: config.adapter, version, installerUrl, sha256: installerSha256 } }
    } else if (config.adapter === 'nextcloud_windows_index') {
      const candidates = [...body.matchAll(
        /href="(Nextcloud-([0-9]+(?:\.[0-9]+)+)-x64\.msi)"/gi,
      )].map((match) => ({
        name: clean(match[1]),
        version: clean(match[2]),
      })).filter((item) => item.name && item.version)
      candidates.sort((a, b) => compareVersionValues(a.version, b.version))
      const latest = candidates.at(-1)
      if (!latest) throw new Error(sourceKey + ' returned no versioned Windows x64 Nextcloud MSI')
      version = latest.version
      installerUrl = (await publicHttpsUrl(new URL(latest.name, state.source_url).toString())).toString()
      resolvedInstallerType = 'msi'
      releaseUrl = state.source_url
      selectedAssetReason = 'official_vendor_channel_installer'
      payload = { text: { adapter: config.adapter, filename: latest.name, version } }
    } else if (config.adapter === 'qgis_windows_download') {
      const candidates = [...body.matchAll(
        /href=["']?(https:\/\/download\.qgis\.org\/downloads\/(QGIS-OSGeo4W-([0-9]+(?:\.[0-9]+)+)-[0-9]+\.msi))/gi,
      )].map((match) => ({
        url: clean(match[1]),
        name: clean(match[2]),
        version: clean(match[3]),
      })).filter((item) => item.url && item.version)
      candidates.sort((a, b) => compareVersionValues(a.version, b.version))
      const latest = candidates.at(-1)
      if (!latest) throw new Error(sourceKey + ' returned no current QGIS Windows MSI')
      version = latest.version
      installerUrl = (await publicHttpsUrl(latest.url)).toString()
      const metaUrl = await publicHttpsUrl('https://dl1.qgis.org/downloads/' + latest.name + '.meta4')
      const metalink = await fetchPublicText(metaUrl.toString(), { maxBytes: 2 * 1024 * 1024 })
      installerSha256 = normalizedSha256(
        metalink.match(/<hash\s+type=["']sha-256["']>([a-f0-9]{64})<\/hash>/i)?.[1],
      )
      if (!installerSha256) throw new Error(sourceKey + ' QGIS Metalink did not contain SHA-256')
      resolvedInstallerType = 'msi'
      releaseUrl = state.source_url
      selectedAssetReason = 'vendor_published_installer'
      payload = {
        text: {
          adapter: config.adapter,
          filename: latest.name,
          version,
          sha256: installerSha256,
          metalink: metaUrl.toString(),
        },
      }
    } else if (config.adapter === 'gimp_windows_index') {
      const candidates = [...body.matchAll(
        /href="(gimp-([0-9]+(?:\.[0-9]+)+)-setup\.exe)"/gi,
      )].map((match) => ({
        name: clean(match[1]),
        version: clean(match[2]),
      })).filter((item) => item.name && item.version)
      candidates.sort((a, b) => compareVersionValues(a.version, b.version))
      const latest = candidates.at(-1)
      if (!latest) throw new Error(sourceKey + ' returned no stable GIMP Windows setup executable')
      version = latest.version
      installerUrl = (await publicHttpsUrl(new URL(latest.name, state.source_url).toString())).toString()
      const sumsUrl = await publicHttpsUrl(new URL('SHA256SUMS', state.source_url).toString())
      const sums = await fetchPublicText(sumsUrl.toString(), { maxBytes: 2 * 1024 * 1024 })
      const checksumLine = sums.split(/\r?\n/).find((line) => line.trim().endsWith('  ' + latest.name))
      installerSha256 = normalizedSha256(clean(checksumLine).split(/\s+/)[0])
      if (!installerSha256) throw new Error(sourceKey + ' GIMP SHA256SUMS did not contain ' + latest.name)
      resolvedInstallerType = 'exe'
      releaseUrl = state.source_url
      selectedAssetReason = 'vendor_published_installer'
      payload = {
        text: {
          adapter: config.adapter,
          filename: latest.name,
          version,
          sha256: installerSha256,
          sums: sumsUrl.toString(),
        },
      }
    } else if (config.adapter === 'wazuh_windows_packages') {
      const matches = [...body.matchAll(
        /href="(https:\/\/packages\.wazuh\.com\/4\.x\/windows\/(wazuh-agent-([0-9]+(?:\.[0-9]+)+)-([0-9]+)\.msi))"/gi,
      )].map((match) => ({
        url: clean(match[1]),
        name: clean(match[2]),
        version: clean(match[3]),
        revision: Number(match[4] || 0),
      }))
      matches.sort((a, b) => compareVersionValues(a.version, b.version) || a.revision - b.revision)
      const latest = matches.at(-1)
      if (!latest) throw new Error(sourceKey + ' returned no Wazuh Windows MSI package')
      version = latest.version
      installerUrl = (await publicHttpsUrl(latest.url)).toString()
      resolvedInstallerType = 'msi'
      releaseUrl = state.source_url
      selectedAssetReason = 'official_vendor_channel_installer'
      payload = {
        text: {
          adapter: config.adapter,
          filename: latest.name,
          version,
          revision: latest.revision,
        },
      }
    } else if (config.adapter === 'jenkins_jsonp') {
      const wrapped = body.match(/^\s*updateCenter\.post\(([\s\S]*)\);?\s*$/)
      if (!wrapped) throw new Error(sourceKey + ' returned invalid Jenkins update-center JSONP')
      const response = JSON.parse(wrapped[1])
      version = clean(response?.core?.version)
      releaseDate = normalizedReleaseDate(response?.core?.buildDate)
      installerUrl = response?.core?.url ? (await publicHttpsUrl(response.core.url)).toString() : ''
      if (response?.core?.sha256) installerSha256 = Buffer.from(response.core.sha256, 'base64').toString('hex').toUpperCase()
      payload = { text: { adapter: config.adapter, core: { version, url: installerUrl } } }
    } else {
      throw new Error(sourceKey + ' has an unsupported vendor text adapter')
    }
  } else if (state.source_type === 'static_release') {
    version = releaseVersion(config.staticVersion)
    installerUrl = config.staticInstallerUrl ? (await publicHttpsUrl(config.staticInstallerUrl)).toString() : ''
    installerSha256 = normalizedSha256(config.staticSha256)
    releaseUrl = config.staticReleaseUrl ? (await publicHttpsUrl(config.staticReleaseUrl)).toString() : ''
    resolvedInstallerType = detectInstallerType(installerUrl ? new URL(installerUrl).pathname : '', resolvedInstallerType)
    payload = { static: { version, installerUrl, releaseUrl } }
  } else {
    throw new Error('No generic software vendor resolver for source type ' + state.source_type)
  }

  if (!version) throw new Error(sourceKey + ' returned no usable release version')
  if (!installerSha256 && clean(config.trustedReleaseVersion) === clean(version)) {
    installerSha256 = normalizedSha256(config.trustedReleaseSha256)
  }
  const verification = { ...object(config.verificationConfig) }
  if (verificationProductCode) {
    verification.productCode = verificationProductCode
    if (clean(verification.method || verification.provider || 'winget') === 'winget') {
      verification.method = 'uninstall_registry'
      verification.packageId = ''
    }
  }
  const jetbrainsBuild = verificationVendorBuild || jetbrainsVendorBuild(sourceKey,version,installerUrl)
  if (jetbrainsBuild && resolvedInstallerType === 'exe') {
    verification.versionTransform = 'jetbrains_vendor_build'
    verification.releaseVersion = version
    verification.vendorBuild = jetbrainsBuild
    config.installArguments = '/S'
  }
  const wingetPackageId = clean(config.wingetPackageId || config.autoWingetPackageId)
  const configuredExpectedSigner = clean(config.autoExpectedSigner || config.expectedSigner)
  const configuredDeploymentMode = clean(config.autoDeploymentMode || config.deploymentMode)
  const trust = vendorReleaseTrustProfile({
    installerUrl,
    installerSha256,
    installerType: resolvedInstallerType,
    publisher: b.publisher,
    expectedSigner: configuredExpectedSigner,
    verification,
    wingetPackageId,
    deploymentMode: configuredDeploymentMode,
  })
  const deploymentMode = trust.deploymentMode
  const trustState = trust.trustState
  const expectedSigner = trust.expectedSigner || configuredExpectedSigner
  const selectedAssetName = installerUrl
    ? decodeURIComponent(new URL(installerUrl).pathname.split('/').filter(Boolean).at(-1) || '')
    : ''
  const qualificationEvidence = {
    ...trust.evidence,
    sourceKey,
    releaseUrl,
    selectedAsset: selectedAssetName,
    selectedAssetReason,
  }

  if (state.source_type === 'github_releases' || state.source_type === 'vendor_html') {
    try {
      if (state.source_type === 'vendor_html') {
        await retainPreviousHtmlReleaseCandidate({
          sourceKey,
          binding: b,
          config,
          currentVersion: version,
        })
      } else {
        await retainPreviousGithubReleaseCandidate({
          sourceKey,
          binding: b,
          config,
          repository: repositoryName(config.repository || state.source_url),
          currentVersion: version,
        })
      }
      await pool.query(
        `UPDATE rmm_software_vendor_sources
            SET metadata=metadata - 'previousReleaseRetentionError',updated_at=now()
          WHERE source_key=$1`,
        [sourceKey],
      )
    } catch (error) {
      await pool.query(
        `UPDATE rmm_software_vendor_sources
            SET metadata=metadata || $2::jsonb,updated_at=now()
          WHERE source_key=$1`,
        [sourceKey, JSON.stringify({
          previousReleaseRetentionError: clean(error?.message || error).slice(0, 1000),
          previousReleaseRetentionFailedAt: new Date().toISOString(),
        })],
      ).catch(() => null)
    }
  }

  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version,
    releaseDate,
    installerUrl,
    installerSha256,
    installerType: resolvedInstallerType,
    releaseUrl,
    assetName: selectedAssetName,
    trustState,
    trustEvidence: qualificationEvidence,
    qualificationState: trust.qualificationState,
    qualificationEvidence,
    qualificationNotes: trust.qualificationState === 'deployment_candidate'
      ? 'Automatically promoted from the authoritative vendor release feed with deployable trust metadata.'
      : '',
    sourcePriority: b.priority,
    payload: {
      ...payload,
      releaseUrl,
      trustState,
      trustEvidence: qualificationEvidence,
      expectedSigner,
      deploymentMode,
      verification,
      installArguments: clean(config.installArguments),
      installerTechnology: clean(config.installerTechnology || (resolvedInstallerType === 'msi' ? 'msi' : 'generic')),
      responseFile: object(config.responseFile),
    },
    catalogueProvider: 'managed',
    verification,
    execution: {
      installArguments: clean(config.installArguments),
      responseFile: object(config.responseFile),
    },
    catalogueMetadata: {
      namePattern: clean(config.namePattern || b.canonical_name),
      publisherPattern: clean(config.publisherPattern || b.publisher),
      latestSource: sourceKey,
      sourceType: state.source_type,
      deploymentMode,
      expectedSigner,
      autoExpectedSigner: clean(config.autoExpectedSigner),
      autoDeploymentMode: clean(config.autoDeploymentMode),
      autoTrustState: clean(config.autoTrustState),
      trustState,
      trustEvidence: qualificationEvidence,
      releaseUrl,
      selectedAsset: selectedAssetName,
      selectedAssetReason,
      installerTechnology: clean(config.installerTechnology || (resolvedInstallerType === 'msi' ? 'msi' : 'generic')),
      installerContinuity: installerContinuityCandidates.length ? {
        availableTypes: [...new Set(installerContinuityCandidates.map((item) => clean(item.installerType)).filter(Boolean))],
        candidates: installerContinuityCandidates.map((item) => ({ name: item.name, installerType: item.installerType })),
      } : {},
      automaticVendorRelease: true,
      hasWingetFallback: Boolean(wingetPackageId),
      wingetPackageId: clean(config.wingetPackageId),
      autoWingetPackageId: clean(config.autoWingetPackageId),
      autoWingetConfidence: clean(config.autoWingetConfidence),
      nvdVendor: clean(config.nvdVendor),
      nvdProduct: clean(config.nvdProduct),
      osvEcosystem: clean(config.osvEcosystem),
      osvPackage: clean(config.osvPackage),
    },
  })
}

async function syncChrome() {
  const b = await binding('google_chrome')
  if (!b) return null
  const releasesUrl = b.source_url.replace(/\/versions\/?$/i, '/versions/all/releases')
    + '?filter=fraction%3D1&order_by=version%20desc&page_size=20'
  const response = await fetchJson(releasesUrl)
  const releases = Array.isArray(response?.releases) ? response.releases : []
  const latestRelease = releases.find((item) =>
    Number(item?.fraction) === 1 && !clean(item?.serving?.endTime)
  ) || releases.find((item) => Number(item?.fraction) === 1)
  const latest = clean(latestRelease?.version)
  if (!latest) throw new Error('Chrome VersionHistory returned no fully rolled-out Stable Windows release')

  const config = { ...object(b.source_metadata), ...object(b.binding_metadata) }
  const installerUrl = (await publicHttpsUrl(
    'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi',
  )).toString()
  const verification = {
    method: 'uninstall_registry',
    packageId: '',
    productCode: '',
    displayNameContains: 'Google Chrome',
    publisherContains: 'Google LLC',
    filePath: '',
  }
  const wingetPackageId = clean(config.wingetPackageId || config.autoWingetPackageId || 'Google.Chrome')
  const trust = vendorReleaseTrustProfile({
    installerUrl,
    installerSha256: '',
    installerType: 'msi',
    publisher: b.publisher,
    expectedSigner: clean(config.expectedSigner),
    verification,
    wingetPackageId,
    deploymentMode: clean(config.deploymentMode),
  })
  const evidence = {
    ...trust.evidence,
    sourceKey: b.source_key,
    releaseUrl: releasesUrl,
    selectedAsset: 'googlechromestandaloneenterprise64.msi',
    selectedAssetReason: 'official_vendor_channel_installer',
    releasePolicy: 'stable_full_rollout',
    rolloutFraction: Number(latestRelease?.fraction || 0),
    rolloutStartTime: clean(latestRelease?.serving?.startTime),
  }
  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version: latest,
    installerUrl,
    installerType: 'msi',
    releaseUrl: releasesUrl,
    assetName: 'googlechromestandaloneenterprise64.msi',
    trustState: trust.trustState,
    trustEvidence: evidence,
    qualificationState: trust.qualificationState,
    qualificationEvidence: evidence,
    sourcePriority: b.priority,
    payload: {
      releases: releases.slice(0, 20),
      releasePolicy: 'stable_full_rollout',
      rolloutFraction: Number(latestRelease?.fraction || 0),
      releaseUrl: releasesUrl,
      trustState: trust.trustState,
      trustEvidence: evidence,
      expectedSigner: '',
      deploymentMode: trust.deploymentMode,
      verification,
      installArguments: '',
    },
    catalogueProvider: 'managed',
    verification,
    execution: { installArguments: '' },
    catalogueMetadata: {
      namePattern: 'Google Chrome',
      publisherPattern: 'Google LLC',
      latestSource: b.source_key,
      sourceType: 'vendor_api',
      deploymentMode: trust.deploymentMode,
      trustState: trust.trustState,
      trustEvidence: evidence,
      releaseUrl: releasesUrl,
      selectedAsset: 'googlechromestandaloneenterprise64.msi',
      selectedAssetReason: 'official_vendor_channel_installer',
      releasePolicy: 'stable_full_rollout',
      rolloutFraction: Number(latestRelease?.fraction || 0),
      automaticVendorRelease: true,
      hasWingetFallback: Boolean(wingetPackageId),
      wingetPackageId,
    },
  })
}

async function syncEdge() {
  const b = await binding('microsoft_edge')
  if (!b) return null
  const products = await fetchJson(b.source_url)
  const stable = (Array.isArray(products) ? products : []).find((item) => clean(item?.Product).toLowerCase() === 'stable')
  const releases = (Array.isArray(stable?.Releases) ? stable.Releases : [])
    .filter((item) => clean(item?.Platform) === 'Windows' && clean(item?.Architecture).toLowerCase() === 'x64')
    .sort((a, z) => compareVersionValues(clean(z?.ProductVersion), clean(a?.ProductVersion))
      || Date.parse(z?.PublishedTime || 0) - Date.parse(a?.PublishedTime || 0))
  const latest = releases[0]
  if (!latest?.ProductVersion) throw new Error('Edge enterprise feed returned no Stable Windows x64 release')
  const msi = (Array.isArray(latest.Artifacts) ? latest.Artifacts : []).find((item) => clean(item?.ArtifactName).toLowerCase() === 'msi')
  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version: latest.ProductVersion,
    releaseDate: parseLooseDate(latest.PublishedTime),
    installerUrl: clean(msi?.Location),
    installerSha256: clean(msi?.Hash),
    installerType: msi ? 'msi' : '',
    sourcePriority: b.priority,
    payload: latest,
  })
}
async function syncMozilla(sourceKey, versionField) {
  const b = await binding(sourceKey)
  if (!b) return null
  const payload = await fetchJson(b.source_url)
  const latest = clean(payload?.[versionField])
  if (!latest) throw new Error(sourceKey + ' returned no release version')
  const releaseDate = sourceKey === 'mozilla_firefox' ? parseLooseDate(payload?.LAST_RELEASE_DATE) : null
  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version: latest,
    releaseDate,
    sourcePriority: b.priority,
    payload,
  })
}

async function syncVsCode() {
  const b = await binding('microsoft_vscode')
  if (!b) return null
  const payload = await fetchJson(b.source_url)
  const versions = Array.isArray(payload) ? payload.map(clean).filter(Boolean) : []
  const latest = clean(versions[0])
  if (!latest) throw new Error('VS Code release API returned no stable version')

  const verification = {
    method: 'uninstall_registry',
    packageId: '',
    productCode: '',
    displayNameContains: 'Microsoft Visual Studio Code',
    publisherContains: 'Microsoft',
    filePath: '',
  }
  const execution = { installArguments: '/VERYSILENT /NORESTART /MERGETASKS=!runcode' }
  const catalogueMetadata = {
    deploymentMode: 'vendor_direct',
    namePattern: 'Visual Studio Code',
    publisherPattern: 'Microsoft',
    automaticVendorRelease: true,
  }
  const qualificationNotes = 'Official Microsoft VS Code system installer. Hi5Central verifies SHA-256, Authenticode, install/uninstall, upgrade and rollback before qualification.'

  const previous = clean(versions.find((version) => compareVersionValues(version, latest) < 0))
  if (previous) {
    await upsertRelease({
      sourceKey: b.source_key,
      packageId: b.provider_package_id,
      canonicalName: b.canonical_name,
      publisher: b.publisher || 'Microsoft Corporation',
      channel: b.channel,
      platform: b.platform,
      architecture: b.architecture,
      version: previous,
      installerUrl: `https://update.code.visualstudio.com/${encodeURIComponent(previous)}/win32-x64-system/stable`,
      installerType: 'exe',
      releaseUrl: b.source_url,
      assetName: `VSCodeSetup-x64-${previous}.exe`,
      trustState: 'asset_candidate',
      qualificationState: 'deployment_candidate',
      qualificationNotes,
      sourcePriority: Math.max(1, Number(b.priority || 900) - 1),
      payload: {
        versions: versions.slice(0, 25),
        historicalReleaseCandidate: true,
        vendorChecksumPresent: false,
      },
      catalogueProvider: 'managed',
      verification,
      execution,
      catalogueMetadata,
    })
  }

  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher || 'Microsoft Corporation',
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version: latest,
    installerUrl: `https://update.code.visualstudio.com/${encodeURIComponent(latest)}/win32-x64-system/stable`,
    installerType: 'exe',
    releaseUrl: b.source_url,
    assetName: `VSCodeSetup-x64-${latest}.exe`,
    trustState: 'asset_candidate',
    qualificationState: 'deployment_candidate',
    qualificationNotes,
    sourcePriority: b.priority,
    payload: { versions: versions.slice(0, 25), vendorChecksumPresent: false },
    catalogueProvider: 'managed',
    verification,
    execution,
    catalogueMetadata,
  })
}
async function syncSevenZip() {
  const b = await binding('sevenzip')
  if (!b) return null
  const html = await fetchText(b.source_url, 'text/html')
  const text = stripHtml(html)
  const match = text.match(/Download 7-Zip\s+([0-9]+(?:\.[0-9]+)+)\s+\((\d{4}-\d{2}-\d{2})\)\s+for Windows/i)
  if (!match) throw new Error('7-Zip download page did not contain the current Windows version')
  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version: match[1],
    releaseDate: parseLooseDate(match[2]),
    sourcePriority: b.priority,
    payload: { source: b.source_url },
  })
}

async function syncAdobeReader() {
  const b = await binding('adobe_acrobat_reader')
  if (!b) return null
  const html = await fetchText(b.source_url, 'text/html')
  const text = stripHtml(html)
  const match = text.match(/Continuous Track Installers.*?([0-9]{2}\.[0-9]{3}\.[0-9]{5})\s+(?:Out of cycle|Planned|Optional)?\s*update,\s*([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4})/i)
    || text.match(/([0-9]{2}\.[0-9]{3}\.[0-9]{5})\s+(?:Out of cycle|Planned|Optional)?\s*update,\s*([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4})/i)
  if (!match) throw new Error('Adobe Acrobat release notes did not contain a current Continuous track version')
  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version: match[1],
    releaseDate: parseLooseDate(match[2]),
    sourcePriority: b.priority,
    payload: { source: b.source_url },
  })
}
async function syncPuttyDirect() {
  const b = await binding('registry_chocolatey_putty')
  if (!b) return null

  const resolved = await resolveWingetVendorInstaller('PuTTY.PuTTY')
  if (!resolved?.ok) throw new Error('PuTTY upstream MSI could not be resolved: ' + clean(resolved?.reason || 'unknown'))
  if (clean(resolved.scope).toLowerCase() === 'user') throw new Error('PuTTY upstream package resolved to user scope')
  if (clean(resolved.installerType).toLowerCase() !== 'msi') throw new Error('PuTTY upstream package is not MSI')

  const publisher = clean(resolved.publishers?.[0] || b.publisher || 'Simon Tatham')
  const verification = {
    method: 'uninstall_registry',
    packageId: '',
    productCode: '',
    displayNameContains: 'PuTTY',
    publisherContains: publisher,
    filePath: '',
  }
  const catalogueMetadata = {
    deploymentMode: 'vendor_direct',
    namePattern: 'PuTTY',
    publisherPattern: publisher,
    nvdVendor: 'simon_tatham',
    nvdProduct: 'putty',
    automaticVendorRelease: true,
  }
  const qualificationNotes = 'Official PuTTY MSI resolved from the signed WinGet manifest to the upstream vendor host. Hi5Central independently pins SHA-256 and Authenticode before deployment.'

  const previous = await resolvePreviousWingetVendorInstaller('PuTTY.PuTTY', resolved.version).catch(() => null)
  if (previous?.ok) {
    await upsertRelease({
      sourceKey: b.source_key,
      packageId: b.provider_package_id,
      canonicalName: b.canonical_name,
      publisher,
      channel: b.channel,
      platform: b.platform,
      architecture: b.architecture,
      version: previous.version,
      installerUrl: previous.installerUrl,
      installerType: previous.installerType,
      releaseUrl: previous.manifestUrl,
      assetName: clean(new URL(previous.installerUrl).pathname.split('/').at(-1)),
      trustState: 'asset_candidate',
      qualificationState: 'deployment_candidate',
      qualificationNotes,
      sourcePriority: Math.max(1, Number(b.priority || 900) - 1),
      payload: {
        historicalReleaseCandidate: true,
        vendorChecksumPresent: false,
        wingetManifest: {
          packageId: previous.packageId,
          manifestUrl: previous.manifestUrl,
          corroboratingSha256: previous.installerSha256,
        },
        verification,
      },
      catalogueProvider: 'managed',
      verification,
      execution: { installArguments: '' },
      catalogueMetadata,
    })
  }

  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version: resolved.version,
    installerUrl: resolved.installerUrl,
    installerType: resolved.installerType,
    releaseUrl: resolved.manifestUrl,
    assetName: clean(new URL(resolved.installerUrl).pathname.split('/').at(-1)),
    trustState: 'asset_candidate',
    qualificationState: 'deployment_candidate',
    qualificationNotes,
    sourcePriority: b.priority,
    payload: {
      vendorChecksumPresent: false,
      wingetManifest: {
        packageId: resolved.packageId,
        manifestUrl: resolved.manifestUrl,
        corroboratingSha256: resolved.installerSha256,
      },
      verification,
    },
    catalogueProvider: 'managed',
    verification,
    execution: { installArguments: '' },
    catalogueMetadata,
  })
}

async function syncMySqlConnectorOdbcArchiveVariant(sourceKey, {
  version,
  series,
  architecture,
  archiveArchitecture,
} = {}) {
  const b = await binding(sourceKey)
  if (!b) return null

  const safeVersion = clean(version)
  const safeSeries = clean(series)
  const safeArchitecture = clean(architecture).toLowerCase()
  const safeArchiveArchitecture = clean(archiveArchitecture)
  if (!safeVersion || !safeSeries || !['x86','x64'].includes(safeArchitecture) || !safeArchiveArchitecture) {
    throw new Error(sourceKey + ' archive variant configuration is incomplete')
  }

  const file = `mysql-connector-odbc-${safeVersion}-${safeArchiveArchitecture}.msi`
  const installerUrl = `https://cdn.mysql.com/archives/mysql-connector-odbc-${safeSeries}/${file}`
  const safeUrl = await publicHttpsUrl(installerUrl)
  const probe = await fetch(safeUrl, {
    method: 'HEAD',
    headers: { 'User-Agent': 'Hi5Central-Software-Catalogue/1.0' },
    signal: AbortSignal.timeout(30_000),
  })
  if (!probe.ok) throw new Error(sourceKey + ' archive MSI HTTP ' + probe.status)

  const displayName = safeSeries === '8.0'
    ? 'MySQL Connector/ODBC 8.0'
    : safeSeries === '9.7'
      ? 'MySQL Connector/ODBC 9.7'
      : `MySQL Connector/ODBC ${safeSeries}`
  const verification = {
    method: 'uninstall_registry',
    packageId: '',
    productCode: '',
    displayNameContains: displayName,
    publisherContains: 'Oracle',
    filePath: '',
  }
  const catalogueMetadata = {
    deploymentMode: 'vendor_direct',
    namePattern: displayName,
    publisherPattern: 'Oracle',
    automaticVendorRelease: true,
    architecture: safeArchitecture,
    mysqlConnectorOdbcSeries: safeSeries,
    pinnedCompatibilitySeries: true,
  }
  const qualificationNotes = `Official MySQL Connector/ODBC ${safeSeries} ${safeArchitecture} MSI from Oracle's archive. Hi5Central independently pins SHA-256 and Authenticode before deployment.`

  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher || 'Oracle Corporation',
    channel: b.channel,
    platform: b.platform,
    architecture: safeArchitecture,
    version: safeVersion,
    installerUrl: safeUrl.toString(),
    installerType: 'msi',
    releaseUrl: 'https://downloads.mysql.com/archives/c-odbc/',
    assetName: file,
    trustState: 'asset_candidate',
    qualificationState: 'deployment_candidate',
    qualificationNotes,
    sourcePriority: b.priority,
    payload: {
      source: 'https://downloads.mysql.com/archives/c-odbc/',
      vendorChecksumPresent: false,
      compatibilitySeries: safeSeries,
      architecture: safeArchitecture,
    },
    catalogueProvider: 'managed',
    verification,
    execution: { installArguments: '' },
    catalogueMetadata,
  })
}

async function syncMySqlConnectorOdbc8X86() {
  return syncMySqlConnectorOdbcArchiveVariant('mysql_connector_odbc_8_x86', {
    version: '8.0.43',
    series: '8.0',
    architecture: 'x86',
    archiveArchitecture: 'win32',
  })
}

async function syncMySqlConnectorOdbc9X64() {
  return syncMySqlConnectorOdbcArchiveVariant('mysql_connector_odbc_9_x64', {
    version: '9.7.0',
    series: '9.7',
    architecture: 'x64',
    archiveArchitecture: 'winx64',
  })
}

async function syncMySqlConnectorOdbc() {
  const b = await binding('mysql_connector_odbc')
  if (!b) return null

  const currentHtml = await fetchText(b.source_url, 'text/html')
  const currentVersion = clean(currentHtml.match(/<h1>\s*Connector\/ODBC\s+([0-9]+(?:\.[0-9]+)+)\s*<\/h1>/i)?.[1])
  if (!currentVersion) throw new Error('MySQL Connector/ODBC download page did not contain the current GA version')

  const currentFileMatch = currentHtml.match(/(mysql-connector-odbc-([0-9]+(?:\.[0-9]+)+)-winx64\.msi)/i)
  const currentFile = clean(currentFileMatch?.[1])
  if (!currentFile || clean(currentFileMatch?.[2]) !== currentVersion) {
    throw new Error('MySQL Connector/ODBC download page did not contain the current x64 MSI')
  }

  const currentBranch = currentVersion.split('.').slice(0, 2).join('.')
  const currentInstallerUrl = `https://cdn.mysql.com/Downloads/Connector-ODBC/${currentBranch}/${currentFile}`
  const verification = {
    method: 'uninstall_registry',
    packageId: '',
    productCode: '',
    displayNameContains: 'MySQL Connector/ODBC',
    publisherContains: 'Oracle',
    filePath: '',
  }
  const catalogueMetadata = {
    deploymentMode: 'vendor_direct',
    namePattern: 'MySQL Connector/ODBC',
    publisherPattern: 'Oracle',
    automaticVendorRelease: true,
  }
  const qualificationNotes = 'Official MySQL x64 MSI. Hi5Central pins SHA-256 and Authenticode on the qualification endpoint before deployment.'

  try {
    const archiveUrl = 'https://downloads.mysql.com/archives/c-odbc/'
    const archiveHtml = await fetchText(archiveUrl, 'text/html')
    const previousFileMatch = archiveHtml.match(/(mysql-connector-odbc-([0-9]+(?:\.[0-9]+)+)-winx64\.msi)/i)
    const previousFile = clean(previousFileMatch?.[1])
    const previousVersion = clean(previousFileMatch?.[2])
    if (previousFile && previousVersion && compareVersionValues(previousVersion, currentVersion) < 0) {
      await upsertRelease({
        sourceKey: b.source_key,
        packageId: b.provider_package_id,
        canonicalName: b.canonical_name,
        publisher: b.publisher,
        channel: b.channel,
        platform: b.platform,
        architecture: b.architecture,
        version: previousVersion,
        installerUrl: `https://cdn.mysql.com/archives/mysql-connector-odbc-${previousVersion.split('.').slice(0, 2).join('.')}/${previousFile}`,
        installerType: 'msi',
        releaseUrl: archiveUrl,
        assetName: previousFile,
        trustState: 'asset_candidate',
        qualificationState: 'deployment_candidate',
        qualificationNotes,
        sourcePriority: Math.max(1, Number(b.priority || 900) - 1),
        payload: { source: archiveUrl, historicalReleaseCandidate: true, vendorChecksumPresent: false },
        catalogueProvider: 'managed',
        verification,
        execution: { installArguments: '' },
        catalogueMetadata,
      })
    }
  } catch (error) {
    console.warn('MySQL Connector/ODBC previous release discovery failed', clean(error?.message || error))
  }

  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version: currentVersion,
    installerUrl: currentInstallerUrl,
    installerType: 'msi',
    releaseUrl: b.source_url,
    assetName: currentFile,
    trustState: 'asset_candidate',
    qualificationState: 'deployment_candidate',
    qualificationNotes,
    sourcePriority: b.priority,
    payload: { source: b.source_url, vendorChecksumPresent: false },
    catalogueProvider: 'managed',
    verification,
    execution: { installArguments: '' },
    catalogueMetadata,
  })
}

async function syncMicrosoft365AppsCurrent() {
  const b = await binding('microsoft_365_apps_current')
  if (!b) return null
  const config = { ...object(b.source_metadata), ...object(b.binding_metadata) }

  const updatePage = (await publicHttpsUrl(b.source_url)).toString()
  const updateHtml = await fetchPublicText(updatePage, {
    accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
    maxBytes: 8 * 1024 * 1024,
  })
  const updateText = stripHtml(updateHtml)
  const supportedMatch = updateText.match(
    /Current Channel\s+(\d{4})\s+(\d{5}\.\d{5})\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})/i,
  ) || updateText.match(
    /Current Channel[\s\S]{0,500}?Version\s+(\d{4})\s*\(Build\s+(\d{5}\.\d{5})\)/i,
  )
  if (!supportedMatch) throw new Error('Microsoft 365 Apps update history returned no Current Channel build')
  const channelVersion = clean(supportedMatch[1])
  const build = clean(supportedMatch[2])
  const releaseDate = normalizedReleaseDate(supportedMatch[3])
  const version = '16.0.' + build

  const odtDownloadPage = (await publicHttpsUrl(
    clean(config.odtDownloadPage) || 'https://www.microsoft.com/en-us/download/details.aspx?id=49117',
  )).toString()
  const odtHtml = await fetchPublicText(odtDownloadPage, {
    accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
    maxBytes: 8 * 1024 * 1024,
  })
  const odtText = stripHtml(odtHtml)
  const odtVersion = clean(odtText.match(/Version:\s*(16\.0\.\d+\.\d+)/i)?.[1])
  const odtFile = clean(odtText.match(/File Name:\s*(officedeploymenttool_[0-9-]+\.exe)/i)?.[1])
  let odtUrl = clean(odtHtml.match(
    /https:\/\/download\.microsoft\.com\/download\/[^"'<>\s]+\/officedeploymenttool_[0-9-]+\.exe/i,
  )?.[0]).replaceAll('&amp;', '&')
  if (!odtVersion || !odtFile || !odtUrl) {
    throw new Error('Microsoft Office Deployment Tool page returned no usable signed package')
  }
  odtUrl = (await publicHttpsUrl(odtUrl)).toString()
  if (new URL(odtUrl).hostname.toLowerCase() !== 'download.microsoft.com') {
    throw new Error('Microsoft Office Deployment Tool download resolved outside download.microsoft.com')
  }

  const verification = {
    method: 'office_c2r_registry',
    productId: clean(config.officeProductId || 'O365ProPlusRetail'),
    displayNameContains: clean(config.namePattern || b.canonical_name),
    publisherContains: clean(config.publisherPattern || b.publisher),
  }
  const expectedSigner = clean(config.expectedSigner || 'Microsoft Corporation')
  const trust = vendorReleaseTrustProfile({
    installerUrl: odtUrl,
    installerSha256: '',
    installerType: 'exe',
    publisher: b.publisher,
    expectedSigner,
    verification,
    wingetPackageId: '',
    deploymentMode: 'vendor_direct',
  })
  const evidence = {
    ...trust.evidence,
    sourceKey: b.source_key,
    releaseUrl: updatePage,
    selectedAsset: odtFile,
    selectedAssetReason: 'official_microsoft_odt_for_click_to_run',
    officeChannel: 'Current',
    officeChannelVersion: channelVersion,
    officeBuild: build,
    officeVersion: version,
    odtVersion,
    odtDownloadPage,
  }
  const installArguments = clean(config.installArguments || '/configure {HI5_RESPONSE_FILE}')
  const responseFile = object(config.responseFile)

  return upsertRelease({
    sourceKey: b.source_key,
    packageId: b.provider_package_id,
    canonicalName: b.canonical_name,
    publisher: b.publisher,
    channel: b.channel,
    platform: b.platform,
    architecture: b.architecture,
    version,
    releaseDate,
    installerUrl: odtUrl,
    installerType: 'exe',
    releaseUrl: updatePage,
    assetName: odtFile,
    trustState: trust.trustState,
    trustEvidence: evidence,
    qualificationState: trust.qualificationState,
    qualificationEvidence: evidence,
    qualificationNotes: trust.qualificationState === 'deployment_candidate'
      ? 'Microsoft Current Channel is authoritative; deployment uses the signed Office Deployment Tool and Office CDN.'
      : '',
    sourcePriority: b.priority,
    payload: {
      microsoft365Apps: {
        channel: 'Current',
        channelVersion,
        build,
        version,
        productId: verification.productId,
        updateHistoryUrl: updatePage,
        odtVersion,
        odtFile,
        odtDownloadPage,
      },
      releaseUrl: updatePage,
      trustState: trust.trustState,
      trustEvidence: evidence,
      expectedSigner,
      deploymentMode: trust.deploymentMode,
      verification,
      installerTechnology: 'office_odt_sfx',
      installArguments,
      responseFile,
    },
    catalogueProvider: 'managed',
    verification,
    execution: { installArguments, responseFile },
    catalogueMetadata: {
      namePattern: clean(config.namePattern || b.canonical_name),
      publisherPattern: clean(config.publisherPattern || b.publisher),
      latestSource: b.source_key,
      sourceType: 'microsoft_365_apps',
      deploymentMode: trust.deploymentMode,
      expectedSigner,
      signerBaseline: expectedSigner,
      trustState: trust.trustState,
      trustEvidence: evidence,
      releaseUrl: updatePage,
      selectedAsset: odtFile,
      selectedAssetReason: 'official_microsoft_odt_for_click_to_run',
      installerTechnology: 'office_odt_sfx',
      automaticVendorRelease: true,
      hasWingetFallback: false,
      officeChannel: 'Current',
      officeProductId: verification.productId,
      odtVersion,
      nvdVendor: clean(config.nvdVendor || 'microsoft'),
      nvdProduct: clean(config.nvdProduct || 'office'),
    },
  })
}

const adapters = {
  google_chrome: syncChrome,
  microsoft_edge: syncEdge,
  microsoft_365_apps_current: syncMicrosoft365AppsCurrent,
  mozilla_firefox: () => syncMozilla('mozilla_firefox', 'LATEST_FIREFOX_VERSION'),
  mozilla_thunderbird: () => syncMozilla('mozilla_thunderbird', 'LATEST_THUNDERBIRD_VERSION'),
  microsoft_vscode: syncVsCode,
  sevenzip: syncSevenZip,
  adobe_acrobat_reader: syncAdobeReader,
  registry_chocolatey_putty: syncPuttyDirect,
  mysql_connector_odbc: syncMySqlConnectorOdbc,
  mysql_connector_odbc_8_x86: syncMySqlConnectorOdbc8X86,
  mysql_connector_odbc_9_x64: syncMySqlConnectorOdbc9X64,
}

function normalizedSoftwareName(value = '') {
  return clean(value).toLowerCase().replace(/[^a-z0-9]+/g, '')
}

function wingetManifestSourceKey(packageId = '') {
  const value = clean(packageId).toLowerCase()
  const slug = value.replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 92)
  let hash = 2166136261
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return 'winget_manifest_' + slug + '_' + (hash >>> 0).toString(36)
}

export async function seedBusinessEssentialVendorCatalogue({ syncLimit = BUSINESS_ESSENTIAL_WINGET_PACKAGES.length, dryRun = false } = {}) {
  const existingResult = await pool.query(
    `SELECT canonical_name,qualification_state,status,provider_package_id,source_metadata
       FROM rmm_software_catalogue
      WHERE tenant_id IS NULL`,
  )
  const deployableNames = new Set()
  const existingPackages = new Set()
  for (const row of existingResult.rows) {
    const metadata = object(row.source_metadata)
    const deploymentMode = clean(metadata.deploymentMode)
    const deployable = row.status === 'active'
      && row.qualification_state !== 'intelligence_only'
      && deploymentMode !== 'intelligence_only'
    if (deployable) deployableNames.add(normalizedSoftwareName(row.canonical_name))
    const reservePackage = row.status !== 'active' || deployable
    if (reservePackage) {
      for (const value of [metadata.wingetPackageId, metadata.autoWingetPackageId, row.provider_package_id]) {
        const packageId = clean(value)
        if (packageId && !packageId.startsWith('vendor:')) existingPackages.add(lower(packageId))
      }
    }
  }

  const entries = []
  const skipped = []
  const rejected = []
  for (const wanted of BUSINESS_ESSENTIAL_WINGET_PACKAGES) {
    const nameKey = normalizedSoftwareName(wanted.canonicalName)
    const packageKey = lower(wanted.packageId)
    if (deployableNames.has(nameKey) || existingPackages.has(packageKey)) {
      skipped.push({ canonicalName: wanted.canonicalName, packageId: wanted.packageId, reason: 'already_deployable' })
      continue
    }

    let resolved
    try {
      resolved = await resolveWingetVendorInstaller(wanted.packageId)
    } catch (error) {
      rejected.push({ canonicalName: wanted.canonicalName, packageId: wanted.packageId, reason: clean(error?.message || error) })
      continue
    }
    if (!resolved?.ok) {
      rejected.push({ canonicalName: wanted.canonicalName, packageId: wanted.packageId, reason: clean(resolved?.reason || 'not_resolved') })
      continue
    }
    if (clean(resolved.scope).toLowerCase() === 'user') {
      rejected.push({ canonicalName: wanted.canonicalName, packageId: wanted.packageId, reason: 'user_scope_only' })
      continue
    }
    if (!['msi', 'exe'].includes(clean(resolved.installerType).toLowerCase())) {
      rejected.push({ canonicalName: wanted.canonicalName, packageId: wanted.packageId, reason: 'installer_not_msi_or_exe' })
      continue
    }
    if (!/^[a-f0-9]{64}$/i.test(clean(resolved.installerSha256))) {
      rejected.push({ canonicalName: wanted.canonicalName, packageId: wanted.packageId, reason: 'installer_sha256_missing' })
      continue
    }
    if (!clean(resolved.version) || /(?:alpha|beta|rc|preview|eap|nightly|dev|canary)/i.test(clean(resolved.version))) {
      rejected.push({ canonicalName: wanted.canonicalName, packageId: wanted.packageId, reason: 'non_stable_version' })
      continue
    }

    const publisher = clean(resolved.publishers?.[0])
    const sourceKey = wingetManifestSourceKey(resolved.packageId)
    entries.push({
      sourceKey,
      displayName: wanted.canonicalName,
      canonicalName: wanted.canonicalName,
      publisher,
      sourceType: 'winget_manifest',
      sourceUrl: 'https://github.com/microsoft/winget-pkgs',
      deploymentMode: 'winget_preferred',
      wingetPackageId: resolved.packageId,
      installerType: resolved.installerType,
      installArguments: clean(resolved.installArguments),
      namePattern: clean(resolved.name || wanted.canonicalName),
      publisherPattern: publisher,
      verificationConfig: {
        method: clean(resolved.productCode) ? 'uninstall_registry' : 'winget',
        packageId: clean(resolved.productCode) ? '' : resolved.packageId,
        productCode: clean(resolved.productCode),
        displayNameContains: clean(resolved.name || wanted.canonicalName),
        publisherContains: publisher,
      },
      priority: Math.max(800, Number(wanted.priority) || 900),
      pollMinutes: 180,
      qualificationNotes: 'Hi5Central Business Essentials: upstream MSI/EXE resolved from the current WinGet manifest. Pending independent artifact, install, uninstall, upgrade and rollback qualification.',
    })
    existingPackages.add(packageKey)
    deployableNames.add(nameKey)
  }

  if (entries.length && !dryRun) await importCuratedSoftwareCatalogue(entries)

  const syncResults = []
  const safeSyncLimit = dryRun ? 0 : Math.max(0, Math.min(entries.length, Number(syncLimit) || 0))
  for (const entry of entries.slice(0, safeSyncLimit)) {
    try {
      syncResults.push(await syncSoftwareVendorSource(entry.sourceKey))
    } catch (error) {
      syncResults.push({ sourceKey: entry.sourceKey, ok: false, error: clean(error?.message || error) })
    }
  }

  return {
    dryRun: Boolean(dryRun),
    requested: BUSINESS_ESSENTIAL_WINGET_PACKAGES.length,
    imported: entries.length,
    skipped: skipped.length,
    rejected: rejected.length,
    synced: syncResults.filter((item) => item?.ok).length,
    entries: entries.map((entry) => ({ canonicalName: entry.canonicalName, packageId: entry.wingetPackageId, sourceKey: entry.sourceKey })),
    skippedItems: skipped,
    rejectedItems: rejected,
    syncResults,
  }
}

export async function seedEnterpriseWingetVendorCatalogue({ targetTotal = 500, scanLimit = 1200, resolveLimit = 400, syncLimit = 20 } = {}) {
  const safeTarget = Math.max(1, Math.min(1000, Number(targetTotal) || 500))
  const currentResult = await pool.query(`SELECT count(*)::int AS count FROM rmm_software_catalogue WHERE tenant_id IS NULL AND status='active'`)
  const current = Number(currentResult.rows[0]?.count || 0)
  if (current >= safeTarget) return { target: safeTarget, current, needed: 0, attempted: 0, imported: 0, synced: 0, rejected: [] }

  const existingResult = await pool.query(
    `SELECT canonical_name,provider_package_id,source_metadata
       FROM rmm_software_catalogue
      WHERE tenant_id IS NULL AND status='active'`,
  )
  const existingPackages = new Set()
  const existingNames = new Set()
  for (const row of existingResult.rows) {
    existingNames.add(normalizedSoftwareName(row.canonical_name))
    const metadata = object(row.source_metadata)
    for (const value of [metadata.wingetPackageId, metadata.autoWingetPackageId, row.provider_package_id]) {
      const packageId = clean(value)
      if (packageId && !packageId.startsWith('vendor:')) existingPackages.add(packageId.toLowerCase())
    }
  }

  const commonNames = new Set(COMMON_WINDOWS_SOFTWARE_LOWER.map(normalizedSoftwareName))
  const seeds = await wingetEnterpriseSeedMatches({ limit: Math.max(100, Math.min(2500, Number(scanLimit) || 1200)) })
  seeds.sort((a, b) => {
    const aCommon = commonNames.has(normalizedSoftwareName(a.packageName)) || commonNames.has(normalizedSoftwareName(a.seedProduct))
    const bCommon = commonNames.has(normalizedSoftwareName(b.packageName)) || commonNames.has(normalizedSoftwareName(b.seedProduct))
    return Number(bCommon) - Number(aCommon) || clean(a.packageName).localeCompare(clean(b.packageName))
  })

  const needed = safeTarget - current
  const maxResolve = Math.max(1, Math.min(1000, Number(resolveLimit) || 400))
  const candidates = seeds.filter((item) =>
    !existingPackages.has(lower(item.packageId))
    && !existingNames.has(normalizedSoftwareName(item.packageName))
    && !existingNames.has(normalizedSoftwareName(item.seedProduct)),
  )
  const entries = []
  const rejected = []
  let attempted = 0

  for (let offset = 0; offset < candidates.length && entries.length < needed && attempted < maxResolve; offset += 8) {
    const remaining = maxResolve - attempted
    const batch = candidates.slice(offset, offset + Math.min(8, remaining))
    attempted += batch.length
    const results = await Promise.all(batch.map(async (seed) => {
      try { return { seed, resolved: await resolveWingetVendorInstaller(seed.packageId, seed.version) } }
      catch (error) { return { seed, error: clean(error?.message || error) } }
    }))

    for (const item of results) {
      if (entries.length >= needed) break
      const resolved = item.resolved
      if (!resolved?.ok) {
        rejected.push({ packageId: item.seed.packageId, reason: item.error || clean(resolved?.reason || 'not_resolved') })
        continue
      }
      const publisher = clean(item.seed.seedVendor || resolved.publishers?.[0])
      const canonicalName = clean(item.seed.seedProduct || resolved.name || item.seed.packageName)
      entries.push({
        sourceKey: wingetManifestSourceKey(resolved.packageId),
        displayName: canonicalName,
        canonicalName,
        publisher,
        sourceType: 'winget_manifest',
        sourceUrl: 'https://github.com/microsoft/winget-pkgs',
        deploymentMode: 'winget_preferred',
        wingetPackageId: resolved.packageId,
        installerType: resolved.installerType,
        installArguments: clean(resolved.installArguments),
        namePattern: clean(resolved.name || canonicalName),
        publisherPattern: publisher,
        verificationConfig: {
          method: resolved.productCode ? 'uninstall_registry' : 'winget',
          packageId: resolved.productCode ? '' : resolved.packageId,
          productCode: clean(resolved.productCode),
          displayNameContains: clean(resolved.name || canonicalName),
          publisherContains: publisher,
        },
        priority: commonNames.has(normalizedSoftwareName(canonicalName)) ? 650 : 450,
        pollMinutes: 360,
        qualificationNotes: 'Seeded from enterprise software coverage and resolved through the current WinGet manifest to an upstream MSI/EXE. Pending independent Hi5Central artifact and endpoint qualification.',
      })
      existingPackages.add(lower(resolved.packageId))
      existingNames.add(normalizedSoftwareName(canonicalName))
    }
  }

  if (entries.length) await importCuratedSoftwareCatalogue(entries)
  const synced = []
  const syncCount = Math.max(0, Math.min(entries.length, Number(syncLimit) || 0))
  for (const entry of entries.slice(0, syncCount)) {
    try { synced.push(await syncSoftwareVendorSource(entry.sourceKey)) }
    catch (error) { synced.push({ sourceKey: entry.sourceKey, ok: false, error: clean(error?.message || error) }) }
  }
  return {
    target: safeTarget,
    current,
    needed,
    attempted,
    imported: entries.length,
    synced: synced.filter((item) => item?.ok).length,
    syncResults: synced,
    rejected: rejected.slice(0, 100),
  }
}
export async function syncSoftwareVendorSource(sourceKey) {
  const state = await sourceState(sourceKey)
  if (!state?.enabled) return { sourceKey, skipped: true }
  const adapter = adapters[sourceKey]
    || (['github_releases','gitlab_releases','vendor_json','vendor_text','vendor_html','hashicorp_releases','python_releases','adoptium','static_release','package_registry','winget_manifest'].includes(state.source_type)
      ? () => syncGenericConfigured(sourceKey, state)
      : null)
  if (!adapter) throw new Error('No software vendor adapter registered for ' + sourceKey + ' (' + state.source_type + ')')
  await markAttempt(sourceKey)
  try {
    const version = await adapter()
    return {
      sourceKey,
      version,
      changed: Boolean(clean(version) && clean(version) !== clean(state.cursor_value)),
      ok: true,
    }
  } catch (error) {
    await markFailure(sourceKey, error)
    throw error
  }
}

async function probeVendorAssetUrl(value, redirects = 0) {
  if (redirects > 4) throw new Error('Vendor asset redirected too many times.')
  const url = await publicHttpsUrl(value)
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Accept: 'application/octet-stream,*/*;q=0.8',
      Range: 'bytes=0-0',
      'User-Agent': 'Hi5Central-Software-Catalogue/1.0',
    },
    redirect: 'manual',
    signal: AbortSignal.timeout(20_000),
  })
  if ([301,302,303,307,308].includes(response.status)) {
    const location = clean(response.headers.get('location'))
    await response.body?.cancel().catch(() => null)
    if (!location) throw new Error('Vendor asset redirected without a location.')
    return probeVendorAssetUrl(new URL(location, url).toString(), redirects + 1)
  }

  const status = Number(response.status) || 0
  const contentType = clean(response.headers.get('content-type'))
  const etag = clean(response.headers.get('etag'))
  const lastModified = clean(response.headers.get('last-modified'))
  const contentRange = clean(response.headers.get('content-range'))
  const rawLength = Number(response.headers.get('content-length'))
  const rangeTotal = Number(contentRange.match(/\/(\d+)$/)?.[1])
  const contentLength = Number.isFinite(rangeTotal) && rangeTotal >= 0
    ? rangeTotal
    : (Number.isFinite(rawLength) && rawLength >= 0 ? rawLength : null)
  await response.body?.cancel().catch(() => null)

  if (![200,206].includes(status)) throw new Error('Vendor asset HTTP ' + status)
  if (/text\/html/i.test(contentType)) throw new Error('Vendor asset returned HTML instead of an installer.')
  return {
    status,
    finalUrl: url.toString(),
    contentType,
    contentLength,
    etag,
    lastModified,
  }
}

export async function probeDueSoftwareVendorAssets({ limit = 20 } = {}) {
  const due = await pool.query(
    `SELECT DISTINCT ON (provider_package_id,channel,platform,architecture)
            id,source_key,provider_package_id,canonical_name,version,installer_url,
            asset_health_state,asset_failure_count
       FROM rmm_software_vendor_releases
      WHERE trust_state='direct_ready'
        AND installer_url<>''
        AND (asset_last_checked_at IS NULL OR asset_last_checked_at <= now() - interval '60 minutes')
      ORDER BY provider_package_id,channel,platform,architecture,
               COALESCE(release_date,last_seen_at) DESC,source_priority DESC
      LIMIT $1`,
    [Math.max(1, Math.min(100, Number(limit) || 20))],
  )

  const results = []
  for (const row of due.rows) {
    try {
      const probe = await probeVendorAssetUrl(row.installer_url)
      await pool.query(
        `UPDATE rmm_software_vendor_releases
            SET asset_health_state='healthy',asset_last_checked_at=now(),asset_http_status=$2,
                asset_failure_count=0,asset_final_url=$3,asset_content_type=$4,asset_content_length=$5,
                asset_etag=$6,asset_last_modified=$7,asset_health_error=''
          WHERE id=$1`,
        [row.id, probe.status, probe.finalUrl, probe.contentType, probe.contentLength, probe.etag, probe.lastModified],
      )
      results.push({ id: row.id, name: row.canonical_name, version: row.version, state: 'healthy' })
    } catch (error) {
      const failures = Number(row.asset_failure_count || 0) + 1
      const state = failures >= 3 ? 'dead' : 'degraded'
      const message = clean(error?.message || error).slice(0, 1000)
      await pool.query(
        `UPDATE rmm_software_vendor_releases
            SET asset_health_state=$2,asset_last_checked_at=now(),asset_failure_count=$3,
                asset_health_error=$4
          WHERE id=$1`,
        [row.id, state, failures, message],
      )
      results.push({ id: row.id, name: row.canonical_name, version: row.version, state, error: message })
    }
  }
  return results
}

async function fastTrackLatestVersionSources() {
  const githubTokenConfigured = Boolean(githubApiToken())
  const githubPollFloor = githubTokenConfigured ? 5 : 60
  const githubCandidatePollMinutes = Math.max(
    githubPollFloor,
    Math.min(1440, Number(process.env.RMM_GITHUB_RELEASE_POLL_MINUTES) || (githubTokenConfigured ? 15 : 240)),
  )
  const candidatePollMinutes = Math.max(5, Math.min(120, Number(process.env.RMM_CANDIDATE_SOURCE_POLL_MINUTES) || 15))
  const qualifiedPollMinutes = Math.max(30, Math.min(360, Number(process.env.RMM_QUALIFIED_SOURCE_POLL_MINUTES) || 60))
  const intelligencePollMinutes = Math.max(60, Math.min(1440, Number(process.env.RMM_INTELLIGENCE_SOURCE_POLL_MINUTES) || 360))

  const result = await pool.query(
    `WITH desired AS (
       SELECT s.source_key,
              CASE
                WHEN bool_or(c.qualification_state='deployment_candidate') THEN
                  CASE WHEN s.source_type='github_releases' THEN $1::int ELSE $2::int END
                WHEN bool_or(c.qualification_state IN ('qualified','qualified_limited')) THEN
                  CASE WHEN s.source_type='github_releases' THEN GREATEST($1::int,$3::int) ELSE $3::int END
                ELSE
                  CASE WHEN s.source_type='github_releases' THEN GREATEST($1::int,$4::int) ELSE $4::int END
              END::int AS desired_poll_minutes,
              CASE
                WHEN bool_or(c.qualification_state='deployment_candidate') THEN 'deployment_candidate'
                WHEN bool_or(c.qualification_state IN ('qualified','qualified_limited')) THEN 'qualified'
                ELSE 'intelligence_only'
              END AS cadence_lane
         FROM rmm_software_vendor_sources s
         JOIN rmm_software_vendor_bindings b
           ON b.source_key=s.source_key AND b.enabled=true
         JOIN rmm_software_catalogue c
           ON c.tenant_id IS NULL
          AND c.status='active'
          AND c.catalogue_source='vendor'
          AND c.external_key=b.provider_package_id
          AND c.qualification_state IN ('qualified','qualified_limited','deployment_candidate','intelligence_only')
        WHERE s.enabled=true
          AND s.source_type IN (
            'github_releases','gitlab_releases','vendor_api','vendor_json','vendor_text','vendor_html',
            'hashicorp_releases','python_releases','adoptium','static_release','package_registry','winget_manifest'
          )
        GROUP BY s.source_key,s.source_type
     )
     UPDATE rmm_software_vendor_sources s
        SET poll_minutes=d.desired_poll_minutes,
            metadata=metadata || jsonb_build_object(
              'latestVersionFastTrack',true,
              'latestVersionFastTrackAt',now(),
              'latestVersionFastTrackReason','state_aware_catalogue_source',
              'latestVersionCadenceLane',d.cadence_lane
            ),
            updated_at=now()
       FROM desired d
      WHERE s.source_key=d.source_key
        AND s.poll_minutes IS DISTINCT FROM d.desired_poll_minutes
      RETURNING s.source_key`,
    [githubCandidatePollMinutes, candidatePollMinutes, qualifiedPollMinutes, intelligencePollMinutes],
  )
  return result.rows.map((row) => row.source_key)
}

export async function syncDueSoftwareVendorSources() {
  await fastTrackLatestVersionSources().catch((error) => {
    console.error('RMM latest-version fast-track setup failed', error.message)
  })
  const syncLimit = Math.max(40, Math.min(250, Number(process.env.RMM_VENDOR_SYNC_DUE_LIMIT) || 120))
  const githubTokenConfigured = Boolean(githubApiToken())
  const githubPerSweep = Math.max(1, Math.min(100, Number(process.env.RMM_GITHUB_SYNC_PER_SWEEP) || (githubTokenConfigured ? 60 : 1)))
  const due = await pool.query(
    `WITH ranked_due AS (
       SELECT s.source_key,s.source_type,
              min(CASE WHEN c.qualification_state IN ('qualified','qualified_limited','deployment_candidate') THEN 0 ELSE 1 END) AS lane,
              max(s.priority) AS source_priority,
              row_number() OVER (PARTITION BY s.source_type ORDER BY min(CASE WHEN c.qualification_state IN ('qualified','qualified_limited','deployment_candidate') THEN 0 ELSE 1 END),max(s.priority) DESC,s.source_key) AS type_rank
         FROM rmm_software_vendor_sources s
         LEFT JOIN rmm_software_vendor_bindings b
           ON b.source_key=s.source_key AND b.enabled=true
         LEFT JOIN rmm_software_catalogue c
           ON c.tenant_id IS NULL
          AND c.status='active'
          AND c.catalogue_source='vendor'
          AND c.external_key=b.provider_package_id
        WHERE s.enabled=true
          AND (s.last_attempt_at IS NULL OR s.last_attempt_at + (s.poll_minutes || ' minutes')::interval <= now())
        GROUP BY s.source_key,s.source_type
     )
     SELECT source_key
       FROM ranked_due
      WHERE source_type<>'github_releases' OR type_rank <= $2
      ORDER BY lane ASC,source_priority DESC,source_key
      LIMIT $1`,
    [syncLimit, githubPerSweep],
  )
  const results = []
  for (const row of due.rows) {
    try {
      results.push(await syncSoftwareVendorSource(row.source_key))
    } catch (error) {
      console.error('RMM software vendor sync failed', row.source_key, error.message)
      results.push({ sourceKey: row.source_key, ok: false, error: error.message })
    }
  }

  try {
    const fallback = await syncAutomaticWingetFallbacks()
    if (fallback?.mapped) {
      const ready = fallback.mappings.filter((item) => item.transportReady).length
      const lagging = fallback.mappings.filter((item) => !item.transportReady).length
      console.log('RMM WinGet fallback verification', { mapped: fallback.mapped, ready, lagging })
    }
  } catch (error) {
    console.error('RMM automatic WinGet fallback verification failed', error.message)
  }

  try {
    const assetHealth = await probeDueSoftwareVendorAssets({ limit: 20 })
    const unhealthy = assetHealth.filter((item) => item.state !== 'healthy')
    if (unhealthy.length) console.warn('RMM vendor asset health warnings', unhealthy)
  } catch (error) {
    console.error('RMM vendor asset health sweep failed', error.message)
  }

  try {
    const evergreen = await syncEvergreenCorroboration()
    if (!evergreen.skipped && (evergreen.promoted || evergreen.checked)) {
      console.log('RMM Evergreen corroboration', {
        checked: evergreen.checked,
        promoted: evergreen.promoted,
      })
    }
  } catch (error) {
    console.error('RMM Evergreen corroboration failed', error.message)
  }

  try {
    const qualification = await runVendorArtifactQualification({ inspectLimit: 2 })
    if (qualification.reconciled.length || qualification.recovered.length || qualification.queued.length) {
      console.log('RMM vendor artifact qualification', qualification)
    }
  } catch (error) {
    console.error('RMM vendor artifact qualification failed', error.message)
  }

  if (results.some((item) => item?.ok && item?.changed)) {
    recalculateAllTenantVulnerabilityExposures().catch((error) => {
      console.error('RMM vulnerability exposure refresh failed after vendor release change', error)
    })
  }
  return results
}

export async function softwareVendorSummary() {
  const [sources, releases] = await Promise.all([
    pool.query(
      `SELECT source_key,display_name,source_type,source_url,enabled,priority,poll_minutes,cursor_value,
              last_attempt_at,last_success_at,last_error,records_seen,metadata
         FROM rmm_software_vendor_sources ORDER BY priority DESC,display_name`,
    ),
    pool.query(
      `SELECT DISTINCT ON (provider_package_id,channel,platform,architecture)
              source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,
              version,release_date,release_url,asset_name,installer_url,installer_sha256,installer_type,
              trust_state,trust_evidence,source_payload,source_priority,last_seen_at,
              asset_health_state,asset_last_checked_at,asset_http_status,asset_failure_count,
              asset_final_url,asset_content_type,asset_content_length,asset_etag,asset_last_modified,asset_health_error
         FROM rmm_software_vendor_releases
        ORDER BY provider_package_id,channel,platform,architecture,source_priority DESC,
                 COALESCE(release_date,last_seen_at) DESC`,
    ),
  ])
  const latest = releases.rows
  const sourceHealth = sources.rows.map((source) => {
    const rows = latest.filter((release) => release.source_key === source.source_key)
    const staleMs = Math.max(Number(source.poll_minutes || 60) * 3, 180) * 60000
    const stale = Boolean(source.last_success_at && Date.now() - new Date(source.last_success_at).getTime() > staleMs)
    const state = source.last_error ? 'attention' : stale ? 'stale' : source.last_success_at ? 'healthy' : 'pending'
    return { source_key: source.source_key, display_name: source.display_name, state, stale, last_success_at: source.last_success_at, last_attempt_at: source.last_attempt_at, last_error: source.last_error, records_seen: Number(source.records_seen || 0), release_count: rows.length, healthy_assets: rows.filter((r) => r.asset_health_state === 'healthy').length, unhealthy_assets: rows.filter((r) => ['dead','degraded'].includes(r.asset_health_state)).length, unknown_assets: rows.filter((r) => !r.asset_health_state || r.asset_health_state === 'unknown').length }
  })
  const health = { total: sourceHealth.length, healthy: sourceHealth.filter((x) => x.state === 'healthy').length, attention: sourceHealth.filter((x) => x.state === 'attention').length, stale: sourceHealth.filter((x) => x.state === 'stale').length, pending: sourceHealth.filter((x) => x.state === 'pending').length, unhealthy_assets: sourceHealth.reduce((sum,x) => sum + x.unhealthy_assets,0), unknown_assets: sourceHealth.reduce((sum,x) => sum + x.unknown_assets,0) }
  const readinessResult = await pool.query(
    `SELECT c.id,c.canonical_name,c.target_version,c.external_key,c.qualification_state,c.source_metadata,
            b.source_key,b.platform,b.architecture,b.metadata AS binding_metadata,
            r.trust_state,r.installer_url,r.installer_type,r.asset_name,r.trust_evidence,r.source_payload AS release_source_payload
       FROM rmm_software_catalogue c
       LEFT JOIN rmm_software_vendor_bindings b ON b.provider_package_id=c.external_key AND b.enabled=true
       LEFT JOIN rmm_software_vendor_releases r ON r.provider_package_id=c.external_key AND r.version=c.target_version
      WHERE c.tenant_id IS NULL AND c.status='active' AND c.qualification_state='intelligence_only'
      ORDER BY c.canonical_name`,
  )
  const readiness = readinessResult.rows.map((row) => {
    const meta = object(row.binding_metadata)
    const source = object(row.source_metadata)
    const targetVersion = clean(row.target_version)
    const trustState = clean(row.trust_state || 'no_release')
    let blocker = clean(source.releaseAssetBlocker || 'qualification_pending')
    let state = 'automation_backlog'
    if (!targetVersion) blocker = 'target_version_missing'
    else if (trustState === 'no_release') blocker = 'release_not_correlated'
    else if (['rejected','signer_review_required','installer_review_required'].includes(trustState)) { blocker = trustState; state = 'manual_review' }
    else if (trustState === 'version_only' && clean(meta.registry) && !['chocolatey'].includes(clean(meta.registry))) { blocker = 'ecosystem_intelligence_only'; state = 'intelligence_only' }
    else if (trustState === 'version_only' && /^gh_/.test(clean(row.source_key)) && !clean(row.installer_url)) blocker = 'vendor_windows_asset_missing'
    else if (trustState === 'version_only' && clean(meta.wingetPackageId) && meta.wingetFallbackReady !== true) blocker = 'winget_target_lagging'
    else if (trustState === 'version_only') blocker = 'deployment_transport_missing'
    if (clean(source.releaseAssetBlocker) && blocker === 'vendor_windows_asset_missing') blocker = clean(source.releaseAssetBlocker)
    return { id: row.id, canonical_name: row.canonical_name, target_version: targetVersion, source_key: row.source_key, platform: row.platform, architecture: row.architecture, trust_state: trustState, state, blocker, registry: clean(meta.registry), winget_package_id: clean(meta.wingetPackageId || source.wingetPackageId), installer_type: clean(row.installer_type), asset_name: clean(row.asset_name), repository: clean(meta.repository), release_tag: clean(object(row.release_source_payload).github?.tag_name || object(row.release_source_payload).github?.tagName) }
  })
  const readinessCounts = readiness.reduce((counts, item) => { counts[item.blocker] = (counts[item.blocker] || 0) + 1; return counts }, {})
  return { sources: sources.rows, latest, sourceHealth, health, readiness, readinessCounts }
}

export async function archiveStructurallyUnusableCatalogueEntries({ dryRun = true, limit = 500 } = {}) {
  const packageRegistriesWithoutEndpointInstallers = [
    'npm',
    'pypi',
    'rubygems',
    'packagist',
    'nuget',
    'maven',
    'crates',
    'go',
  ]
  const safeLimit = Math.max(1, Math.min(2000, Number(limit) || 500))
  const candidates = await pool.query(
    `SELECT c.id,c.canonical_name,c.platform,c.external_key,
            COALESCE(s.source_key,'') AS source_key,
            COALESCE(s.source_type,'') AS source_type,
            COALESCE(s.metadata->>'registry','') AS registry,
            CASE
              WHEN EXISTS (
                SELECT 1
                  FROM rmm_software_catalogue sibling
                 WHERE sibling.tenant_id IS NULL
                   AND sibling.status='active'
                   AND sibling.id<>c.id
                   AND lower(sibling.canonical_name)=lower(c.canonical_name)
                   AND sibling.qualification_state IN ('deployment_candidate','qualified','qualified_limited')
              ) THEN 'redundant_intelligence_only_duplicate'
              WHEN c.platform IN ('windows','cross_platform')
               AND COALESCE(c.source_metadata->>'releaseAssetBlocker','') IN (
                 'vendor_windows_asset_missing',
                 'portable_transport_not_qualified',
                 'msix_transport_not_qualified'
               ) THEN 'non_deployable_windows_transport'
              ELSE 'non_deployable_package_registry'
            END AS archive_reason
       FROM rmm_software_catalogue c
       LEFT JOIN rmm_software_vendor_sources s
         ON s.source_key=c.source_metadata->>'latestSource'
      WHERE c.tenant_id IS NULL
        AND c.catalogue_source='vendor'
        AND c.status='active'
        AND c.qualification_state='intelligence_only'
        AND (
          EXISTS (
            SELECT 1
              FROM rmm_software_catalogue sibling
             WHERE sibling.tenant_id IS NULL
               AND sibling.status='active'
               AND sibling.id<>c.id
               AND lower(sibling.canonical_name)=lower(c.canonical_name)
               AND sibling.qualification_state IN ('deployment_candidate','qualified','qualified_limited')
          )
          OR (
            NOT (lower(c.canonical_name)=ANY($1::text[]))
            AND s.source_type='package_registry'
            AND lower(COALESCE(s.metadata->>'registry',''))=ANY($2::text[])
            AND COALESCE(c.source_metadata->>'wingetPackageId',c.source_metadata->>'autoWingetPackageId','')=''
            AND NOT EXISTS (
              SELECT 1
                FROM rmm_software_vendor_releases r
               WHERE r.provider_package_id=c.external_key
                 AND r.trust_state='direct_ready'
                 AND r.installer_type IN ('msi','exe')
                 AND r.installer_url LIKE 'https://%'
                 AND r.installer_sha256 ~* '^[a-f0-9]{64}$'
            )
          )
          OR (
            NOT (lower(c.canonical_name)=ANY($1::text[]))
            AND c.platform IN ('windows','cross_platform')
            AND COALESCE(c.source_metadata->>'releaseAssetBlocker','') IN (
              'vendor_windows_asset_missing',
              'portable_transport_not_qualified',
              'msix_transport_not_qualified'
            )
            AND COALESCE(c.source_metadata->>'wingetPackageId',c.source_metadata->>'autoWingetPackageId','')=''
            AND NOT EXISTS (
              SELECT 1
                FROM rmm_software_vendor_releases r
               WHERE r.provider_package_id=c.external_key
                 AND r.trust_state='direct_ready'
                 AND r.installer_type IN ('msi','exe')
                 AND r.installer_url LIKE 'https://%'
                 AND r.installer_sha256 ~* '^[a-f0-9]{64}$'
            )
          )
        )
      ORDER BY
        CASE WHEN EXISTS (
          SELECT 1
            FROM rmm_software_catalogue sibling
           WHERE sibling.tenant_id IS NULL
             AND sibling.status='active'
             AND sibling.id<>c.id
             AND lower(sibling.canonical_name)=lower(c.canonical_name)
             AND sibling.qualification_state IN ('deployment_candidate','qualified','qualified_limited')
        ) THEN 0 ELSE 1 END,
        lower(c.canonical_name)
      LIMIT $3`,
    [COMMON_WINDOWS_SOFTWARE_LOWER, packageRegistriesWithoutEndpointInstallers, safeLimit],
  )

  if (dryRun || !candidates.rowCount) {
    return {
      dryRun: Boolean(dryRun),
      candidates: candidates.rowCount,
      archived: 0,
      rows: candidates.rows,
    }
  }

  const archived = []
  await withTransaction(async (client) => {
    for (const row of candidates.rows) {
      const result = await client.query(
        `UPDATE rmm_software_catalogue
            SET status='archived',
                source_metadata=source_metadata || jsonb_build_object(
                  'catalogueArchiveReason',$2::text,
                  'catalogueArchivedAt',now(),
                  'cataloguePreviousStatus',status,
                  'catalogueArchivePolicy','business_focused_structural_cleanup_v1'
                ),
                qualification_notes=CASE
                  WHEN qualification_notes='' THEN 'Archived from the deployable catalogue: ' || $3::text
                  ELSE qualification_notes || ' Archived from the deployable catalogue: ' || $3::text
                END,
                updated_at=now()
          WHERE id=$1 AND status='active'
          RETURNING id,canonical_name`,
        [
          row.id,
          row.archive_reason,
          row.archive_reason === 'redundant_intelligence_only_duplicate'
            ? 'a deployable catalogue entry for this application already exists'
            : row.archive_reason === 'non_deployable_windows_transport'
              ? 'no supported Windows MSI/EXE or approved fallback transport is currently available'
              : 'this package-registry record has no endpoint MSI/EXE or WinGet deployment route',
        ],
      )
      if (result.rowCount) archived.push({ ...row, id: result.rows[0].id })
    }
  })

  return {
    dryRun: false,
    candidates: candidates.rowCount,
    archived: archived.length,
    rows: archived,
  }
}

let schedulerStarted = false
let qualificationRunnerTickActive = false
let qualificationProgressionTickActive = false

function catalogueQualificationPipelineEnabled() {
  return !['0', 'false', 'off', 'no']
    .includes(clean(process.env.RMM_CATALOGUE_QUALIFICATION_PIPELINE_ENABLED || 'false').toLowerCase())
}

async function runQualificationProgressionTick() {
  if (qualificationProgressionTickActive || !catalogueQualificationPipelineEnabled()) return
  qualificationProgressionTickActive = true
  try {
    await resetStaleQualificationQueuesForCurrentTargets({ limit: 100 })
    await promoteAutomaticAdmissionReady({ limit: 50 })

    const upgradeEnabled = qualificationStageEnabled('upgrade')
    const rollbackEnabled = qualificationStageEnabled('rollback')
    if (rollbackEnabled) await queueAutomaticRollbackQualifications({ limit: 8 })
    if (upgradeEnabled) await queueAutomaticUpgradeQualifications({ limit: 8, allowCleanOnly: true })

    await queueCommonSoftwareQualifications({
      limit: COMMON_WINDOWS_SOFTWARE_LOWER.length,
      allowUnresolvedVulnerability: true,
    })
    await queueAutomaticCleanInstallQualifications({
      limit: 2000,
      allowUnresolvedVulnerability: true,
    })
  } catch (error) {
    console.error('RMM qualification progression tick failed', error)
  } finally {
    qualificationProgressionTickActive = false
  }
}

async function runQualificationRunnerTick() {
  if (qualificationRunnerTickActive) return
  qualificationRunnerTickActive = true
  try {
    await runSoftwareQualificationQueue({ dispatchLimit: 1 })
    await promoteAutomaticAdmissionReady({ limit: 50 })
  } catch (error) {
    console.error('RMM qualification runner tick failed', error)
  } finally {
    qualificationRunnerTickActive = false
  }
}

async function retainPreviousVendorJsonReleaseCandidate({ sourceKey, binding: b, config, currentVersion }) {
  if (!/^jetbrains_[a-z0-9_]+$/.test(sourceKey)) return null
  const retained=await pool.query(
    `SELECT version FROM rmm_software_vendor_releases
      WHERE source_key=$1 AND provider_package_id=$2 AND channel=$3 AND platform=$4 AND architecture=$5
        AND trust_state IN ('asset_candidate','direct_ready') AND asset_health_state IS DISTINCT FROM 'dead'
        AND installer_type IN ('msi','exe')`,
    [sourceKey,b.provider_package_id,b.channel,b.platform,b.architecture],
  )
  if(retained.rows.some((row)=>compareVersionValues(row.version,currentVersion)<0
    && !/(alpha|beta|preview|nightly|canary|rc|eap|dev)/i.test(row.version))) return null

  const historyUrl=new URL(b.source_url)
  historyUrl.searchParams.delete('latest')
  const response=await fetchPublicJson(historyUrl.toString())
  const product=Array.isArray(response) ? response[0] : response
  const releases=(Array.isArray(product?.releases) ? product.releases : [])
    .filter((item)=>lower(item?.type)==='release')
    .filter((item)=>/^20\d{2}\.\d+(?:\.\d+)?$/.test(clean(item?.version)))
    .filter((item)=>compareVersionValues(clean(item.version),currentVersion)<0)
    .filter((item)=>clean(item?.downloads?.windows?.link))
    .sort((a,b)=>compareVersionValues(clean(a.version),clean(b.version)))
  const previous=releases.at(-1)
  if(!previous) return null

  const windows=object(previous.downloads?.windows)
  const installerUrl=(await publicHttpsUrl(clean(windows.link))).toString()
  const checksumUrl=clean(windows.checksumLink)
  let installerSha256=''
  if(checksumUrl){
    const checksumText=await fetchPublicText(checksumUrl,{maxBytes:1024*1024})
    installerSha256=normalizedSha256(clean(checksumText).split(/\s+/)[0])
  }
  if(!installerSha256) throw new Error(sourceKey + ' previous stable release did not include a usable SHA-256')
  const installerType=detectInstallerType(new URL(installerUrl).pathname,clean(config.installerType).toLowerCase())
  if(!['msi','exe'].includes(installerType)) return null

  const expectedSigner=clean(config.autoExpectedSigner || config.expectedSigner || config.signerBaseline)
  const verification={...object(config.verificationConfig)}
  const vendorBuild=clean(previous.build)
  if(vendorBuild && installerType==='exe'){
    verification.versionTransform='jetbrains_vendor_build'
    verification.releaseVersion=clean(previous.version)
    verification.vendorBuild=vendorBuild
  }
  const installArguments=clean(config.installArguments) || (installerType==='exe' ? '/S' : '')
  const payload={
    historicalReleaseCandidate:true,
    historicalRole:'upgrade_baseline',
    expectedSigner,
    deploymentMode:'intelligence_only',
    verification,
    installArguments,
    jetbrains:{
      version:clean(previous.version),
      build:vendorBuild,
      type:clean(previous.type),
      date:clean(previous.date),
      installerUrl,
      checksumUrl,
      stable:true,
      historical:true,
    },
  }

  const result=await pool.query(
    `INSERT INTO rmm_software_vendor_releases
      (source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,version,
       release_date,installer_url,installer_sha256,installer_type,release_url,asset_name,trust_state,trust_evidence,
       source_priority,source_payload,last_seen_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'asset_candidate',$15::jsonb,$16,$17::jsonb,now())
     ON CONFLICT (source_key,provider_package_id,channel,platform,architecture,version)
     DO NOTHING
     RETURNING id,version,trust_state`,
    [sourceKey,b.provider_package_id,b.canonical_name,b.publisher,b.channel,b.platform,b.architecture,
      clean(previous.version),normalizedReleaseDate(previous.date),installerUrl,installerSha256,installerType,
      historyUrl.toString(),decodeURIComponent(new URL(installerUrl).pathname.split('/').at(-1)||''),
      JSON.stringify({source:'vendor_json_history',historicalReleaseCandidate:true,vendorChecksumPresent:true,
        expectedSigner,stableRelease:true}),b.priority,JSON.stringify(payload)],
  )
  return result.rows[0] || null
}

async function retainPreviousHtmlReleaseCandidate({ sourceKey, binding: b, config, currentVersion }) {
  const retained = await pool.query(
    `SELECT version FROM rmm_software_vendor_releases
      WHERE source_key=$1 AND provider_package_id=$2 AND channel=$3 AND platform=$4 AND architecture=$5
        AND trust_state IN ('asset_candidate','direct_ready') AND asset_health_state IS DISTINCT FROM 'dead'
        AND installer_type IN ('msi','exe')`,
    [sourceKey,b.provider_package_id,b.channel,b.platform,b.architecture],
  )
  if (retained.rows.some((row) => compareVersionValues(row.version,currentVersion)<0
    && !/(alpha|beta|preview|nightly|canary|rc|eap|dev)/i.test(row.version))) return null

  const recipe = object(config.htmlRecipe)
  const compliance = await evaluateVendorHtmlAutomation(
    b.source_url,
    object(config.automationPolicy),
    b.poll_minutes,
  )
  const body = await fetchPublicText(b.source_url, {
    accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
    maxBytes: 8 * 1024 * 1024,
  })
  const candidates = parseVendorHtmlReleases(body,b.source_url,recipe)
    .filter((item) => compareVersionValues(item.version,currentVersion)<0)
  const previous = candidates.at(-1)
  if (!previous) return null
  if (!htmlHostAllowed(previous.installerUrl,recipe.allowedHosts)) {
    throw new Error(sourceKey + ' previous installer host is not allowed by htmlRecipe.allowedHosts')
  }
  const downloadProbe=await resolveAllowedPublicDownload(previous.installerUrl,recipe.allowedHosts)
  const installerUrl=downloadProbe.url
  const installerType=detectInstallerType(previous.assetName || new URL(installerUrl).pathname,clean(config.installerType).toLowerCase())
  if(!['msi','exe'].includes(installerType)) return null
  const expectedSigner=clean(config.autoExpectedSigner || config.expectedSigner || config.signerBaseline)
  const historicalTrustState=expectedSigner ? 'asset_candidate' : 'version_only'
  const payload={
    historicalReleaseCandidate:true,
    historicalRole:'upgrade_baseline',
    expectedSigner,
    deploymentMode:'intelligence_only',
    verification:object(config.verificationConfig),
    installArguments:clean(config.installArguments),
    html:{
      recipeVersion:1,
      compliance,
      sourceUrl:b.source_url,
      selected:{version:previous.version,installerUrl,assetName:previous.assetName,releaseDate:previous.releaseDate},
      allowedHosts:recipe.allowedHosts,
      historical:true,
    },
  }
  const result=await pool.query(
    `INSERT INTO rmm_software_vendor_releases
      (source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,version,
       release_date,installer_url,installer_sha256,installer_type,release_url,asset_name,trust_state,trust_evidence,
       source_priority,source_payload,last_seen_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16::jsonb,$17,$18::jsonb,now())
     ON CONFLICT (source_key,provider_package_id,channel,platform,architecture,version)
     DO NOTHING
     RETURNING id,version,trust_state`,
    [sourceKey,b.provider_package_id,b.canonical_name,b.publisher,b.channel,b.platform,b.architecture,
      previous.version,normalizedReleaseDate(previous.releaseDate),installerUrl,normalizedSha256(previous.installerSha256),
      installerType,previous.releaseUrl || b.source_url,previous.assetName,historicalTrustState,
      JSON.stringify({source:'vendor_html_history',historicalReleaseCandidate:true,sha256Present:Boolean(previous.installerSha256),
        finalDownloadUrl:downloadProbe.url,downloadContentType:downloadProbe.contentType}),
      b.priority,JSON.stringify(payload)],
  )
  return result.rows[0] || null
}

async function retainPreviousWingetReleaseCandidate({ sourceKey, binding: b, config, currentVersion }) {
  const retained=await pool.query(
    `SELECT version FROM rmm_software_vendor_releases
      WHERE source_key=$1 AND provider_package_id=$2 AND channel=$3 AND platform=$4 AND architecture=$5
        AND trust_state IN ('asset_candidate','direct_ready') AND asset_health_state IS DISTINCT FROM 'dead'
        AND installer_type IN ('msi','exe')`,
    [sourceKey,b.provider_package_id,b.channel,b.platform,b.architecture],
  )
  if(retained.rows.some(r=>compareVersionValues(r.version,currentVersion)<0 && !/(alpha|beta|preview|nightly|canary|rc)/i.test(r.version))) return null
  const packageId=clean(config.wingetPackageId || config.packageId)
  if(!packageId) throw new Error('winget_package_identity_missing')
  const resolved=await resolvePreviousWingetVendorInstaller(packageId,currentVersion)
  if(!resolved) return null
  const url=(await publicHttpsUrl(resolved.installerUrl)).toString()
  const payload={
    historicalReleaseCandidate:true,historicalRole:'upgrade_baseline',
    expectedSigner:clean(config.autoExpectedSigner || config.expectedSigner || config.signerBaseline),
    deploymentMode:'intelligence_only',
    verification:resolved.productCode ? {
      ...object(config.verificationConfig),
      method:'uninstall_registry',
      packageId:'',
      productCode:clean(resolved.productCode),
      displayNameContains:clean(object(config.verificationConfig).displayNameContains || b.canonical_name),
      publisherContains:clean(object(config.verificationConfig).publisherContains || b.publisher),
    } : object(config.verificationConfig),
    installArguments:clean(config.installArguments) || resolved.installArguments,
    responseFile:object(config.responseFile),
    installerTechnology:resolved.installerTechnology,
    wingetManifest:{packageId:resolved.packageId,version:resolved.version,manifestUrl:resolved.manifestUrl,
      upstreamHost:resolved.upstreamHost,architecture:resolved.architecture,scope:resolved.scope,
      productCode:clean(resolved.productCode),installerTechnology:resolved.installerTechnology},
  }
  const result=await pool.query(
    `INSERT INTO rmm_software_vendor_releases
      (source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,version,
       installer_url,installer_sha256,installer_type,release_url,asset_name,trust_state,trust_evidence,
       source_priority,source_payload,last_seen_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'asset_candidate',$14::jsonb,$15,$16::jsonb,now())
     ON CONFLICT (source_key,provider_package_id,channel,platform,architecture,version) DO NOTHING
     RETURNING id,version,trust_state`,
    [sourceKey,b.provider_package_id,b.canonical_name,b.publisher,b.channel,b.platform,b.architecture,
      resolved.version,url,resolved.installerSha256,resolved.installerType,resolved.manifestUrl,
      decodeURIComponent(new URL(url).pathname.split('/').at(-1)||''),
      JSON.stringify({source:'winget_manifest_history',historicalReleaseCandidate:true,vendorChecksumPresent:true}),
      b.priority,JSON.stringify(payload)],
  )
  return result.rows[0] || null
}

export async function prepareQualificationBaselineForCatalogue(catalogueId) {
  const candidate = await pool.query(
    `SELECT c.id,c.canonical_name,c.target_version,s.source_key,s.source_url,s.source_type,s.metadata
       FROM rmm_software_catalogue c
       JOIN rmm_software_vendor_sources s
         ON s.source_key=c.source_metadata->>'latestSource'
        AND s.enabled=true
      WHERE c.id=$1
        AND c.tenant_id IS NULL
        AND c.status='active'
        AND c.source_metadata->>'trustState'='direct_ready'
        AND COALESCE(c.target_version,'')<>''
      LIMIT 1`,
    [catalogueId],
  )
  const row = candidate.rows[0]
  if (!row) return { prepared: false, reason: 'catalogue_vendor_source_not_ready' }

  const b = await binding(row.source_key)
  if (!b) return { prepared: false, reason: 'vendor_binding_missing' }

  const releases = await pool.query(
    `SELECT id,version,trust_state,trust_evidence,source_payload,asset_health_state,installer_type,installer_url
       FROM rmm_software_vendor_releases
      WHERE source_key=$1
        AND provider_package_id=$2
        AND channel=$3
        AND platform=$4
        AND architecture=$5
        AND version<>$6
        AND installer_type IN ('msi','exe')
        AND asset_health_state IS DISTINCT FROM 'dead'
      ORDER BY last_seen_at DESC`,
    [row.source_key,b.provider_package_id,b.channel,b.platform,b.architecture,row.target_version],
  )
  const stableOlder = releases.rows.filter((release) =>
    !/(alpha|beta|preview|nightly|canary|rc|eap|dev)/i.test(clean(release.version))
    && compareVersionValues(release.version,row.target_version)<0
  )
  const historicalFailureReason = (release) => clean(
    object(release.trust_evidence).reason
      || object(release.source_payload).artifactInspectionError
      || object(release.source_payload).artifactTrustReason,
  )
  const historicalArtifactUnavailable = (release) => {
    const state = clean(release.trust_state)
    const reason = historicalFailureReason(release)
    return state === 'rejected'
      || ['vendor_checksum_mismatch','sha256_mismatch','vendor_download_failed','artifact_download_failed'].includes(reason)
  }

  const ready = stableOlder.find((release) => clean(release.trust_state)==='direct_ready')
  if (ready) {
    await pool.query(
      `UPDATE rmm_software_vendor_sources
          SET metadata=(metadata - 'baselinePreparationError') || $2::jsonb,updated_at=now()
        WHERE source_key=$1`,
      [row.source_key,JSON.stringify({
        baselinePreparationState:'trusted_baseline_available',
        baselinePreparationTargetVersion:row.target_version,
        baselinePreparationPreviousVersion:clean(ready.version),
        baselinePreparationCompletedAt:new Date().toISOString(),
        baselinePreparationRequestedForCatalogueId:catalogueId,
      })],
    )
    return { prepared: true, ready: true, state: 'trusted_baseline_available', release: ready }
  }
  const pending = stableOlder.find((release) =>
    ['asset_candidate','winget_ready'].includes(clean(release.trust_state))
      && !historicalArtifactUnavailable(release))
  if (pending) {
    await pool.query(
      `UPDATE rmm_software_vendor_sources
          SET metadata=(metadata - 'baselinePreparationError') || $2::jsonb,updated_at=now()
        WHERE source_key=$1`,
      [row.source_key,JSON.stringify({
        baselinePreparationState:'awaiting_artifact_verification',
        baselinePreparationTargetVersion:row.target_version,
        baselinePreparationPreviousVersion:clean(pending.version),
        baselinePreparationCompletedAt:new Date().toISOString(),
        baselinePreparationRequestedForCatalogueId:catalogueId,
      })],
    )
    return { prepared: true, ready: false, state: 'awaiting_artifact_verification', release: pending }
  }

  const unavailableRelease = stableOlder.find(historicalArtifactUnavailable) || stableOlder[0] || null
  const config={...object(b.source_metadata),...object(b.binding_metadata)}
  let retained=null
  if (row.source_type==='github_releases') {
    retained=await retainPreviousGithubReleaseCandidate({
      sourceKey:row.source_key,
      binding:b,
      config,
      repository:repositoryName(config.repository || row.source_url),
      currentVersion:row.target_version,
    })
  } else if (row.source_type==='winget_manifest') {
    retained=await retainPreviousWingetReleaseCandidate({
      sourceKey:row.source_key,
      binding:b,
      config,
      currentVersion:row.target_version,
    })
  } else if (row.source_type==='vendor_json') {
    retained=await retainPreviousVendorJsonReleaseCandidate({
      sourceKey:row.source_key,
      binding:b,
      config,
      currentVersion:row.target_version,
    })
  } else if (row.source_type==='vendor_html') {
    retained=await retainPreviousHtmlReleaseCandidate({
      sourceKey:row.source_key,
      binding:b,
      config,
      currentVersion:row.target_version,
    })
  } else {
    return { prepared:false, reason:'historical_discovery_not_supported_for_source', sourceType:row.source_type }
  }

  if (!retained) {
    const reason = unavailableRelease ? historicalFailureReason(unavailableRelease) || clean(unavailableRelease.trust_state) : 'historical_artifact_not_retrievable'
    await pool.query(
      `UPDATE rmm_software_vendor_sources
          SET metadata=(metadata - 'baselinePreparationError') || $2::jsonb,updated_at=now()
        WHERE source_key=$1`,
      [row.source_key,JSON.stringify({
        baselinePreparationState:'previous_stable_installer_unavailable',
        baselinePreparationTargetVersion:row.target_version,
        baselinePreparationReason:reason,
        baselinePreparationPreviousVersion:clean(unavailableRelease?.version),
        baselinePreparationCompletedAt:new Date().toISOString(),
        baselinePreparationRequestedForCatalogueId:catalogueId,
      })],
    )
    return {
      prepared:false,
      ready:false,
      state:'previous_stable_installer_unavailable',
      reason,
      release:unavailableRelease,
      sourceType:row.source_type,
    }
  }

  await pool.query(
    `UPDATE rmm_software_vendor_sources
        SET metadata=(metadata - 'baselinePreparationError') || $2::jsonb,updated_at=now()
      WHERE source_key=$1`,
    [row.source_key,JSON.stringify({
      baselinePreparationState:'awaiting_artifact_verification',
      baselinePreparationTargetVersion:row.target_version,
      baselinePreparationCompletedAt:new Date().toISOString(),
      baselinePreparationRequestedForCatalogueId:catalogueId,
    })],
  )
  return {
    prepared:true,
    ready:false,
    state:'awaiting_artifact_verification',
    release:retained,
    sourceType:row.source_type,
  }
}

let baselinePreparationActive = false

export async function prepareQualificationBaselines({ limit = 4 } = {}) {
  if (baselinePreparationActive) return []
  baselinePreparationActive = true
  const results = []
  try {
    const candidates = await pool.query(
      `SELECT c.id,c.canonical_name,c.target_version,s.source_key,s.source_url,s.source_type,
              s.metadata,q.state AS clean_install_state
         FROM rmm_software_catalogue c
         JOIN rmm_software_vendor_sources s
           ON s.source_key=c.source_metadata->>'latestSource'
          AND s.enabled=true AND s.source_type IN ('github_releases','winget_manifest','vendor_html')
         LEFT JOIN rmm_software_qualification_queue q
           ON q.catalogue_id=c.id AND q.test_type='clean_install'
        WHERE c.tenant_id IS NULL AND c.status='active'
          AND c.qualification_state='deployment_candidate'
          AND c.source_metadata->>'trustState'='direct_ready'
          AND COALESCE(c.target_version,'')<>''
          AND c.target_version !~* '(alpha|beta|preview|nightly|canary|rc)'
          AND (
            NOT (s.metadata ? 'baselinePreparationAttemptedAt')
            OR (s.metadata->>'baselinePreparationAttemptedAt')::timestamptz < now()-interval '6 hours'
            OR (q.state='passed' AND COALESCE(s.metadata->>'baselinePreparationCleanInstallState','')<>'passed')
          )
        ORDER BY CASE WHEN q.state='passed' THEN 0 ELSE 1 END,
                 COALESCE(s.metadata->>'baselinePreparationAttemptedAt',''),c.canonical_name
        LIMIT $1`,
      [Math.max(1,Math.min(10,Number(limit)||4))],
    )
    for (const row of candidates.rows) {
      await pool.query(
        `UPDATE rmm_software_vendor_sources SET metadata=metadata || $2::jsonb WHERE source_key=$1`,
        [row.source_key,JSON.stringify({baselinePreparationAttemptedAt:new Date().toISOString(),
          baselinePreparationCleanInstallState:row.clean_install_state || ''})],
      )
      try {
        const b = await binding(row.source_key)
        if (!b) throw new Error('vendor_binding_missing')
        const config = {...object(b.source_metadata),...object(b.binding_metadata)}
        const retain = row.source_type === 'winget_manifest'
          ? retainPreviousWingetReleaseCandidate
          : row.source_type === 'vendor_html'
            ? retainPreviousHtmlReleaseCandidate
            : retainPreviousGithubReleaseCandidate
        const retained = await retain({
          sourceKey:row.source_key,binding:b,config,
          repository:repositoryName(config.repository || row.source_url),currentVersion:row.target_version,
        })
        const releases = await pool.query(
          `SELECT version,trust_state,trust_evidence,source_payload FROM rmm_software_vendor_releases
            WHERE source_key=$1 AND provider_package_id=$2
              AND channel=$3 AND platform=$4 AND architecture=$5
              AND trust_state IN ('asset_candidate','winget_ready','direct_ready','rejected')
              AND asset_health_state IS DISTINCT FROM 'dead' AND installer_type IN ('msi','exe')`,
          [row.source_key,b.provider_package_id,b.channel,b.platform,b.architecture],
        )
        const older = releases.rows.filter(r=>!/(alpha|beta|preview|nightly|canary|rc)/i.test(r.version)
          && compareVersionValues(r.version,row.target_version)<0)
        const failureReason = (release) => clean(
          object(release.trust_evidence).reason
            || object(release.source_payload).artifactInspectionError
            || object(release.source_payload).artifactTrustReason,
        )
        const unavailable = (release) => clean(release.trust_state)==='rejected'
          || ['vendor_checksum_mismatch','sha256_mismatch','vendor_download_failed','artifact_download_failed'].includes(failureReason(release))
        const ready = older.find(r=>r.trust_state==='direct_ready')
        const pending = older.find(r=>['asset_candidate','winget_ready'].includes(clean(r.trust_state)) && !unavailable(r))
        const failed = older.find(unavailable) || older[0] || null
        const state = ready ? 'trusted_baseline_available'
          : pending ? 'awaiting_artifact_verification'
            : 'previous_stable_installer_unavailable'
        const baselinePatch = {
          baselinePreparationState:state,
          baselinePreparationTargetVersion:row.target_version,
          baselinePreparationPreviousVersion:clean((ready || pending || failed)?.version),
          baselinePreparationCompletedAt:new Date().toISOString(),
          ...(state==='previous_stable_installer_unavailable' ? {
            baselinePreparationReason:failureReason(failed) || clean(failed?.trust_state) || 'historical_artifact_not_retrievable',
            baselinePreparationPreviousVersion:clean(failed?.version),
          } : {}),
        }
        await pool.query(
          `UPDATE rmm_software_vendor_sources SET metadata=(metadata - 'baselinePreparationError') || $2::jsonb WHERE source_key=$1`,
          [row.source_key,JSON.stringify(baselinePatch)],
        )
        results.push({application:row.canonical_name,state,release:retained,reason:baselinePatch.baselinePreparationReason || ''})
      } catch (error) {
        const message=clean(error?.message || error).slice(0,1000)
        await pool.query(
          `UPDATE rmm_software_vendor_sources SET metadata=metadata || $2::jsonb WHERE source_key=$1`,
          [row.source_key,JSON.stringify({baselinePreparationState:'discovery_failed',baselinePreparationError:message})],
        )
        results.push({application:row.canonical_name,state:'discovery_failed',error:message})
      }
    }
    return results
  } finally { baselinePreparationActive = false }
}

export function startSoftwareVendorSyncScheduler() {
  if (schedulerStarted) return
  schedulerStarted = true
  const run = () => syncDueSoftwareVendorSources().catch((error) => console.error('RMM software vendor scheduler failed', error))
  const qualify = async () => {
    try {
      await Promise.all([
        runVendorArtifactQualification({ inspectLimit: 2 }),
        classifyGithubReleaseBacklog(8),
      ])
      const automaticQualificationSeedingEnabled = !['0', 'false', 'off', 'no']
        .includes(clean(process.env.RMM_AUTOMATIC_QUALIFICATION_SEEDING_ENABLED || 'true').toLowerCase())
      if (automaticQualificationSeedingEnabled) {
        await queueCommonSoftwareQualifications({ limit: 50 })
        await queueAutomaticCleanInstallQualifications({
          limit: 2000,
          allowUnresolvedVulnerability: true,
        })
        await queueAutomaticUpgradeQualifications({ limit: 12 })
      }
    } catch (error) {
      console.error('RMM vendor/software qualification scheduler failed', error)
    }
  }
  const seedBusinessEssentials = () => seedBusinessEssentialVendorCatalogue()
    .catch(error => console.error('Business Essentials catalogue seed failed', error))
  const archiveStructuralDeadWeight = () => archiveStructurallyUnusableCatalogueEntries({ dryRun: false, limit: 1000 })
    .then((result) => {
      if (result.archived) console.log('Business-focused catalogue cleanup', { archived: result.archived, candidates: result.candidates })
    })
    .catch(error => console.error('Business-focused catalogue cleanup failed', error))
  const prepareBaselines = () => prepareQualificationBaselines({ limit: 6 }).catch(error => console.error('Qualification baseline preparation failed', error))
  setTimeout(seedBusinessEssentials, 20_000).unref?.()
  setInterval(seedBusinessEssentials, 24 * 60 * 60_000).unref?.()
  setTimeout(archiveStructuralDeadWeight, 45_000).unref?.()
  setInterval(archiveStructuralDeadWeight, 24 * 60 * 60_000).unref?.()
  setTimeout(prepareBaselines, 15_000).unref?.()
  setInterval(prepareBaselines, 2 * 60_000).unref?.()
  setTimeout(run, 10_000).unref?.()
  setInterval(run, Math.max(60_000, Number(process.env.RMM_VENDOR_SYNC_INTERVAL_MS) || 60_000)).unref?.()
  setTimeout(qualify, 30_000).unref?.()
  setInterval(qualify, 60_000).unref?.()
  setTimeout(runQualificationProgressionTick, 8_000).unref?.()
  setInterval(runQualificationProgressionTick, 15_000).unref?.()
  setTimeout(runQualificationRunnerTick, 5_000).unref?.()
  setInterval(runQualificationRunnerTick, 10_000).unref?.()
}
