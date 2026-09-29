import { pool, withTransaction } from './db.js'
import { COMMON_WINDOWS_SOFTWARE_LOWER } from './rmmCommonSoftware.js'
import { githubApiHeaders, publicHttpsUrl } from './rmmTenantVendorSources.js'

function clean(value = '') { return String(value ?? '').trim() }
function lower(value = '') { return clean(value).toLowerCase() }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }

function htmlDecode(value = '') {
  return String(value)
    .replaceAll('&amp;', '&')
    .replaceAll('&#x2F;', '/')
    .replaceAll('&#47;', '/')
    .replaceAll('&quot;', '"')
}

function assetName(value = '') {
  try {
    const path = new URL(value, 'https://github.com').pathname
    return decodeURIComponent(path.split('/').filter(Boolean).at(-1) || '')
  } catch {
    return clean(value).split('/').at(-1) || ''
  }
}

const GENERIC_PRODUCT_TOKENS = new Set([
  'app','application','client','community','desktop','electron','for','manager',
  'player','professional','studio','the','windows',
])

function compactAssetToken(value = '') {
  return lower(value).replace(/[^a-z0-9]/g, '')
}

function productAssetMatch(name = '', productName = '') {
  const compactName = compactAssetToken(name)
  const tokens = lower(productName)
    .split(/[^a-z0-9]+/)
    .map((token) => token.trim())
    .filter((token) => token.length >= 3 && !GENERIC_PRODUCT_TOKENS.has(token))
  return tokens.some((token) => compactName.includes(compactAssetToken(token)))
}

function releaseLooksLikeRawBinaryMatrix(assets = []) {
  const names = assets.map((asset) => lower(asset?.name)).filter(Boolean)
  const matrixAssets = names.filter((name) =>
    /(?:windows|linux|darwin|macos)[-_.].*(?:amd64|x86_64|arm64|aarch64|386)/i.test(name),
  )
  const guiPackaging = names.some((name) =>
    /\.(?:msi|msix|msixbundle|dmg|pkg|deb|rpm|appimage)$/i.test(name)
    || /(?:setup|installer|install|nsis|inno|squirrel)/i.test(name),
  )
  return matrixAssets.length >= 4 && !guiPackaging
}

function installerAssetAssessment(name = '', productName = '', assets = []) {
  const value = lower(name)
  const product = lower(productName)
  const isMsi = value.endsWith('.msi')
  const isExe = value.endsWith('.exe')
  if (!isMsi && !isExe) return { score: -Infinity, reason: '' }
  if (/\b(?:arm64|aarch64|armv\d*|win32|x32|ia32|i[3-6]86|32[-_. ]?bit)\b/i.test(value)) {
    return { score: -Infinity, reason: '' }
  }
  if (/(?:^|[-_. ])x86(?:[-_. ]|\.exe$)/i.test(value) && !/(?:x86_64|x86-64)/i.test(value)) {
    return { score: -Infinity, reason: '' }
  }
  if (/\b(?:portable|debug|symbols?|pdb|source|src|uninstall)\b/i.test(value)) {
    return { score: -Infinity, reason: '' }
  }

  const explicitInstaller = /(?:setup|installer|install|nsis|inno|squirrel)/i.test(value)
  const windows64 = /(?:windows|win64|win[-_.]?x64|win[-_.]?amd64|x86_64|x86-64|amd64|64[-_. ]?bit)/i.test(value)
  const productMatch = productAssetMatch(value, productName)
  const rawBinaryMatrix = releaseLooksLikeRawBinaryMatrix(assets)

  if (isExe && !explicitInstaller) {
    if (!productMatch) return { score: -Infinity, reason: '' }
    if (!windows64 && rawBinaryMatrix) return { score: -Infinity, reason: '' }
    if (rawBinaryMatrix) return { score: -Infinity, reason: '' }
  }

  let score = isMsi ? 80 : 55
  let reason = isMsi ? 'msi' : explicitInstaller ? 'explicit_installer' : 'product_windows_executable'
  if (/(?:windows|win64|win[-_.]?x64|win[-_.]?amd64)/i.test(value)) score += 25
  if (/(?:x64|x86_64|x86-64|amd64|64[-_. ]?bit)/i.test(value)) score += 20
  if (explicitInstaller) score += 20
  if (/(?:enterprise|machine|allusers)/i.test(value)) score += 5
  if (/legacy/i.test(value) && !/legacy/i.test(product)) score -= 60
  if (/\bagent\b/i.test(value) && !/\bagent\b/i.test(product)) score -= 50
  if (/\bserver\b/i.test(value) && !/\bserver\b/i.test(product)) score -= 35
  if (/\bcli\b/i.test(value) && !/\bcli\b/i.test(product)) score -= 25
  if (/(?:web|bootstrap)/i.test(value)) score -= 8
  return { score, reason }
}

function checksumAssetScore(name = '') {
  const value = lower(name)
  if (/sha256sums?|checksums?.*sha256|sha256.*checksums?/.test(value)) return 100
  if (/\.sha256(?:sum)?$/.test(value)) return 90
  if (/checksums?|shasums?/.test(value)) return 60
  return -Infinity
}

export function rankWindowsInstallerAssets(assets = [], productName = '', preferredInstallerType = '') {
  const preferred = lower(preferredInstallerType)
  return assets
    .map((asset) => {
      const assessment = installerAssetAssessment(asset?.name, productName, assets)
      const type = lower(asset?.name).endsWith('.msi') ? 'msi' : lower(asset?.name).endsWith('.exe') ? 'exe' : ''
      const continuityBonus = preferred && type === preferred ? 1000 : 0
      return { ...asset, installerType: type, score: assessment.score + continuityBonus, selectionReason: continuityBonus ? 'installer_continuity_' + type : assessment.reason }
    })
    .filter((asset) => Number.isFinite(asset.score))
    .sort((a, b) => b.score - a.score || clean(a.name).localeCompare(clean(b.name)))
}

export function selectWindowsInstallerAsset(assets = [], productName = '', preferredInstallerType = '') {
  return rankWindowsInstallerAssets(assets, productName, preferredInstallerType)[0] || null
}

export function classifyWindowsReleaseAssets(assets = []) {
  const names = assets.map((asset) => clean(asset?.name)).filter(Boolean)
  const x64 = (name) => /(?:windows|win(?:64)?|pc-windows).*(?:x64|amd64|x86_64)|(?:x64|amd64|x86_64).*(?:windows|win(?:64)?|pc-windows)/i.test(name)
  const packageAsset = names.find((name) => !/(?:arm64|aarch64|win32|x86(?:[-_.]|$))/i.test(name) && /\.(?:msixbundle|appxbundle)$/i.test(name))
    || names.find((name) => !/(?:arm64|aarch64|win32|x86(?:[-_.]|$))/i.test(name) && /\.(?:msix|appx)$/i.test(name))
  const supported = names.filter((name) => x64(name) && /\.(?:zip|7z|tar\.gz|tgz|exe)$/i.test(name))
  const portableAsset = supported.find((name) => /\.(?:zip|7z|tar\.gz|tgz)$/i.test(name))
  const binaryAsset = supported.find((name) => /\.exe$/i.test(name) && !/(?:setup|installer|install|nsis|inno|squirrel)/i.test(name))
  if (packageAsset) return { kind: /bundle$/i.test(packageAsset) ? 'msix_bundle' : 'msix', assetName: packageAsset, deployableNow: false, blocker: 'msix_transport_not_qualified' }
  if (portableAsset) return { kind: 'portable_windows_archive', assetName: portableAsset, deployableNow: false, blocker: 'portable_transport_not_qualified' }
  if (binaryAsset) return { kind: 'portable_windows_binary', assetName: binaryAsset, deployableNow: false, blocker: 'portable_transport_not_qualified' }
  return { kind: 'none', assetName: '', deployableNow: false, blocker: 'vendor_windows_asset_missing' }
}

export function selectChecksumAsset(assets = []) {
  return assets
    .map((asset) => ({ ...asset, score: checksumAssetScore(asset?.name) }))
    .filter((asset) => Number.isFinite(asset.score))
    .sort((a, b) => b.score - a.score || clean(a.name).localeCompare(clean(b.name)))[0] || null
}

export async function githubExpandedAssets(repository, tag) {
  const [owner, repo] = clean(repository).split('/')
  if (!owner || !repo || !clean(tag)) return []
  const url = await publicHttpsUrl(
    'https://github.com/' + owner + '/' + repo + '/releases/expanded_assets/' + encodeURIComponent(clean(tag)),
  )
  const response = await fetch(url, {
    headers: { Accept: 'text/html', 'User-Agent': 'Hi5Central-Software-Catalogue/1.0' },
    signal: AbortSignal.timeout(30_000),
  })
  if (!response.ok) throw new Error('GitHub expanded assets HTTP ' + response.status)
  const body = await response.text()
  const seen = new Set()
  const assets = []
  const matcher = /href="([^"]*\/releases\/download\/[^"]+)"/gi
  for (const match of body.matchAll(matcher)) {
    const href = htmlDecode(match[1])
    const resolved = new URL(href, 'https://github.com').toString()
    if (seen.has(resolved)) continue
    seen.add(resolved)
    assets.push({ name: assetName(resolved), browser_download_url: resolved })
  }
  return assets
}

export async function discoverGithubWindowsInstaller(repository, tag, productName = '') {
  const [owner, repo] = clean(repository).split('/')
  let assets = []
  if (owner && repo && clean(tag)) {
    try {
      const apiUrl = await publicHttpsUrl(
        'https://api.github.com/repos/' + owner + '/' + repo + '/releases/tags/' + encodeURIComponent(clean(tag)),
      )
      const response = await fetch(apiUrl, {
        headers: githubApiHeaders(),
        signal: AbortSignal.timeout(30_000),
      })
      if (response.ok) {
        const release = await response.json()
        assets = Array.isArray(release?.assets) ? release.assets : []
      }
    } catch {}
  }
  if (!assets.length) assets = await githubExpandedAssets(repository, tag)
  return {
    installer: selectWindowsInstallerAsset(assets, productName),
    installers: rankWindowsInstallerAssets(assets, productName),
    checksum: selectChecksumAsset(assets),
    assetsSeen: assets.length,
  }
}

export async function classifyGithubReleaseBacklog(limit = 8) {
  const rows = await pool.query(`SELECT c.id,c.canonical_name,b.metadata->>'repository' AS repository,r.source_payload->'github'->>'tag_name' AS tag_name FROM rmm_software_catalogue c JOIN rmm_software_vendor_releases r ON r.provider_package_id=c.external_key AND r.version=c.target_version JOIN rmm_software_vendor_bindings b ON b.source_key=r.source_key AND b.provider_package_id=r.provider_package_id WHERE c.tenant_id IS NULL AND c.status='active' AND c.qualification_state='intelligence_only' AND r.trust_state='version_only' AND r.source_key LIKE 'gh_%' AND COALESCE(c.source_metadata->>'releaseAssetClassifiedTag','')<>COALESCE(r.source_payload->'github'->>'tag_name','') ORDER BY c.updated_at ASC LIMIT $1`, [Math.max(1, Math.min(25, Number(limit)||8))])
  const classified=[]
  for (const row of rows.rows) {
    if (!clean(row.repository) || !clean(row.tag_name)) continue
    try {
      const assets=await githubExpandedAssets(row.repository,row.tag_name)
      const result=classifyWindowsReleaseAssets(assets)
      await pool.query(`UPDATE rmm_software_catalogue SET source_metadata=source_metadata || $2::jsonb,updated_at=now() WHERE id=$1`,[row.id,JSON.stringify({releaseAssetClassifiedTag:row.tag_name,releaseAssetKind:result.kind,releaseAssetName:result.assetName,releaseAssetBlocker:result.blocker,releaseAssetClassifiedAt:new Date().toISOString()})])
      classified.push({canonicalName:row.canonical_name,...result})
    } catch {}
  }
  return classified
}

export function vendorReleaseTrustProfile(input = {}) {
  const installerUrl = clean(input.installerUrl)
  const installerSha256 = clean(input.installerSha256).toUpperCase()
  const installerType = lower(input.installerType)
  const expectedSigner = clean(input.expectedSigner)
  const verification = object(input.verification)
  const wingetPackageId = clean(input.wingetPackageId)
  const existingMode = clean(input.deploymentMode)
  const verificationReady = Boolean(
    verification.method
    && (verification.productCode || verification.displayNameContains || verification.filePath || verification.packageId),
  )
  const directReady = Boolean(
    /^https:\/\//i.test(installerUrl)
    && /^[A-F0-9]{64}$/.test(installerSha256)
    && ['msi','exe'].includes(installerType)
    && expectedSigner.length >= 4
    && verificationReady
  )

  const trustState = directReady
    ? 'direct_ready'
    : installerUrl && ['msi','exe'].includes(installerType)
      ? 'asset_candidate'
      : 'version_only'

  const deploymentMode = directReady
    ? 'vendor_direct'
    : wingetPackageId
      ? 'winget_preferred'
      : existingMode === 'vendor_direct'
        ? 'intelligence_only'
        : (existingMode || 'intelligence_only')

  const qualificationState = directReady || wingetPackageId
    ? 'deployment_candidate'
    : 'intelligence_only'

  return {
    trustState,
    deploymentMode,
    qualificationState,
    expectedSigner: directReady ? expectedSigner : '',
    evidence: {
      automaticVendorRelease: true,
      installerSelected: Boolean(installerUrl),
      installerType,
      vendorChecksumPresent: /^[A-F0-9]{64}$/.test(installerSha256),
      signerExpectationSource: directReady ? 'curated_publisher' : 'not_ready',
      verificationReady,
      wingetFallback: Boolean(wingetPackageId),
    },
  }
}

function signerKey(value = '') {
  return lower(value)
    .replace(/[^a-z0-9]/g, '')
}

function signerEquivalent(left = '', right = '') {
  const a = signerKey(left)
  const b = signerKey(right)
  if (!a || !b) return false
  return a === b || (a.length >= 8 && b.length >= 8 && (a.includes(b) || b.includes(a)))
}

function probeResult(row = {}) {
  const result = object(row.result)
  return result
}

export async function reconcileVendorArtifactInspections() {
  const jobs = await pool.query(
    `SELECT j.id,j.status,j.result,j.error_message,j.request_metadata,
            r.id AS release_id,r.source_key,r.provider_package_id,r.canonical_name,r.version,
            r.installer_url,r.installer_sha256,r.installer_type,r.trust_state,r.source_payload,
            b.metadata AS binding_metadata
       FROM rmm_agent_jobs j
       JOIN rmm_software_vendor_releases r
         ON r.id::text=j.request_metadata->>'vendor_release_id'

       LEFT JOIN rmm_software_vendor_bindings b
         ON b.source_key=r.source_key
        AND b.provider_package_id=r.provider_package_id
        AND b.channel=r.channel
        AND b.platform=r.platform
        AND b.architecture=r.architecture
      WHERE j.job_type='patch.vendor_artifact.inspect'
        AND j.request_metadata->>'source' IN ('vendor_artifact_trust_probe','manual_catalogue_revalidation')
        AND COALESCE(j.request_metadata->>'reconciled','false')<>'true'
        AND j.status IN ('completed','failed')
      ORDER BY j.completed_at NULLS LAST,j.created_at
      LIMIT 50`,
  )

  const reconciled = []
  for (const row of jobs.rows) {
    const result = probeResult(row)
    const actualSha = clean(result.sha256 || result.actualSha256).toUpperCase()
    const configuredSha = clean(row.installer_sha256).toUpperCase()
    const signer = clean(result.signer)
    const signatureVerified = result.signatureVerified === true
    const hashVerified = /^[A-F0-9]{64}$/.test(actualSha)
      && (!configuredSha || configuredSha === actualSha)
    const metadata = object(row.binding_metadata)
    const sourcePayload = object(row.source_payload)
    const trustPayload = object(sourcePayload.trustEvidence)
    const githubPayload = object(sourcePayload.github)
    const selectionReason = clean(
      trustPayload.selectedAssetReason
      || githubPayload.selectedAssetReason
      || metadata.selectedAssetReason,
    )
    const configuredInstallerTechnology = lower(clean(metadata.installerTechnology))
    const installerTechnology = configuredInstallerTechnology === 'office_odt_sfx'
      ? configuredInstallerTechnology
      : lower(clean(result.installerTechnology))
    const installerTechnologyRecognized = configuredInstallerTechnology === 'office_odt_sfx'
      || result.installerTechnologyRecognized === true
      || ['msi','inno','nullsoft','nsis','burn','installshield','squirrel','install4j'].includes(installerTechnology)
    const curatedInstallArguments = clean(sourcePayload.installArguments || metadata.installArguments)
    const deploymentSupported = ['msi', 'exe'].includes(lower(row.installer_type))
    const technologyRequired = lower(row.installer_type) === 'exe'
      && !curatedInstallArguments
    const signerBaseline = clean(metadata.signerBaseline || metadata.expectedSigner)
    const inspectionError = lower(clean(result.error || row.error_message))

    let trustState = 'asset_candidate'
    let reason = clean(row.error_message || result.error) || 'inspection_incomplete'
    if (row.status === 'completed' && hashVerified && signatureVerified && signer) {
      if (signerBaseline && !signerEquivalent(signerBaseline, signer)) {
        trustState = 'signer_review_required'
        reason = 'signer_changed_from_baseline'
      } else if (!deploymentSupported) {
        trustState = 'asset_candidate'
        reason = 'inspection_only_transport_not_qualified'
      } else if (technologyRequired && !installerTechnologyRecognized) {
        trustState = 'installer_review_required'
        reason = 'installer_technology_unrecognized'
      } else {
        trustState = 'direct_ready'
        reason = technologyRequired
          ? 'authenticode_sha256_and_installer_technology_verified'
          : 'authenticode_and_sha256_verified'
      }
    } else if (configuredSha && actualSha && configuredSha !== actualSha) {
      trustState = 'rejected'
      reason = 'vendor_checksum_mismatch'
    } else if (
      inspectionError === 'authenticode_invalid'
      || inspectionError === 'authenticode_signer_missing'
      || (row.status === 'completed' && !signatureVerified)
    ) {
      trustState = 'rejected'
      reason = inspectionError || 'authenticode_invalid'
    }

    const resolvedSha = trustState === 'direct_ready' ? (configuredSha || actualSha) : configuredSha
    const expectedSigner = trustState === 'direct_ready' ? (signerBaseline || signer) : signerBaseline
    const hashProvenance = configuredSha ? 'vendor_published_checksum' : 'endpoint_pinned_sha256'
    const evidence = {
      source: 'patchhost_artifact_inspection',
      jobId: row.id,
      inspectedAt: new Date().toISOString(),
      reason,
      sha256: actualSha,

      hashProvenance,
      signatureVerified,
      signer,
      signerBaseline: signerBaseline || signer,
      installerUrl: row.installer_url,
      installerType: row.installer_type,
      selectionReason,
      installerTechnology,
      installerTechnologyRecognized,
      installerTechnologyRequired: technologyRequired,
      deploymentSupported,
      packageIdentity: object(result.packageIdentity),
      packageInspection: object(result.packageInspection),
      patchHostVersion: clean(object(result.capabilities).patchHostVersion),
    }

    await withTransaction(async (client) => {
      await client.query(
        `UPDATE rmm_software_vendor_releases
            SET installer_sha256=CASE WHEN $2<>'' THEN $2 ELSE installer_sha256 END,
                trust_state=$3,
                trust_evidence=trust_evidence || $4::jsonb,
                source_payload=source_payload || $5::jsonb,
                last_seen_at=now()
          WHERE id=$1`,
        [
          row.release_id,
          resolvedSha,
          trustState,
          JSON.stringify(evidence),
          JSON.stringify({
            trustState,
            deploymentMode: trustState === 'direct_ready' ? 'vendor_direct' : 'intelligence_only',
            expectedSigner,
            signerBaseline: signerBaseline || signer,
            artifactHashProvenance: hashProvenance,
            installerTechnology,
            selectedAssetReason: selectionReason,
          }),
        ],
      )

      if (trustState === 'direct_ready' && sourcePayload.historicalReleaseCandidate !== true) {
        await client.query(
          `UPDATE rmm_software_vendor_bindings
              SET metadata=metadata || $3::jsonb
            WHERE source_key=$1 AND provider_package_id=$2 AND enabled=true`,
          [
            row.source_key,
            row.provider_package_id,
            JSON.stringify({
              deploymentMode: 'vendor_direct',
              expectedSigner,
              signerBaseline: signerBaseline || signer,
              trustState,
              installerType: row.installer_type,
              installerTechnology,
              selectedAssetReason: selectionReason,
              automaticVendorRelease: true,
              artifactHashProvenance: hashProvenance,
              trustedReleaseVersion: row.version,
              trustedReleaseSha256: resolvedSha,
            }),
          ],
        )

        await client.query(
          `UPDATE rmm_software_catalogue
              SET source_metadata=source_metadata || $2::jsonb,
                  qualification_state=CASE
                    WHEN qualification_state IN ('qualified','qualified_limited','blocked') THEN qualification_state
                    ELSE 'deployment_candidate'
                  END,

                  qualification_evidence=qualification_evidence || $3::jsonb,
                  qualification_notes=CASE
                    WHEN qualification_notes<>'' THEN qualification_notes
                    ELSE 'Automatically promoted after non-executing PatchHost artifact trust inspection.'
                  END,
                  updated_at=now()
            WHERE tenant_id IS NULL
              AND catalogue_source='vendor'
              AND external_key=$1
              AND target_version=$4
              AND source_metadata->>'latestSource'=$5
              AND status='active'`,
          [
            row.provider_package_id,
            JSON.stringify({
              deploymentMode: 'vendor_direct',
              expectedSigner,
              signerBaseline: signerBaseline || signer,
              trustState,
              installerTechnology,
              selectedAssetReason: selectionReason,
              automaticVendorRelease: true,
              artifactHashProvenance: hashProvenance,
            }),
            JSON.stringify({
              source: 'automatic_vendor_release',
              vendorReleaseId: row.release_id,
              artifactInspectionJobId: row.id,
              artifactVerificationVersion: row.version,
              artifactVerifiedAt: new Date().toISOString(),
              authenticodeVerified: true,
              sha256Verified: true,
              signer,
              hashProvenance,
            }),
            row.version,
            row.source_key,
          ],
        )
      } else if (sourcePayload.historicalReleaseCandidate !== true) {
        await client.query(
          `UPDATE rmm_software_catalogue
              SET source_metadata=source_metadata || $2::jsonb,updated_at=now()
            WHERE tenant_id IS NULL
              AND catalogue_source='vendor'
              AND external_key=$1
              AND target_version=$3
              AND source_metadata->>'latestSource'=$4
              AND status='active'`,
          [
            row.provider_package_id,
            JSON.stringify({ trustState, trustEvidence: evidence, ...(!deploymentSupported ? { deploymentMode: 'intelligence_only' } : {}) }),
            row.version,
            row.source_key,
          ],
        )
      }

      await client.query(
        `UPDATE rmm_agent_jobs
            SET request_metadata=request_metadata || $2::jsonb
          WHERE id=$1`,
        [row.id, JSON.stringify({
          reconciled: 'true',
          reconciledAt: new Date().toISOString(),
          trustState,
          trustReason: reason,
        })],
      )
    })
    reconciled.push({ releaseId: row.release_id, sourceKey: row.source_key, trustState, reason })
  }
  return reconciled
}

export async function queueVendorArtifactInspections(limit = 2) {
  const cappedLimit = Math.max(0, Math.min(5, Number(limit) || 0))
  if (!cappedLimit) return []

  const runners = await pool.query(
    `SELECT a.id AS agent_device_id,a.tenant_id,i.name AS device_name
       FROM rmm_software_vendor_qualification_runners q
       JOIN rmm_agent_devices a ON a.id=q.agent_device_id AND a.disabled_at IS NULL
       JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true
      WHERE q.enabled=true
        AND a.websocket_status='Connected'
        AND a.last_telemetry_at>now()-interval '90 seconds'
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'artifactInspection')::boolean,false)=true
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'artifactTechnologyDetection')::boolean,false)=true
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'artifactStorage'),'')='job_scoped'
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'jobDirectoryPurgedOnExit')::boolean,false)=true
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'winInetCacheUsed')::boolean,true)=false
      ORDER BY a.last_telemetry_at DESC
      LIMIT 1`,
  )
  const runner = runners.rows[0]
  if (!runner) return []

  const qualificationBusy = await pool.query(
    `SELECT 1
       FROM rmm_software_qualification_queue q
       JOIN rmm_software_catalogue c ON c.id=q.catalogue_id
      WHERE c.tenant_id IS NULL
        AND c.status='active'
        AND q.state IN ('queued','running','cleanup_pending','cleanup_running')
      LIMIT 1`,
  )
  if (qualificationBusy.rowCount) return []

  const active = await pool.query(
    `SELECT count(*)::int AS count
       FROM rmm_agent_jobs
      WHERE agent_device_id=$1
        AND job_type='patch.vendor_artifact.inspect'
        AND status IN ('queued','claimed')`,
    [runner.agent_device_id],
  )
  const availableSlots = Math.max(0, cappedLimit - Number(active.rows[0]?.count || 0))
  if (!availableSlots) return []

  const candidates = await pool.query(
    `WITH ranked AS (
       SELECT r.id,r.source_key,r.provider_package_id,r.canonical_name,r.version,
              r.installer_url,r.installer_sha256,r.installer_type,r.last_seen_at,
              CASE
                WHEN COALESCE(r.source_payload->>'historicalReleaseCandidate','false')='true'
                  AND EXISTS (
                    SELECT 1
                      FROM rmm_software_catalogue c
                      JOIN rmm_software_qualification_queue q
                        ON q.catalogue_id=c.id
                       AND q.test_type='clean_install'
                       AND q.state='passed'
                     WHERE c.tenant_id IS NULL
                       AND c.status='active'
                       AND c.external_key=r.provider_package_id
                       AND c.source_metadata->>'latestSource'=r.source_key
                  )
                THEN 0 ELSE 1
              END AS priority_group,
              row_number() OVER (
                PARTITION BY r.source_key,r.provider_package_id
                ORDER BY
                  CASE
                    WHEN COALESCE(r.source_payload->>'historicalReleaseCandidate','false')='true'
                      AND EXISTS (
                        SELECT 1
                          FROM rmm_software_catalogue c
                          JOIN rmm_software_qualification_queue q
                            ON q.catalogue_id=c.id
                           AND q.test_type='clean_install'
                           AND q.state='passed'
                         WHERE c.tenant_id IS NULL
                           AND c.status='active'
                           AND c.external_key=r.provider_package_id
                           AND c.source_metadata->>'latestSource'=r.source_key
                      )
                    THEN 0 ELSE 1
                  END,
                  r.last_seen_at DESC
              ) AS rn
         FROM rmm_software_vendor_releases r
        WHERE (
            r.trust_state IN ('asset_candidate','winget_ready')
            OR (
              r.trust_state='direct_ready'
              AND COALESCE(r.trust_evidence->>'signatureVerified','false')<>'true'
            )
          )
          AND r.installer_url<>''
          AND r.installer_type IN ('msi','exe')
          AND NOT EXISTS (
            SELECT 1 FROM rmm_agent_jobs j
             WHERE j.job_type='patch.vendor_artifact.inspect'
               AND j.request_metadata->>'vendor_release_id'=r.id::text
               AND j.status IN ('queued','claimed')
          )
          AND NOT EXISTS (
            SELECT 1 FROM rmm_agent_jobs j
             WHERE j.job_type='patch.vendor_artifact.inspect'
               AND j.request_metadata->>'vendor_release_id'=r.id::text
               AND j.status IN ('completed','failed')
               AND j.created_at>now()-interval '24 hours'
               AND NOT (
                 j.status='failed'
                 AND lower(COALESCE(j.error_message,''))='patchhost did not return a result.'
               )
          )
     )
     SELECT id,source_key,provider_package_id,canonical_name,version,
            installer_url,installer_sha256,installer_type
       FROM ranked
      WHERE rn=1
      ORDER BY priority_group,
               CASE WHEN lower(canonical_name)=ANY($2::text[]) THEN 0 ELSE 1 END,
               last_seen_at DESC
      LIMIT $1`,
    [availableSlots, COMMON_WINDOWS_SOFTWARE_LOWER],
  )

  const queued = []
  for (const release of candidates.rows) {
    const safeUrl = await publicHttpsUrl(release.installer_url)
    const inserted = await pool.query(
      `INSERT INTO rmm_agent_jobs
        (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
       VALUES ($1,$2,'patch.vendor_artifact.inspect',$3::jsonb,'system','Vendor catalogue trust',$4::jsonb)
       RETURNING id,status,created_at`,

      [
        runner.tenant_id,
        runner.agent_device_id,
        JSON.stringify({
          protocolVersion: 1,
          action: 'software.inspect',
          provider: 'vendor_direct',
          applicationName: release.canonical_name,
          targetVersion: release.version,
          downloadUrl: safeUrl.toString(),
          sha256: clean(release.installer_sha256),
          installerType: release.installer_type,
        }),
        JSON.stringify({
          source: 'vendor_artifact_trust_probe',
          vendor_release_id: release.id,
          vendor_source_key: release.source_key,
          canonical_name: release.canonical_name,
          expected_version: release.version,
        }),
      ],
    )
    queued.push({
      jobId: inserted.rows[0].id,
      releaseId: release.id,
      sourceKey: release.source_key,
      applicationName: release.canonical_name,
      version: release.version,
      deviceName: runner.device_name,
    })
  }
  return queued
}

export async function queueVendorArtifactInspectionForCatalogue(catalogueId) {
  const releaseResult = await pool.query(
    `SELECT r.id,r.source_key,r.provider_package_id,r.canonical_name,r.version,
            r.installer_url,r.installer_sha256,r.installer_type
       FROM rmm_software_catalogue c
       JOIN rmm_software_vendor_releases r
         ON r.provider_package_id=c.external_key
        AND r.source_key=c.source_metadata->>'latestSource'
        AND r.version=c.target_version
      WHERE c.id=$1 AND c.tenant_id IS NULL AND c.status='active'
        AND r.installer_url<>'' AND r.installer_type IN ('msi','exe')
      LIMIT 1`,
    [catalogueId],
  )
  const release = releaseResult.rows[0]
  if (!release) return { queued: false, reason: 'vendor_release_not_ready' }

  const existing = await pool.query(
    `SELECT id,status
       FROM rmm_agent_jobs
      WHERE job_type='patch.vendor_artifact.inspect'
        AND request_metadata->>'vendor_release_id'=$1
        AND status IN ('queued','claimed')
      ORDER BY created_at DESC LIMIT 1`,
    [release.id],
  )
  if (existing.rowCount) {
    return { queued: false, active: true, jobId: existing.rows[0].id, releaseId: release.id }
  }

  const runnerResult = await pool.query(
    `SELECT a.id AS agent_device_id,a.tenant_id,i.name AS device_name
       FROM rmm_software_vendor_qualification_runners q
       JOIN rmm_agent_devices a ON a.id=q.agent_device_id AND a.disabled_at IS NULL
       JOIN rmm_device_inventory i ON i.id=a.inventory_id AND i.active=true
      WHERE q.enabled=true
        AND a.websocket_status='Connected'
        AND a.last_telemetry_at>now()-interval '90 seconds'
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'artifactInspection')::boolean,false)=true
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'artifactTechnologyDetection')::boolean,false)=true
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'artifactStorage'),'')='job_scoped'
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'jobDirectoryPurgedOnExit')::boolean,false)=true
        AND COALESCE((a.patch_capabilities->'vendorDirect'->>'winInetCacheUsed')::boolean,true)=false
      ORDER BY a.last_telemetry_at DESC LIMIT 1`,
  )
  const runner = runnerResult.rows[0]
  if (!runner) return { queued: false, reason: 'qualification_runner_offline' }

  const safeUrl = await publicHttpsUrl(release.installer_url)
  const inserted = await pool.query(
    `INSERT INTO rmm_agent_jobs
      (tenant_id,agent_device_id,job_type,payload,initiated_by,initiated_by_label,request_metadata)
     VALUES ($1,$2,'patch.vendor_artifact.inspect',$3::jsonb,'system','Manual catalogue revalidation',$4::jsonb)
     RETURNING id,status,created_at`,
    [
      runner.tenant_id,
      runner.agent_device_id,
      JSON.stringify({
        protocolVersion: 1,
        action: 'software.inspect',
        provider: 'vendor_direct',
        applicationName: release.canonical_name,
        targetVersion: release.version,
        downloadUrl: safeUrl.toString(),
        sha256: clean(release.installer_sha256),
        installerType: release.installer_type,
      }),
      JSON.stringify({
        source: 'manual_catalogue_revalidation',
        vendor_release_id: release.id,
        vendor_source_key: release.source_key,
        canonical_name: release.canonical_name,
        expected_version: release.version,
        catalogue_id: catalogueId,
      }),
    ],
  )
  return {
    queued: true,
    jobId: inserted.rows[0].id,
    releaseId: release.id,
    sourceKey: release.source_key,
    applicationName: release.canonical_name,
    version: release.version,
    deviceName: runner.device_name,
  }
}

async function reconcileDirectReadyCatalogue() {
  await pool.query(
    `UPDATE rmm_software_vendor_releases
        SET installer_sha256=upper(trust_evidence->>'sha256'),last_seen_at=last_seen_at
      WHERE trust_state='direct_ready'
        AND COALESCE(installer_sha256,'')=''
        AND COALESCE(trust_evidence->>'signatureVerified','false')='true'
        AND COALESCE(trust_evidence->>'sha256','') ~* '^[a-f0-9]{64}$'`,
  )
  const result = await pool.query(
    `UPDATE rmm_software_catalogue c
        SET source_metadata=c.source_metadata || jsonb_build_object(
              'deploymentMode','vendor_direct',
              'trustState','direct_ready',
              'automaticVendorRelease',true,
              'expectedSigner',COALESCE(NULLIF(b.metadata->>'expectedSigner',''),NULLIF(r.source_payload->>'expectedSigner',''),NULLIF(r.trust_evidence->>'signer',''),''),
              'installerTechnology',COALESCE(NULLIF(b.metadata->>'installerTechnology',''),NULLIF(r.source_payload->>'installerTechnology',''),NULLIF(r.trust_evidence->>'installerTechnology',''),''),
              'artifactHashProvenance',COALESCE(NULLIF(r.source_payload->>'artifactHashProvenance',''),NULLIF(r.trust_evidence->>'hashProvenance',''),'endpoint_pinned_sha256')
            ),
            qualification_state=CASE
              WHEN c.qualification_state='blocked' THEN c.qualification_state
              WHEN c.qualification_state IN ('qualified','qualified_limited')
               AND (
                (
                  COALESCE(c.qualification_evidence->>'cleanInstallVersion','')<>''
                  AND c.qualification_evidence->>'cleanInstallVersion'<>c.target_version
                )
                OR (
                  COALESCE(c.qualification_version,'')<>''
                  AND c.qualification_version<>c.target_version
                )
              ) THEN 'deployment_candidate'
              WHEN NOT (
                COALESCE((r.trust_evidence->>'signatureVerified')::boolean,false)
                AND COALESCE(r.trust_evidence->>'sha256','') ~* '^[a-f0-9]{64}$'
                AND upper(r.trust_evidence->>'sha256')=upper(r.installer_sha256)
              ) THEN 'deployment_candidate'
              WHEN c.qualification_state IN ('qualified','qualified_limited') THEN c.qualification_state
              ELSE 'deployment_candidate'
            END,
            qualification_version=CASE
              WHEN c.qualification_state<>'blocked'
               AND (
                 NOT (
                   COALESCE((r.trust_evidence->>'signatureVerified')::boolean,false)
                   AND COALESCE(r.trust_evidence->>'sha256','') ~* '^[a-f0-9]{64}$'
                   AND upper(r.trust_evidence->>'sha256')=upper(r.installer_sha256)
                 )
                 OR (
                  (
                    COALESCE(c.qualification_evidence->>'cleanInstallVersion','')<>''
                    AND c.qualification_evidence->>'cleanInstallVersion'<>c.target_version
                  )
                  OR (
                    COALESCE(c.qualification_version,'')<>''
                    AND c.qualification_version<>c.target_version
                  )
                )
               ) THEN ''
              ELSE c.qualification_version
            END,
            qualified_at=CASE
              WHEN c.qualification_state<>'blocked'
               AND (
                 NOT (
                   COALESCE((r.trust_evidence->>'signatureVerified')::boolean,false)
                   AND COALESCE(r.trust_evidence->>'sha256','') ~* '^[a-f0-9]{64}$'
                   AND upper(r.trust_evidence->>'sha256')=upper(r.installer_sha256)
                 )
                 OR (
                  (
                    COALESCE(c.qualification_evidence->>'cleanInstallVersion','')<>''
                    AND c.qualification_evidence->>'cleanInstallVersion'<>c.target_version
                  )
                  OR (
                    COALESCE(c.qualification_version,'')<>''
                    AND c.qualification_version<>c.target_version
                  )
                )
               ) THEN NULL
              ELSE c.qualified_at
            END,
            qualification_evidence=c.qualification_evidence || jsonb_build_object(
              'source','vendor_release_trust_reconciliation',
              'vendorReleaseId',r.id,
              'artifactVerificationVersion',c.target_version,
              'artifactVerifiedAt',NULLIF(r.trust_evidence->>'inspectedAt',''),
              'authenticodeVerified',COALESCE((r.trust_evidence->>'signatureVerified')::boolean,false),
              'sha256Verified',(
                COALESCE(r.trust_evidence->>'sha256','') ~* '^[a-f0-9]{64}$'
                AND upper(r.trust_evidence->>'sha256')=upper(r.installer_sha256)
              ),
              'signer',COALESCE(r.trust_evidence->>'signer','')
            ),
            qualification_notes=CASE
              WHEN c.qualification_state IN ('qualified','qualified_limited')
               AND (
                (
                  COALESCE(c.qualification_evidence->>'cleanInstallVersion','')<>''
                  AND c.qualification_evidence->>'cleanInstallVersion'<>c.target_version
                )
                OR (
                  COALESCE(c.qualification_version,'')<>''
                  AND c.qualification_version<>c.target_version
                )
              )
                THEN 'Target version changed; current install/verify/uninstall qualification is required.'
              WHEN NOT (
                COALESCE((r.trust_evidence->>'signatureVerified')::boolean,false)
                AND COALESCE(r.trust_evidence->>'sha256','') ~* '^[a-f0-9]{64}$'
                AND upper(r.trust_evidence->>'sha256')=upper(r.installer_sha256)
              ) THEN 'Trusted release metadata is available; endpoint artifact signature/hash inspection is pending.'
              WHEN c.qualification_notes<>'' THEN c.qualification_notes
              ELSE 'Deployment-ready vendor artifact reconciled from verified release trust evidence.'
            END,
            updated_at=now()
       FROM rmm_software_vendor_releases r
       LEFT JOIN rmm_software_vendor_bindings b
         ON b.source_key=r.source_key AND b.provider_package_id=r.provider_package_id
        AND b.channel=r.channel AND b.platform=r.platform AND b.architecture=r.architecture AND b.enabled=true
      WHERE c.tenant_id IS NULL AND c.catalogue_source='vendor' AND c.status='active'
        AND c.external_key=r.provider_package_id
        AND c.source_metadata->>'latestSource'=r.source_key
        AND c.target_version=r.version
        AND r.trust_state='direct_ready' AND r.installer_type IN ('msi','exe') AND r.installer_url LIKE 'https://%'
        AND r.installer_sha256 ~* '^[a-f0-9]{64}$'
        AND (COALESCE(c.source_metadata->>'deploymentMode','')<>'vendor_direct'
          OR COALESCE(c.source_metadata->>'trustState','')<>'direct_ready'
          OR COALESCE(c.source_metadata->>'expectedSigner','')=''
          OR c.qualification_state='intelligence_only'
          OR COALESCE(c.qualification_evidence->>'vendorReleaseId','')<>r.id::text
          OR COALESCE(c.qualification_evidence->>'artifactVerificationVersion','')<>c.target_version
          OR lower(COALESCE(c.qualification_evidence->>'authenticodeVerified','false'))
             <> lower(COALESCE(r.trust_evidence->>'signatureVerified','false'))
          OR lower(COALESCE(c.qualification_evidence->>'sha256Verified','false'))
             <> CASE
                  WHEN COALESCE(r.trust_evidence->>'sha256','') ~* '^[a-f0-9]{64}$'
                   AND upper(r.trust_evidence->>'sha256')=upper(r.installer_sha256)
                    THEN 'true'
                  ELSE 'false'
                END
          OR (
            c.qualification_state IN ('qualified','qualified_limited')
            AND (
              NOT (
                COALESCE((r.trust_evidence->>'signatureVerified')::boolean,false)
                AND COALESCE(r.trust_evidence->>'sha256','') ~* '^[a-f0-9]{64}$'
                AND upper(r.trust_evidence->>'sha256')=upper(r.installer_sha256)
              )
              OR (
                (
                  COALESCE(c.qualification_evidence->>'cleanInstallVersion','')<>''
                  AND c.qualification_evidence->>'cleanInstallVersion'<>c.target_version
                )
                OR (
                  COALESCE(c.qualification_version,'')<>''
                  AND c.qualification_version<>c.target_version
                )
              )
            )
          ))
     RETURNING c.id,c.canonical_name,c.target_version`)
  await pool.query(
    `UPDATE rmm_software_vendor_bindings b
        SET metadata=b.metadata || jsonb_build_object(
              'expectedSigner',COALESCE(
                NULLIF(b.metadata->>'expectedSigner',''),
                NULLIF(r.source_payload->>'expectedSigner',''),
                NULLIF(r.source_payload->>'signerBaseline',''),
                NULLIF(r.trust_evidence->>'signer',''),
                ''
              ),
              'signerBaseline',COALESCE(
                NULLIF(b.metadata->>'signerBaseline',''),
                NULLIF(r.source_payload->>'signerBaseline',''),
                NULLIF(r.trust_evidence->>'signer',''),
                ''
              )
            )
       FROM rmm_software_catalogue c
       JOIN rmm_software_vendor_releases r
         ON r.provider_package_id=c.external_key
        AND r.source_key=c.source_metadata->>'latestSource'
        AND r.version=c.target_version
      WHERE b.source_key=r.source_key
        AND b.provider_package_id=r.provider_package_id
        AND b.channel=r.channel
        AND b.platform=r.platform
        AND b.architecture=r.architecture
        AND b.enabled=true
        AND c.tenant_id IS NULL
        AND c.status='active'
        AND r.trust_state='direct_ready'
        AND COALESCE(r.trust_evidence->>'signatureVerified','false')='true'
        AND COALESCE(r.trust_evidence->>'signer','')<>''
        AND COALESCE(b.metadata->>'expectedSigner','')=''`,
  )
  return result.rows
}

export async function runVendorArtifactQualification({ inspectLimit = 2 } = {}) {
  const reconciled = await reconcileVendorArtifactInspections()
  const recovered = await reconcileDirectReadyCatalogue()
  const queued = await queueVendorArtifactInspections(inspectLimit)
  return { reconciled, recovered, queued }
}
