import { withTransaction } from './db.js'
import {
  normalizedSha256,
  repositoryName,
} from './rmmTenantVendorSources.js'
import { normalizeVendorHtmlAutomationPolicy, normalizeVendorHtmlRecipe } from './vendorHtmlRecipe.js'

function clean(value = '') { return String(value ?? '').trim() }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }
function curatedHttpsUrl(value = '') {
  let url
  try { url = new URL(clean(value)) } catch { throw new Error('A valid HTTPS URL is required.') }
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')) {
    throw new Error('Curated source URLs must use HTTPS without embedded credentials or custom ports.')
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')
    || /^\d+(?:\.\d+){3}$/.test(host) || host.includes(':')) {
    throw new Error('Curated source URLs must use a public DNS hostname, not a local or literal IP address.')
  }
  return url
}

function sourceKey(value = '') {
  const key = clean(value).toLowerCase().replace(/[^a-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '')
  if (!key || key.length > 120) throw new Error('Each catalogue entry requires a sourceKey of 120 characters or fewer.')
  return key
}

function jsonPath(value = '') {
  const path = clean(value)
  if (!path) return ''
  if (path.length > 240 || path.split('.').some((part) => !part || !/^(?:[A-Za-z0-9_-]+|\d+)$/.test(part)
    || ['__proto__', 'prototype', 'constructor'].includes(part))) {
    throw new Error('JSON paths may contain only object keys, numeric indexes, underscores and hyphens.')
  }
  return path
}

function verificationConfig(value = {}, providerPackageId = '') {
  const input = object(value)
  const method = ['winget', 'uninstall_registry', 'file_version'].includes(clean(input.method))
    ? clean(input.method)
    : providerPackageId ? 'winget' : 'uninstall_registry'
  const productCode = clean(input.productCode).slice(0, 80)
  if (productCode && !/^\{[0-9A-Fa-f-]{36}\}$/.test(productCode)) throw new Error('Invalid MSI ProductCode.')
  const filePath = clean(input.filePath).slice(0, 520)
  if (filePath && (!/^(?:[A-Za-z]:\\|%ProgramFiles%\\|%ProgramFiles\(x86\)%\\|%ProgramData%\\)/i.test(filePath)
    || filePath.includes('..') || /["\r\n]/.test(filePath) || !/\.(?:exe|dll)$/i.test(filePath))) {
    throw new Error('Invalid file-version verification path.')
  }
  return {
    method,
    packageId: providerPackageId,
    productCode,
    displayNameContains: clean(input.displayNameContains).slice(0, 200),
    publisherContains: clean(input.publisherContains).slice(0, 200),
    filePath,
  }
}

async function normalizeEntry(raw = {}) {
  const key = sourceKey(raw.sourceKey || raw.key || raw.canonicalName || raw.displayName)
  const displayName = clean(raw.displayName || raw.canonicalName).slice(0, 160)
  const canonicalName = clean(raw.canonicalName || raw.displayName).slice(0, 200)
  if (!displayName || !canonicalName) throw new Error(key + ': displayName and canonicalName are required.')
  const publisher = clean(raw.publisher).slice(0, 200)
  const sourceType = clean(raw.sourceType)
  if (!['github_releases', 'gitlab_releases', 'vendor_json', 'vendor_text', 'vendor_html', 'hashicorp_releases', 'python_releases', 'adoptium', 'static_release', 'package_registry', 'winget_manifest'].includes(sourceType)) {
    throw new Error(key + ': unsupported curated sourceType.')
  }
  const deploymentMode = ['vendor_direct', 'winget_preferred', 'intelligence_only'].includes(clean(raw.deploymentMode))
    ? clean(raw.deploymentMode)
    : clean(raw.wingetPackageId || raw.providerPackageId) ? 'winget_preferred' : 'intelligence_only'
  const requestedQualificationState = clean(raw.qualificationState)
  const qualificationStatePinned = ['intelligence_only', 'deployment_candidate', 'qualified', 'qualified_limited', 'blocked'].includes(requestedQualificationState)
  const qualificationState = qualificationStatePinned
    ? requestedQualificationState
    : deploymentMode === 'intelligence_only' ? 'intelligence_only' : 'deployment_candidate'
  const qualificationNotes = clean(raw.qualificationNotes).slice(0, 1000)
  const wingetPackageId = clean(raw.wingetPackageId || raw.providerPackageId).slice(0, 240)
  if (deploymentMode === 'winget_preferred' && !wingetPackageId) {
    throw new Error(key + ': winget_preferred requires a real wingetPackageId.')
  }
  const catalogueKey = 'vendor:' + key
  const repository = sourceType === 'github_releases' ? repositoryName(raw.repository || raw.sourceUrl) : ''
  if (sourceType === 'github_releases' && !repository) throw new Error(key + ': a valid GitHub repository is required.')
  let sourceUrl = clean(raw.sourceUrl)
  if (sourceType === 'github_releases' && !sourceUrl) sourceUrl = 'https://github.com/' + repository
  if (!sourceUrl && sourceType === 'static_release') sourceUrl = clean(raw.staticReleaseUrl || raw.releaseUrl)
  if (!sourceUrl) throw new Error(key + ': sourceUrl is required.')
  sourceUrl = curatedHttpsUrl(sourceUrl).toString()

  const parserInput = object(raw.parserConfig)
  const parserConfig = {
    versionPath: jsonPath(raw.versionPath ?? parserInput.versionPath),
    releaseDatePath: jsonPath(raw.releaseDatePath ?? parserInput.releaseDatePath),
    releaseUrlPath: jsonPath(raw.releaseUrlPath ?? parserInput.releaseUrlPath),
    installerUrlPath: jsonPath(raw.installerUrlPath ?? parserInput.installerUrlPath),
    sha256Path: jsonPath(raw.sha256Path ?? parserInput.sha256Path),
    productCodePath: jsonPath(raw.productCodePath ?? parserInput.productCodePath),
  }
  if (sourceType === 'vendor_json' && !parserConfig.versionPath) throw new Error(key + ': vendor_json requires versionPath.')
  const htmlRecipe = sourceType === 'vendor_html'
    ? normalizeVendorHtmlRecipe(raw.htmlRecipe || raw.htmlConfig || {})
    : {}
  const automationPolicy = sourceType === 'vendor_html'
    ? normalizeVendorHtmlAutomationPolicy(raw.automationPolicy || {})
    : {}

  const staticVersion = clean(raw.staticVersion || raw.version).slice(0, 120)
  const staticInstallerUrl = clean(raw.staticInstallerUrl || raw.installerUrl)
  const staticSha256 = normalizedSha256(raw.staticSha256 || raw.sha256)
  const staticReleaseUrl = clean(raw.staticReleaseUrl || raw.releaseUrl || sourceUrl)
  if (sourceType === 'static_release') {
    if (!staticVersion || !staticInstallerUrl || !staticSha256) {
      throw new Error(key + ': static_release requires version, installerUrl and SHA-256.')
    }
    curatedHttpsUrl(staticInstallerUrl)
    if (staticReleaseUrl) curatedHttpsUrl(staticReleaseUrl)
  }

  const installerType = clean(raw.installerType).toLowerCase()
  if (installerType && !['msi', 'exe'].includes(installerType)) throw new Error(key + ': installerType must be msi or exe.')
  const installArguments = clean(raw.installArguments).slice(0, 1000)
  if (deploymentMode === 'vendor_direct' && installerType === 'exe' && !installArguments) {
    throw new Error(key + ': vendor-direct EXE entries require explicit silent installArguments.')
  }
  const expectedSigner = clean(raw.expectedSigner).slice(0, 300)
  if (deploymentMode === 'vendor_direct' && !expectedSigner) throw new Error(key + ': vendor-direct entries require expectedSigner.')

  const verification = verificationConfig(raw.verificationConfig || raw.verification, wingetPackageId)
  const namePattern = clean(raw.namePattern || canonicalName).slice(0, 200)
  const publisherPattern = clean(raw.publisherPattern || publisher).slice(0, 200)
  const priority = Math.max(1, Math.min(1000, Number(raw.priority || 700) || 700))
  const requestedPollMinutes = Math.max(5, Math.min(10080, Number(raw.pollMinutes || 60) || 60))
  const pollMinutes = sourceType === 'vendor_html'
    ? Math.max(requestedPollMinutes, Number(automationPolicy.minimumPollMinutes || 60))
    : requestedPollMinutes
  const channel = clean(raw.channel || 'stable').slice(0, 80)
  const requestedPlatform = clean(raw.platform || 'windows').toLowerCase().slice(0, 40)
  const platform = requestedPlatform === 'any' ? 'cross_platform' : requestedPlatform
  if (!['windows', 'macos', 'linux', 'cross_platform'].includes(platform)) {
    throw new Error(key + ': platform must be windows, macos, linux or cross_platform.')
  }
  if (platform !== 'windows' && deploymentMode !== 'intelligence_only') {
    throw new Error(key + ': non-Windows catalogue entries must remain intelligence_only until an OS-specific deployment executor is implemented.')
  }
  const architecture = clean(raw.architecture || 'x64').slice(0, 40)
  const nvdVendor = clean(raw.nvdVendor).slice(0, 160)
  const nvdProduct = clean(raw.nvdProduct).slice(0, 160)
  if (Boolean(nvdVendor) !== Boolean(nvdProduct)) {
    throw new Error(key + ': nvdVendor and nvdProduct must be supplied together.')
  }

  const rawVersionNormalization = object(raw.versionNormalization)
  const normalizationStrategy = clean(rawVersionNormalization.strategy)
  if (normalizationStrategy && normalizationStrategy !== 'strip_leading_numeric_segments') {
    throw new Error(key + ': unsupported versionNormalization strategy.')
  }
  const versionNormalization = normalizationStrategy
    ? {
        strategy: normalizationStrategy,
        installedSegmentsToStrip: Math.max(0, Math.min(4, Number(rawVersionNormalization.installedSegmentsToStrip || 0) || 0)),
        providerSegmentsToStrip: Math.max(0, Math.min(4, Number(rawVersionNormalization.providerSegmentsToStrip || 0) || 0)),
        expectedRemainingSegments: Math.max(0, Math.min(8, Number(rawVersionNormalization.expectedRemainingSegments || 0) || 0)),
      }
    : {}
  if (normalizationStrategy && !versionNormalization.installedSegmentsToStrip && !versionNormalization.providerSegmentsToStrip) {
    throw new Error(key + ': versionNormalization requires at least one strip count.')
  }

  const adapter = clean(raw.adapter).slice(0, 80)
  if (sourceType === 'vendor_text' && !['signal_yaml','vlc_directory','jenkins_jsonp','element_windows_index','grafana_windows_download','nextcloud_windows_index','qgis_windows_download','gimp_windows_index','wazuh_windows_packages'].includes(adapter)) {
    throw new Error(key + ': vendor_text requires a supported adapter.')
  }
  const registry = clean(raw.registry).toLowerCase().slice(0, 40)
  const registryPackage = clean(raw.registryPackage || raw.packageName).slice(0, 300)
  const registryGroup = clean(raw.registryGroup).slice(0, 240)
  const registryArtifact = clean(raw.registryArtifact).slice(0, 240)
  const osvEcosystem = clean(raw.osvEcosystem).slice(0, 80)
  const osvPackage = clean(raw.osvPackage || registryPackage).slice(0, 300)
  if (sourceType === 'package_registry') {
    const supportedRegistries = ['npm','pypi','crates','rubygems','nuget','packagist','snapcraft','flathub','apple','go','maven','homebrew','chocolatey']
    if (!supportedRegistries.includes(registry)) throw new Error(key + ': unsupported package registry.')
    if (!registryPackage && registry !== 'maven') throw new Error(key + ': package_registry requires registryPackage.')
    if (registry === 'maven' && (!registryGroup || !registryArtifact)) throw new Error(key + ': Maven sources require registryGroup and registryArtifact.')
  }
  const sourceMetadata = {
    curated: true,
    repository,
    adapter,
    parserConfig,
    htmlRecipe,
    automationPolicy,
    releaseTagPattern: clean(raw.releaseTagPattern).slice(0, 240),
    assetPattern: clean(raw.assetPattern).slice(0, 240),
    checksumAssetPattern: clean(raw.checksumAssetPattern).slice(0, 240),
    staticVersion,
    staticInstallerUrl,
    staticSha256,
    staticReleaseUrl,
    nvdVendor,
    nvdProduct,
    registry,
    registryPackage,
    registryGroup,
    registryArtifact,
    osvEcosystem,
    osvPackage,
    versionNormalization,
  }
  const bindingMetadata = {
    curated: true,
    namePattern,
    publisherPattern,
    deploymentMode,
    expectedSigner,
    installerType,
    installArguments,
    verificationConfig: {
      ...verification,
      displayNameContains: verification.displayNameContains || namePattern,
      publisherContains: verification.publisherContains || publisherPattern,
    },
    wingetPackageId,
    repository,
    adapter,
    parserConfig,
    htmlRecipe,
    automationPolicy,
    releaseTagPattern: sourceMetadata.releaseTagPattern,
    assetPattern: sourceMetadata.assetPattern,
    checksumAssetPattern: sourceMetadata.checksumAssetPattern,
    staticVersion,
    staticInstallerUrl,
    staticSha256,
    staticReleaseUrl,
    nvdVendor,
    nvdProduct,
    registry,
    registryPackage,
    registryGroup,
    registryArtifact,
    osvEcosystem,
    osvPackage,
    versionNormalization,
  }

  return {
    sourceKey: key,
    displayName,
    sourceType,
    sourceUrl,
    enabled: raw.enabled !== false && (
      sourceType !== 'vendor_html'
      || (automationPolicy.termsDecision === 'allowed' && automationPolicy.automatedRetrievalAllowed)
    ),
    priority,
    pollMinutes,
    catalogueKey,
    wingetPackageId,
    canonicalName,
    publisher,
    channel,
    platform,
    architecture,
    namePattern,
    publisherPattern,
    deploymentMode,
    qualificationState,
    qualificationStatePinned,
    qualificationNotes,
    installerType,
    expectedSigner,
    nvdVendor,
    nvdProduct,
    osvEcosystem,
    osvPackage,
    registry,
    registryPackage,
    versionNormalization,
    verification: bindingMetadata.verificationConfig,
    execution: { installArguments },
    sourceMetadata,
    bindingMetadata,
  }
}

export async function validateCuratedSoftwareCatalogue(entries = []) {
  if (!Array.isArray(entries)) throw new Error('Catalogue import must be an array.')
  if (!entries.length) return { entries: [], count: 0 }
  if (entries.length > 1000) throw new Error('A single catalogue import is limited to 1000 entries.')
  const normalized = []
  const seen = new Set()
  for (let index = 0; index < entries.length; index += 1) {
    try {
      const item = await normalizeEntry(entries[index])
      if (seen.has(item.sourceKey)) throw new Error('Duplicate sourceKey in import.')
      seen.add(item.sourceKey)
      normalized.push(item)
    } catch (error) {
      throw new Error('Entry ' + (index + 1) + ': ' + clean(error?.message || error))
    }
  }
  return { entries: normalized, count: normalized.length }
}

export async function importCuratedSoftwareCatalogue(entries = [], { dryRun = false } = {}) {
  const validated = await validateCuratedSoftwareCatalogue(entries)
  if (dryRun) {
    return {
      dryRun: true,
      count: validated.count,
      sources: validated.entries.map((item) => ({
        sourceKey: item.sourceKey,
        canonicalName: item.canonicalName,
        sourceType: item.sourceType,
        deploymentMode: item.deploymentMode,
        packageKey: item.catalogueKey,
        hasWingetFallback: Boolean(item.wingetPackageId),
      })),
    }
  }

  return withTransaction(async (client) => {
    let created = 0
    let updated = 0
    for (const item of validated.entries) {
      const existed = await client.query('SELECT 1 FROM rmm_software_vendor_sources WHERE source_key=$1', [item.sourceKey])
      await client.query(
        `INSERT INTO rmm_software_vendor_sources
          (source_key,display_name,source_type,source_url,enabled,priority,poll_minutes,metadata,updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,now())
         ON CONFLICT (source_key) DO UPDATE SET
           display_name=EXCLUDED.display_name,source_type=EXCLUDED.source_type,source_url=EXCLUDED.source_url,
           enabled=EXCLUDED.enabled,priority=EXCLUDED.priority,poll_minutes=EXCLUDED.poll_minutes,
           metadata=EXCLUDED.metadata,updated_at=now()`,
        [
          item.sourceKey,item.displayName,item.sourceType,item.sourceUrl,item.enabled,item.priority,item.pollMinutes,
          JSON.stringify(item.sourceMetadata),
        ],
      )
      await client.query(
        `INSERT INTO rmm_software_vendor_bindings
          (source_key,provider_package_id,canonical_name,publisher,channel,platform,architecture,enabled,metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,true,$8::jsonb)
         ON CONFLICT (source_key,provider_package_id,channel,platform,architecture) DO UPDATE SET
           canonical_name=EXCLUDED.canonical_name,publisher=EXCLUDED.publisher,enabled=true,
           metadata=rmm_software_vendor_bindings.metadata || EXCLUDED.metadata`,
        [
          item.sourceKey,item.catalogueKey,item.canonicalName,item.publisher,item.channel,item.platform,item.architecture,
          JSON.stringify(item.bindingMetadata),
        ],
      )
      await client.query(
        `INSERT INTO rmm_software_catalogue
          (tenant_id,canonical_name,publisher,name_pattern,publisher_pattern,platform,provider,provider_package_id,
           target_version,release_channel,installer_type,verification,execution,status,catalogue_source,external_key,
           source_revision,source_metadata,qualification_state,qualification_notes)
         VALUES (NULL,$1,$2,$3,$4,$5,$6,$7,'',$8,$9,$10::jsonb,$11::jsonb,'active','vendor',$7,'',$12::jsonb,$13,$14)
         ON CONFLICT (catalogue_source,external_key) WHERE tenant_id IS NULL AND external_key<>'' AND status<>'archived'
         DO UPDATE SET canonical_name=EXCLUDED.canonical_name,publisher=EXCLUDED.publisher,
           name_pattern=EXCLUDED.name_pattern,publisher_pattern=EXCLUDED.publisher_pattern,platform=EXCLUDED.platform,
           provider=EXCLUDED.provider,release_channel=EXCLUDED.release_channel,installer_type=EXCLUDED.installer_type,
           verification=EXCLUDED.verification,execution=EXCLUDED.execution,
           target_version=CASE WHEN EXCLUDED.source_metadata->>'sourceEnabled'='false' THEN '' ELSE rmm_software_catalogue.target_version END,
           qualification_state=CASE
             WHEN EXCLUDED.source_metadata->>'qualificationStatePinned'='true' THEN EXCLUDED.qualification_state
             WHEN rmm_software_catalogue.qualification_state IN ('qualified','qualified_limited','blocked') THEN rmm_software_catalogue.qualification_state
             ELSE EXCLUDED.qualification_state
           END,
           qualification_notes=CASE
             WHEN EXCLUDED.source_metadata->>'qualificationStatePinned'='true' THEN EXCLUDED.qualification_notes
             ELSE rmm_software_catalogue.qualification_notes
           END,
           source_metadata=rmm_software_catalogue.source_metadata || EXCLUDED.source_metadata,status='active',updated_at=now()`,
        [
          item.canonicalName,item.publisher,item.namePattern,item.publisherPattern,item.platform,
          'managed',
          item.catalogueKey,item.channel,item.installerType,JSON.stringify(item.verification),JSON.stringify(item.execution),
          JSON.stringify({
            curated: true,
            preseeded: true,
            latestSource: item.sourceKey,
            sourceType: item.sourceType,
            sourceEnabled: item.enabled,
            deploymentMode: item.deploymentMode,
            expectedSigner: item.expectedSigner,
            trustState: 'pending_source_sync',
            hasWingetFallback: Boolean(item.wingetPackageId),
            wingetPackageId: item.wingetPackageId,
            nvdVendor: item.nvdVendor,
            nvdProduct: item.nvdProduct,
            osvEcosystem: item.osvEcosystem,
            osvPackage: item.osvPackage,
            registry: item.registry,
            registryPackage: item.registryPackage,
            versionNormalization: item.versionNormalization,
            qualificationStatePinned: item.qualificationStatePinned,
          }),
          item.qualificationState,
          item.qualificationNotes,
        ],
      )
      const catalogueIdentity = await client.query(
        `UPDATE rmm_software_catalogue
            SET cpe_vendor=$2,cpe_product=$3,osv_ecosystem=$4,osv_package_name=$5,updated_at=now()
          WHERE tenant_id IS NULL AND catalogue_source='vendor' AND external_key=$1 AND status='active'
          RETURNING id`,
        [item.catalogueKey,item.nvdVendor,item.nvdProduct,item.osvEcosystem,item.osvPackage],
      )
      const catalogueId = catalogueIdentity.rows[0]?.id
      if (catalogueId) {
        await client.query(
          `UPDATE rmm_software_vulnerability_identities
              SET enabled=false,updated_at=now()
            WHERE catalogue_id=$1 AND source IN ('nvd','osv')
              AND metadata->>'origin'='curated_catalogue_import'`,
          [catalogueId],
        )
        if (item.nvdVendor && item.nvdProduct) {
          await client.query(
            `INSERT INTO rmm_software_vulnerability_identities
              (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
             VALUES ($1,'nvd',$2,$3,'','','','curated',true,$4::jsonb)
             ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
             DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now()`,
            [catalogueId,item.nvdVendor,item.nvdProduct,JSON.stringify({ origin: 'curated_catalogue_import', sourceKey: item.sourceKey })],
          )
        }
        if (item.osvEcosystem && item.osvPackage) {
          await client.query(
            `INSERT INTO rmm_software_vulnerability_identities
              (catalogue_id,source,vendor,product,cpe,ecosystem,package_name,confidence,enabled,metadata)
             VALUES ($1,'osv','','','',$2,$3,'curated',true,$4::jsonb)
             ON CONFLICT (catalogue_id,source,vendor,product,cpe,ecosystem,package_name)
             DO UPDATE SET confidence='curated',enabled=true,metadata=EXCLUDED.metadata,updated_at=now()`,
            [catalogueId,item.osvEcosystem,item.osvPackage,JSON.stringify({ origin: 'curated_catalogue_import', sourceKey: item.sourceKey, registry: item.registry })],
          )
        }
      }
      if (existed.rowCount) updated += 1
      else created += 1
    }
    return { dryRun: false, count: validated.count, created, updated }
  })
}
