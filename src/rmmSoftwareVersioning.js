function clean(value = '') { return String(value ?? '').trim() }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }

function normalizationConfig(catalogue = {}) {
  const metadata = object(catalogue?.source_metadata || catalogue?.sourceMetadata)
  return object(metadata.versionNormalization || catalogue?.versionNormalization)
}

export function normalizeCatalogueVersion(value, catalogue = {}, role = 'installed') {
  const raw = clean(value)
  if (!raw) return ''

  const config = normalizationConfig(catalogue)
  if (clean(config.strategy) !== 'strip_leading_numeric_segments') return raw

  const strip = role === 'provider'
    ? Number(config.providerSegmentsToStrip || 0)
    : Number(config.installedSegmentsToStrip || 0)
  if (!Number.isInteger(strip) || strip <= 0 || strip > 4) return raw

  const match = /^v?([0-9]+(?:\.[0-9]+)+)(.*)$/i.exec(raw)
  if (!match) return raw
  const parts = match[1].split('.')
  if (parts.length <= strip) return raw

  const normalizedParts = parts.slice(strip)
  const expectedRemainingSegments = Number(config.expectedRemainingSegments || 0)
  if (expectedRemainingSegments > 0 && normalizedParts.length !== expectedRemainingSegments) return raw

  return normalizedParts.join('.') + clean(match[2])
}

export function verificationVersionForRelease(value, verification = {}) {
  const raw = clean(value)
  if (!raw) return ''

  if (clean(object(verification).versionTransform) === 'jetbrains_vendor_build') {
    const release = clean(object(verification).releaseVersion)
    const build = clean(object(verification).vendorBuild)
    const match = /^(\d{2})(\d)\.\d+\.\d+$/.exec(build)
    if (raw === release && /^20\d{2}\.\d+(?:\.\d+)?$/.test(raw) && match) {
      const major = '20' + match[1] + '.' + Number(match[2])
      if (raw === major || raw.startsWith(major + '.')) return build
    }
  }

  if (clean(object(verification).versionTransform) === 'git_windows_registry') {
    const match = /^(\d+\.\d+\.\d+)\.windows\.(\d+)$/.exec(raw)
    if (match) return `${match[1]}.${match[2]}`
  }

  if (clean(object(verification).versionTransform) === 'salt_windows_msi') {
    const match = /^(\d{2})(\d{2})\.(\d+)(?:-(\d+))?$/.exec(raw)
    if (match) return `${match[1]}.${match[2]}.${match[3]}.${match[4] || '0'}`
  }

  return raw
}

export function catalogueVersionNormalization(catalogue = {}) {
  return normalizationConfig(catalogue)
}
