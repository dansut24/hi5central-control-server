import { load } from 'cheerio'

function clean(value = '') { return String(value ?? '').trim() }
function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {} }

function safeRegex(pattern = '', label = 'regex') {
  const value = clean(pattern)
  if (!value) return null
  if (value.length > 500) throw new Error(label + ' must be 500 characters or fewer.')
  try { return new RegExp(value, 'i') } catch { throw new Error(label + ' is not a valid regular expression.') }
}

function normalizedHost(value = '') {
  const host = clean(value).toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/\.$/, '')
  if (!host || host.includes('/') || host.includes('@') || host.includes(':')) throw new Error('HTML source allowedHosts must contain hostnames only.')
  if (!/^(?:\*\.)?[a-z0-9.-]+$/i.test(host)) throw new Error('HTML source allowedHosts contains an invalid hostname.')
  return host
}

export function normalizeVendorHtmlAutomationPolicy(raw = {}) {
  const input = object(raw)
  const termsDecision = ['allowed','prohibited','review_required'].includes(clean(input.termsDecision))
    ? clean(input.termsDecision)
    : 'review_required'
  const reviewedAt = clean(input.termsReviewedAt)
  const reviewedMs = Date.parse(reviewedAt)
  const termsUrl = clean(input.termsUrl).slice(0, 2000)
  if (termsUrl) {
    let parsed
    try { parsed = new URL(termsUrl) } catch { throw new Error('HTML source termsUrl must be a valid HTTPS URL.') }
    if (parsed.protocol !== 'https:') throw new Error('HTML source termsUrl must use HTTPS.')
  }
  const policy = {
    automatedRetrievalAllowed: input.automatedRetrievalAllowed === true,
    termsDecision,
    termsUrl,
    termsReviewedAt: Number.isFinite(reviewedMs) ? new Date(reviewedMs).toISOString() : '',
    reviewBasis: clean(input.reviewBasis).slice(0, 1000),
    reviewedBy: clean(input.reviewedBy).slice(0, 200),
    reviewExpiresDays: Math.max(30, Math.min(365, Number(input.reviewExpiresDays || 180) || 180)),
    minimumPollMinutes: Math.max(30, Math.min(10080, Number(input.minimumPollMinutes || 60) || 60)),
    robotsUserAgent: 'Hi5Central-Software-Catalogue',
  }
  if (policy.termsDecision === 'allowed') {
    if (!policy.automatedRetrievalAllowed) throw new Error('Allowed HTML automation policy must explicitly set automatedRetrievalAllowed=true.')
    if (!policy.termsUrl) throw new Error('Allowed HTML automation policy requires termsUrl.')
    if (!policy.termsReviewedAt) throw new Error('Allowed HTML automation policy requires termsReviewedAt.')
    if (policy.reviewBasis.length < 8) throw new Error('Allowed HTML automation policy requires a reviewBasis.')
  }
  if (policy.termsDecision === 'prohibited') policy.automatedRetrievalAllowed = false
  return policy
}

function normalizedRobotsPath(value = '') {
  try {
    const url = new URL(value, 'https://robots.invalid')
    return url.pathname + url.search
  } catch {
    return clean(value).startsWith('/') ? clean(value) : '/' + clean(value)
  }
}

export function robotsPathAllowed(robotsText = '', target = '/', userAgent = 'Hi5Central-Software-Catalogue') {
  const lines = String(robotsText ?? '').split(/\r?\n/)
  const groups = []
  let current = null
  let seenRule = false

  for (const rawLine of lines) {
    const line = rawLine.replace(/#.*$/, '').trim()
    if (!line) {
      if (current && (current.agents.length || current.rules.length)) groups.push(current)
      current = null
      seenRule = false
      continue
    }
    const match = line.match(/^([^:]+):\s*(.*)$/)
    if (!match) continue
    const field = match[1].trim().toLowerCase()
    const value = match[2].trim()
    if (field === 'user-agent') {
      if (!current || seenRule) {
        if (current && (current.agents.length || current.rules.length)) groups.push(current)
        current = { agents: [], rules: [] }
        seenRule = false
      }
      current.agents.push(value.toLowerCase())
      continue
    }
    if (!current) continue
    if (field === 'allow' || field === 'disallow') {
      seenRule = true
      current.rules.push({ type: field, path: value })
    }
  }
  if (current && (current.agents.length || current.rules.length)) groups.push(current)

  const ua = clean(userAgent).toLowerCase()
  const candidates = groups.map((group) => {
    const matches = group.agents
      .filter((agent) => agent === '*' || (agent && ua.includes(agent)))
      .map((agent) => ({ agent, score: agent === '*' ? 0 : agent.length }))
      .sort((a,b) => b.score-a.score)
    return matches.length ? { group, match: matches[0] } : null
  }).filter(Boolean)

  if (!candidates.length) return { allowed: true, matchedAgent: '', matchedRule: '', reason: 'no_matching_group' }
  const bestScore = Math.max(...candidates.map((item) => item.match.score))
  const applicable = candidates.filter((item) => item.match.score === bestScore)
  const path = normalizedRobotsPath(target)
  const rules = applicable.flatMap(({ group, match }) => group.rules.map((rule) => ({ ...rule, agent: match.agent })))
    .filter((rule) => rule.path && path.startsWith(rule.path))
    .sort((a,b) => b.path.length-a.path.length || (a.type === 'allow' ? -1 : 1))
  if (!rules.length) return { allowed: true, matchedAgent: applicable[0]?.match.agent || '', matchedRule: '', reason: 'no_matching_rule' }
  const winner=rules[0]
  return {
    allowed: winner.type === 'allow',
    matchedAgent: winner.agent,
    matchedRule: winner.type + ':' + winner.path,
    reason: winner.type === 'allow' ? 'allowed_by_rule' : 'disallowed_by_rule',
  }
}

export function normalizeVendorHtmlRecipe(raw = {}) {
  const input = object(raw)
  const allowedHosts = [...new Set((Array.isArray(input.allowedHosts) ? input.allowedHosts : [])
    .map(normalizedHost))]
  const recipe = {
    releaseSelector: clean(input.releaseSelector || '').slice(0, 300),
    installerSelector: clean(input.installerSelector || '').slice(0, 300),
    installerAttribute: clean(input.installerAttribute || 'href').slice(0, 80) || 'href',
    installerHrefRegex: clean(input.installerHrefRegex || '').slice(0, 500),
    installerVersionRegex: clean(input.installerVersionRegex || '').slice(0, 500),
    versionSelector: clean(input.versionSelector || '').slice(0, 300),
    versionAttribute: clean(input.versionAttribute || '').slice(0, 80),
    versionRegex: clean(input.versionRegex || '').slice(0, 500),
    versionGroup: Math.max(1, Math.min(9, Number(input.versionGroup || 1) || 1)),
    releaseDateSelector: clean(input.releaseDateSelector || '').slice(0, 300),
    releaseDateAttribute: clean(input.releaseDateAttribute || '').slice(0, 80),
    releaseDateRegex: clean(input.releaseDateRegex || '').slice(0, 500),
    releaseDateGroup: Math.max(1, Math.min(9, Number(input.releaseDateGroup || 1) || 1)),
    checksumSelector: clean(input.checksumSelector || '').slice(0, 300),
    checksumAttribute: clean(input.checksumAttribute || '').slice(0, 80),
    checksumRegex: clean(input.checksumRegex || '([A-Fa-f0-9]{64})').slice(0, 500),
    checksumGroup: Math.max(1, Math.min(9, Number(input.checksumGroup || 1) || 1)),
    releaseUrlSelector: clean(input.releaseUrlSelector || '').slice(0, 300),
    releaseUrlAttribute: clean(input.releaseUrlAttribute || 'href').slice(0, 80) || 'href',
    allowedHosts,
    previousStableCount: Math.max(0, Math.min(5, Number(input.previousStableCount ?? 1) || 0)),
  }
  if (!recipe.installerSelector) throw new Error('vendor_html requires htmlRecipe.installerSelector.')
  if (!recipe.installerVersionRegex && !recipe.versionSelector && !recipe.versionRegex) {
    throw new Error('vendor_html requires a version selector/regex or installerVersionRegex.')
  }
  for (const [label, value] of [
    ['installerHrefRegex', recipe.installerHrefRegex],
    ['installerVersionRegex', recipe.installerVersionRegex],
    ['versionRegex', recipe.versionRegex],
    ['releaseDateRegex', recipe.releaseDateRegex],
    ['checksumRegex', recipe.checksumRegex],
  ]) safeRegex(value, 'HTML source ' + label)
  return recipe
}

function nodeValue($, node, selector, attribute = '') {
  let target = node
  if (selector) {
    const within = node.find(selector).first()
    target = within.length ? within : $(selector).first()
  }
  if (!target?.length) return ''
  if (attribute) return clean(target.attr(attribute))
  return clean(target.text())
}

function capture(value, pattern, group = 1) {
  const matcher = safeRegex(pattern)
  if (!matcher) return ''
  return clean(String(value ?? '').match(matcher)?.[group])
}

function versionNumbers(value = '') { return clean(value).match(/\d+/g)?.map(Number) || [] }
function compareVersions(a, b) {
  const left = versionNumbers(a), right = versionNumbers(b)
  const size = Math.max(left.length, right.length)
  for (let i = 0; i < size; i += 1) {
    const delta = (left[i] || 0) - (right[i] || 0)
    if (delta) return delta
  }
  return clean(a).localeCompare(clean(b))
}

function stableVersion(value = '') {
  return Boolean(clean(value)) && !/(?:^|[._-])(alpha|beta|preview|nightly|canary|rc|eap|dev)(?:[._-]|$)/i.test(clean(value))
}

function scopeFor($, node, recipe) {
  if (!recipe.releaseSelector) return node.parent()
  const closest = node.closest(recipe.releaseSelector)
  return closest.length ? closest : node.parent()
}

export function parseVendorHtmlReleases(html, sourceUrl, rawRecipe = {}) {
  const recipe = normalizeVendorHtmlRecipe(rawRecipe)
  const $ = load(String(html ?? ''))
  const installerFilter = safeRegex(recipe.installerHrefRegex, 'HTML source installerHrefRegex')
  const rows = []

  $(recipe.installerSelector).each((_, element) => {
    const node = $(element)
    const rawInstaller = clean(node.attr(recipe.installerAttribute))
    if (!rawInstaller) return
    if (installerFilter && !installerFilter.test(rawInstaller)) return

    let installerUrl = ''
    try { installerUrl = new URL(rawInstaller, sourceUrl).toString() } catch { return }
    const scope = scopeFor($, node, recipe)
    const versionValue = recipe.versionSelector
      ? nodeValue($, scope, recipe.versionSelector, recipe.versionAttribute)
      : ''
    const fallbackVersionText = [versionValue, rawInstaller, node.text(), scope.text()].join(' ')
    const version = capture(
      fallbackVersionText,
      recipe.installerVersionRegex || recipe.versionRegex,
      recipe.versionGroup,
    ) || clean(versionValue)
    if (!stableVersion(version)) return

    const releaseDateValue = recipe.releaseDateSelector
      ? nodeValue($, scope, recipe.releaseDateSelector, recipe.releaseDateAttribute)
      : ''
    const releaseDate = recipe.releaseDateRegex
      ? capture(releaseDateValue || scope.text(), recipe.releaseDateRegex, recipe.releaseDateGroup)
      : clean(releaseDateValue)

    const checksumValue = recipe.checksumSelector
      ? nodeValue($, scope, recipe.checksumSelector, recipe.checksumAttribute)
      : ''
    const checksum = capture(checksumValue, recipe.checksumRegex, recipe.checksumGroup).toUpperCase()

    let releaseUrl = sourceUrl
    if (recipe.releaseUrlSelector) {
      const rawRelease = nodeValue($, scope, recipe.releaseUrlSelector, recipe.releaseUrlAttribute)
      try { if (rawRelease) releaseUrl = new URL(rawRelease, sourceUrl).toString() } catch {}
    }

    let assetName = ''
    try { assetName = decodeURIComponent(new URL(installerUrl).pathname.split('/').filter(Boolean).at(-1) || '') } catch {}

    rows.push({
      version,
      installerUrl,
      installerSha256: /^[A-F0-9]{64}$/.test(checksum) ? checksum : '',
      releaseDate,
      releaseUrl,
      assetName,
    })
  })

  const deduped = new Map()
  for (const row of rows) {
    const key = row.version + '|' + row.installerUrl
    if (!deduped.has(key)) deduped.set(key, row)
  }
  return [...deduped.values()].sort((a, b) => compareVersions(a.version, b.version))
}

export function htmlHostAllowed(value, allowedHosts = []) {
  let hostname = ''
  try { hostname = new URL(value).hostname.toLowerCase().replace(/\.$/, '') } catch { return false }
  const rules = (Array.isArray(allowedHosts) ? allowedHosts : []).map(normalizedHost)
  if (!rules.length) return false
  return rules.some((rule) => rule.startsWith('*.')
    ? hostname === rule.slice(2) || hostname.endsWith('.' + rule.slice(2))
    : hostname === rule)
}
