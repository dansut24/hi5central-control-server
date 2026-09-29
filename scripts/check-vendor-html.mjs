import assert from 'node:assert/strict'
import {
  htmlHostAllowed,
  normalizeVendorHtmlAutomationPolicy,
  normalizeVendorHtmlRecipe,
  parseVendorHtmlReleases,
  robotsPathAllowed,
} from '../src/vendorHtmlRecipe.js'

const recipe = normalizeVendorHtmlRecipe({
  installerSelector: "a[href*='Example-'][href$='-x64.msi']",
  installerVersionRegex: "Example-([0-9]+(?:\\.[0-9]+)+)-x64\\.msi",
  allowedHosts: ['downloads.example.com'],
  previousStableCount: 1,
})

const html = `
<html><body>
  <a href="https://downloads.example.com/Example-4.2.0-x64.msi">Current</a>
  <a href="https://downloads.example.com/Example-4.1.3-x64.msi">Previous</a>
  <a href="https://downloads.example.com/Example-4.3.0-beta-x64.msi">Beta</a>
</body></html>`

const releases = parseVendorHtmlReleases(html, 'https://downloads.example.com/releases/', recipe)
assert.equal(releases.length, 2)
assert.equal(releases.at(-1)?.version, '4.2.0')
assert.equal(releases.at(-2)?.version, '4.1.3')
assert.equal(htmlHostAllowed(releases.at(-1)?.installerUrl, recipe.allowedHosts), true)
assert.equal(htmlHostAllowed('https://evil.example.net/Example-4.2.0-x64.msi', recipe.allowedHosts), false)

assert.throws(
  () => normalizeVendorHtmlRecipe({ installerSelector: 'a[href]', allowedHosts: ['downloads.example.com'] }),
  /version selector\/regex|installerVersionRegex/,
)

const reviewRequired = normalizeVendorHtmlAutomationPolicy({
  termsDecision: 'review_required',
  automatedRetrievalAllowed: false,
})
assert.equal(reviewRequired.termsDecision, 'review_required')
assert.equal(reviewRequired.automatedRetrievalAllowed, false)

assert.throws(
  () => normalizeVendorHtmlAutomationPolicy({
    termsDecision: 'allowed',
    automatedRetrievalAllowed: true,
  }),
  /termsUrl/,
)

const approved = normalizeVendorHtmlAutomationPolicy({
  termsDecision: 'allowed',
  automatedRetrievalAllowed: true,
  termsUrl: 'https://vendor.example.com/terms',
  termsReviewedAt: '2026-09-22T19:00:00Z',
  reviewBasis: 'Manual review permits low-frequency automated release checks.',
  reviewedBy: 'Catalogue administrator',
  minimumPollMinutes: 120,
})
assert.equal(approved.minimumPollMinutes, 120)
assert.equal(approved.robotsUserAgent, 'Hi5Central-Software-Catalogue')

const robots = `
User-agent: *
Disallow: /private/
Allow: /private/releases/
Disallow: /blocked/

User-agent: Hi5Central-Software-Catalogue
Disallow: /downloads/internal/
Allow: /downloads/releases/
`
assert.equal(robotsPathAllowed(robots, '/downloads/releases/windows', approved.robotsUserAgent).allowed, true)
assert.equal(robotsPathAllowed(robots, '/downloads/internal/builds', approved.robotsUserAgent).allowed, false)
assert.equal(robotsPathAllowed(robots, '/public/releases', approved.robotsUserAgent).allowed, true)

console.log('Vendor HTML source + compliance contract passed')
