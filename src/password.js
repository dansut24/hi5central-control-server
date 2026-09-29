import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

const scryptAsync = promisify(scrypt)

export async function hashPassword(password) {
  const salt = randomBytes(16)
  const derived = await scryptAsync(String(password || ''), salt, 64, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  })
  return `scrypt$16384$8$1$${salt.toString('base64url')}$${Buffer.from(derived).toString('base64url')}`
}

export function passwordPolicyResult(password, policy = 'strong') {
  const value = String(password || '')
  if (value.length > 256) return { ok: false, message: 'Password must be 256 characters or fewer.' }

  if (policy === 'standard') {
    if (value.length < 10) return { ok: false, message: 'Use a password or passphrase of at least 10 characters.' }
    return { ok: true }
  }

  if (value.length < 12) return { ok: false, message: 'Use a password or passphrase of at least 12 characters.' }
  if (!/[a-z]/.test(value) || !/[A-Z]/.test(value) || !/\d/.test(value)) {
    return { ok: false, message: 'Strong passwords must include upper-case, lower-case and numeric characters.' }
  }
  return { ok: true }
}

export async function verifyPassword(password, encodedHash) {
  const [scheme, nText, rText, pText, saltText, hashText] = String(encodedHash || '').split('$')
  if (scheme !== 'scrypt' || !nText || !rText || !pText || !saltText || !hashText) return false

  const expected = Buffer.from(hashText, 'base64url')
  const salt = Buffer.from(saltText, 'base64url')
  const N = Number(nText)
  const r = Number(rText)
  const p = Number(pText)
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p) || expected.length !== 64) return false

  const derived = await scryptAsync(String(password || ''), salt, expected.length, {
    N,
    r,
    p,
    maxmem: 64 * 1024 * 1024,
  })

  const actual = Buffer.from(derived)
  return actual.length === expected.length && timingSafeEqual(actual, expected)
}
