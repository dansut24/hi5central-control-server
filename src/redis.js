import { createClient } from 'redis'

const redisUrl = process.env.REDIS_URL
if (!redisUrl) {
  throw new Error('REDIS_URL is required')
}

export const redis = createClient({ url: redisUrl })

redis.on('error', (error) => {
  console.error('Redis client error', error)
})

export async function ensureRedisConnected() {
  if (!redis.isOpen) {
    await redis.connect()
  }
  return redis
}
