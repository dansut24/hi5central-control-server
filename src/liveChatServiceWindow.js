const DEFAULT_TIMEZONE = 'Europe/London'

export const DEFAULT_LIVE_CHAT_SCHEDULE = Object.freeze({
  1: [['09:00', '17:00']],
  2: [['09:00', '17:00']],
  3: [['09:00', '17:00']],
  4: [['09:00', '17:00']],
  5: [['09:00', '17:00']],
})

function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {}
}

function validTime(value) {
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(String(value || ''))
}

function minutes(value) {
  const [hour, minute] = String(value).split(':').map(Number)
  return (hour * 60) + minute
}

function validTimezone(value) {
  const candidate = String(value || '').trim()
  if (!candidate || candidate.length > 80) return false
  try {
    new Intl.DateTimeFormat('en-GB', { timeZone: candidate }).format(new Date())
    return true
  } catch {
    return false
  }
}

export function normaliseLiveChatSchedule(value) {
  const input = asObject(value)
  const output = {}

  for (let day = 0; day <= 6; day += 1) {
    const intervals = Array.isArray(input[String(day)])
      ? input[String(day)]
      : Array.isArray(input[day])
        ? input[day]
        : []

    const cleaned = intervals
      .slice(0, 4)
      .map((interval) => {
        if (!Array.isArray(interval) || interval.length < 2) return null
        const start = String(interval[0] || '').trim()
        const end = String(interval[1] || '').trim()
        if (!validTime(start) || !validTime(end) || minutes(start) >= minutes(end)) return null
        return [start, end]
      })
      .filter(Boolean)
      .sort((a, b) => minutes(a[0]) - minutes(b[0]))

    if (cleaned.length) output[String(day)] = cleaned
  }

  return output
}

export async function loadLiveChatServiceSettings(db, tenantId) {
  const result = await db.query(
    `SELECT service_hours_enabled, timezone, schedule, updated_at
     FROM live_chat_service_settings
     WHERE tenant_id=$1
     LIMIT 1`,
    [tenantId],
  )

  const row = result.rows[0]
  return {
    enabled: row?.service_hours_enabled === true,
    timezone: validTimezone(row?.timezone) ? row.timezone : DEFAULT_TIMEZONE,
    schedule: normaliseLiveChatSchedule(row?.schedule || DEFAULT_LIVE_CHAT_SCHEDULE),
    updatedAt: row?.updated_at || null,
  }
}

export async function saveLiveChatServiceSettings(db, {
  tenantId,
  userId,
  enabled,
  timezone,
  schedule,
}) {
  const resolvedTimezone = validTimezone(timezone) ? String(timezone).trim() : null
  if (!resolvedTimezone) {
    throw Object.assign(new Error('Choose a valid IANA timezone such as Europe/London.'), { status: 400 })
  }

  const resolvedSchedule = normaliseLiveChatSchedule(schedule)
  if (enabled && !Object.keys(resolvedSchedule).length) {
    throw Object.assign(new Error('Add at least one service-hours interval before enabling service hours.'), { status: 400 })
  }

  await db.query(
    `INSERT INTO live_chat_service_settings
       (tenant_id,service_hours_enabled,timezone,schedule,updated_by_user_id)
     VALUES ($1,$2,$3,$4::jsonb,$5)
     ON CONFLICT (tenant_id) DO UPDATE SET
       service_hours_enabled=EXCLUDED.service_hours_enabled,
       timezone=EXCLUDED.timezone,
       schedule=EXCLUDED.schedule,
       updated_by_user_id=EXCLUDED.updated_by_user_id,
       updated_at=now()`,
    [tenantId, Boolean(enabled), resolvedTimezone, JSON.stringify(resolvedSchedule), userId || null],
  )

  return loadLiveChatServiceSettings(db, tenantId)
}

function localClock(date, timezone) {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: timezone,
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date)

  const values = Object.fromEntries(parts.map((part) => [part.type, part.value]))
  const dayMap = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 }
  return {
    day: dayMap[values.weekday] ?? 0,
    time: `${values.hour || '00'}:${values.minute || '00'}`,
    minuteOfDay: (Number(values.hour || 0) * 60) + Number(values.minute || 0),
  }
}

export async function liveChatServiceWindow(db, tenantId, at = new Date()) {
  const settings = await loadLiveChatServiceSettings(db, tenantId)

  if (!settings.enabled) {
    return {
      ...settings,
      open: true,
      reason: 'unrestricted',
      localTime: null,
      today: [],
    }
  }

  const clock = localClock(at, settings.timezone)
  const today = settings.schedule[String(clock.day)] || []
  const open = today.some(([start, end]) => {
    const startMinutes = minutes(start)
    const endMinutes = minutes(end)
    return clock.minuteOfDay >= startMinutes && clock.minuteOfDay < endMinutes
  })

  return {
    ...settings,
    open,
    reason: open ? 'within_service_hours' : 'outside_service_hours',
    localTime: clock.time,
    today,
  }
}
