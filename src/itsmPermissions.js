import { hasPermission } from './access.js'

const prefixes = {
  Incident: 'itsm.incidents',
  Problem: 'itsm.problems',
  Change: 'itsm.changes',
  'Service Request': 'itsm.requests',
}

export function recordPermission(recordType, action) {
  const prefix = prefixes[recordType]
  if (!prefix) return ''
  if (recordType === 'Change' && action === 'resolve') return 'itsm.changes.implement'
  return `${prefix}.${action}`
}

export function hasRecordPermission(session, recordType, action) {
  if (!session?.access) return false
  if (action === 'view' && hasPermission(session.access, 'itsm.records.view_all')) return true
  if (action === 'create' && hasPermission(session.access, 'itsm.records.create_all')) return true
  const permission = recordPermission(recordType, action)
  return Boolean(permission && hasPermission(session.access, permission))
}