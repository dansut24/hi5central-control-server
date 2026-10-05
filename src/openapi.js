const HTTP_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'])

const PUBLIC_PATHS = [
  /^\/api\/v1\/auth\/(login|signup|verify-email|resend-verification)/,
  /^\/api\/v1\/portal\/auth\//,
  /^\/api\/licensing\/v1\/(public-key(?:\.pem)?|activate|refresh)$/,
  /^\/api\/v1\/system\/(edition|license)$/,
  /^\/api\/v1\/openapi\.json$/,
]

function openApiPath(path) {
  if (!path || path.includes('*')) return null
  return path.replace(/:([A-Za-z0-9_]+)/g, '{$1}')
}

function pathParameters(path) {
  return [...path.matchAll(/:([A-Za-z0-9_]+)/g)].map((match) => ({
    name: match[1],
    in: 'path',
    required: true,
    schema: { type: 'string' },
  }))
}

function routeTag(path) {
  if (path.startsWith('/api/platform/v1/')) return 'Platform Admin'
  if (path.startsWith('/api/licensing/v1/')) return 'Licensing Authority'
  if (path.startsWith('/api/v1/rmm/')) return 'RMM'
  if (path.startsWith('/api/v1/integrations/')) return 'Integrations'
  if (path.startsWith('/api/v1/auth/')) return 'Authentication'
  if (path.startsWith('/api/v1/portal/')) return 'Self Service'
  if (path.startsWith('/api/v1/organisation/')) return 'Organisation'
  if (path.startsWith('/api/v1/settings/')) return 'Settings'
  if (path.startsWith('/api/v1/projects/')) return 'Projects'
  if (path.startsWith('/api/v1/system/')) return 'System'
  return 'Hi5Central API'
}

function operationId(method, path) {
  const suffix = path
    .replace(/^\/api\//, '')
    .replace(/:([A-Za-z0-9_]+)/g, 'by_$1')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_|_$/g, '')
  return `${method.toLowerCase()}_${suffix || 'root'}`
}

function publicRoute(path) {
  return PUBLIC_PATHS.some((pattern) => pattern.test(path))
}

function securityFor(path) {
  if (publicRoute(path)) return []
  if (path.startsWith('/api/platform/v1/')) return [{ adminSessionCookie: [] }]
  return undefined
}

function routeOperation(method, path) {
  const security = securityFor(path)
  const operation = {
    operationId: operationId(method, path),
    tags: [routeTag(path)],
    summary: `${method} ${path}`,
    responses: {
      default: {
        description: 'Hi5Central API response. Detailed response schemas are added as endpoint contracts are formalised.',
        content: {
          'application/json': {
            schema: {
              oneOf: [
                { type: 'object', additionalProperties: true },
                { type: 'array', items: {} },
              ],
            },
          },
        },
      },
    },
    'x-hi5central-route-source': 'hono-runtime',
  }
  const parameters = pathParameters(path)
  if (parameters.length) operation.parameters = parameters
  if (security !== undefined) operation.security = security
  return operation
}

export function buildOpenApiDocument(app, deployment = {}) {
  const paths = {}
  const seen = new Set()

  for (const route of app.routes || []) {
    const method = String(route.method || '').toUpperCase()
    const honoPath = String(route.path || '')
    if (!HTTP_METHODS.has(method) || !honoPath.startsWith('/api/')) continue
    if (honoPath.startsWith('/api/platform-operator/')) continue

    const path = openApiPath(honoPath)
    if (!path) continue

    const key = `${method} ${path}`
    if (seen.has(key)) continue
    seen.add(key)

    paths[path] ||= {}
    paths[path][method.toLowerCase()] = routeOperation(method, honoPath)
  }

  const apiUrl = String(deployment.apiUrl || '').trim()
  const tags = [...new Set(Object.values(paths)
    .flatMap((item) => Object.values(item))
    .flatMap((operation) => operation.tags || []))]
    .sort()
    .map((name) => ({ name }))

  return {
    openapi: '3.1.0',
    info: {
      title: 'Hi5Central API',
      version: 'v1',
      description: 'Canonical route inventory for the Hi5Central Hono Control Server. Methods and paths are generated from the registered runtime routes. Request and response schemas are progressively enriched as endpoint contracts are formalised.',
    },
    ...(apiUrl ? { servers: [{ url: apiUrl }] } : {}),
    tags,
    paths,
    components: {
      securitySchemes: {
        sessionCookie: {
          type: 'apiKey',
          in: 'cookie',
          name: 'hi5central_session',
          description: 'Browser workspace session.',
        },
        portalSessionCookie: {
          type: 'apiKey',
          in: 'cookie',
          name: 'hi5central_portal_session',
          description: 'Requester/Self Service portal session.',
        },
        adminSessionCookie: {
          type: 'apiKey',
          in: 'cookie',
          name: 'hi5central_admin_session',
          description: 'Hi5Central Platform Admin session.',
        },
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'hi5_pat_…',
          description: 'Tenant-scoped Hi5Central API token. Effective scopes can never exceed the issuing user permissions.',
        },
      },
      schemas: {
        Error: {
          type: 'object',
          required: ['error'],
          properties: {
            error: { type: 'string' },
            code: { type: 'string' },
          },
          additionalProperties: true,
        },
      },
    },
    'x-hi5central-generated': true,
    'x-hi5central-route-count': seen.size,
  }
}
