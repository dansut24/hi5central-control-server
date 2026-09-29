# Hi5Central Control Server

Shared Hi5Central backend/control plane.

This service owns:
- Authentication, sessions, MFA, RBAC and tenancy
- ITSM and self-service APIs
- RMM Agent, Viewer, Connect and device-control APIs/WebSockets
- Admin/control-plane APIs
- Software catalogue, qualification, patching and vulnerability orchestration
- Database migrations
- Shared PostgreSQL/Redis integration

Frontend applications are intentionally deployed separately and consume this API over HTTPS/WSS.

## Runtime

- Node.js 24
- Hono
- PostgreSQL 17
- Redis 8

## Container

Build:

    docker build -t hi5central/control-server .

Run migrations before starting the long-running service. In Compose this is handled by a dedicated migration service.

Health:
- /live
- /health

## Migration ownership

This repository is the single schema migration owner for Hi5Central until individual backend domains are explicitly extracted into independently versioned services.
