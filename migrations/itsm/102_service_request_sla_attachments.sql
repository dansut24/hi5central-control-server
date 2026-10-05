-- Production Service Request SLA tracking and server-backed attachments.
ALTER TABLE service_requests
  ADD COLUMN IF NOT EXISTS first_response_at timestamptz,
  ADD COLUMN IF NOT EXISTS response_due_at timestamptz,
  ADD COLUMN IF NOT EXISTS resolution_due_at timestamptz,
  ADD COLUMN IF NOT EXISTS sla_paused_at timestamptz,
  ADD COLUMN IF NOT EXISTS sla_paused_seconds bigint NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS resolved_at timestamptz;

CREATE TABLE IF NOT EXISTS service_request_attachments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  request_id uuid NOT NULL REFERENCES service_requests(id) ON DELETE CASCADE,
  file_name text NOT NULL,
  mime_type text NOT NULL DEFAULT 'application/octet-stream',
  byte_size bigint NOT NULL CHECK (byte_size > 0),
  sha256 text NOT NULL,
  content bytea NOT NULL,
  visibility text NOT NULL DEFAULT 'customer' CHECK (visibility IN ('customer','internal')),
  uploaded_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  uploaded_by_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS service_request_attachments_request_idx
  ON service_request_attachments(request_id, created_at DESC);

CREATE INDEX IF NOT EXISTS service_requests_sla_idx
  ON service_requests(tenant_id, status, resolution_due_at)
  WHERE closed_at IS NULL;
