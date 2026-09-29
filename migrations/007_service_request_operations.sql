ALTER TABLE service_requests
  ADD COLUMN IF NOT EXISTS operational_data jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS service_requests_operational_updated_idx
  ON service_requests(tenant_id, updated_at DESC);
