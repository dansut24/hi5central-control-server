CREATE TABLE IF NOT EXISTS rmm_agent_enrollment_packages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  label text NOT NULL DEFAULT 'Windows Agent',
  token_hash text NOT NULL UNIQUE,
  token_hint text NOT NULL DEFAULT '',
  expires_at timestamptz NOT NULL,
  max_uses integer NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 100),
  use_count integer NOT NULL DEFAULT 0 CHECK (use_count >= 0),
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_agent_enrollment_packages_tenant_idx
  ON rmm_agent_enrollment_packages(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS rmm_agent_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL UNIQUE REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  secret_hash text NOT NULL,
  fingerprint text NOT NULL DEFAULT '',
  architecture text NOT NULL DEFAULT '',
  agent_version text NOT NULL DEFAULT '',
  enrollment_package_id uuid REFERENCES rmm_agent_enrollment_packages(id) ON DELETE SET NULL,
  cpu_percent double precision,
  memory_used_percent double precision,
  memory_total_bytes bigint,
  memory_used_bytes bigint,
  disk_used_percent double precision,
  uptime_seconds bigint,
  active_user text NOT NULL DEFAULT '',
  service_status text NOT NULL DEFAULT '',
  websocket_status text NOT NULL DEFAULT '',
  last_authenticated_at timestamptz,
  last_telemetry_at timestamptz,
  websocket_connected_at timestamptz,
  websocket_disconnected_at timestamptz,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_agent_devices_fingerprint_idx
  ON rmm_agent_devices(tenant_id, fingerprint)
  WHERE fingerprint <> '' AND disabled_at IS NULL;
ALTER TABLE rmm_agent_devices ADD COLUMN IF NOT EXISTS last_inventory_at timestamptz;

CREATE INDEX IF NOT EXISTS rmm_agent_devices_tenant_idx
  ON rmm_agent_devices(tenant_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS rmm_agent_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_device_id uuid NOT NULL REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  job_type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued','claimed','completed','failed','cancelled')),
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  error_message text,
  queued_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  claimed_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_agent_jobs_poll_idx
  ON rmm_agent_jobs(agent_device_id, status, created_at);

CREATE INDEX IF NOT EXISTS rmm_agent_jobs_tenant_idx
  ON rmm_agent_jobs(tenant_id, created_at DESC);
