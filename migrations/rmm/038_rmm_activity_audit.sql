CREATE TABLE IF NOT EXISTS rmm_tool_sessions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_device_id uuid REFERENCES rmm_agent_devices(id) ON DELETE SET NULL,
  inventory_id uuid REFERENCES rmm_device_inventory(id) ON DELETE SET NULL,
  initiated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  initiated_by_label text NOT NULL DEFAULT '',
  tool text NOT NULL,
  shell text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'created' CHECK (status IN ('created','active','ended','failed')),
  started_at timestamptz,
  ended_at timestamptz,
  command_count integer NOT NULL DEFAULT 0,
  transcript text NOT NULL DEFAULT '',
  transcript_truncated boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_tool_sessions_tenant_created_idx
  ON rmm_tool_sessions(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_tool_sessions_device_created_idx
  ON rmm_tool_sessions(agent_device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS rmm_activity_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_device_id uuid REFERENCES rmm_agent_devices(id) ON DELETE SET NULL,
  inventory_id uuid REFERENCES rmm_device_inventory(id) ON DELETE SET NULL,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  actor_type text NOT NULL DEFAULT 'system' CHECK (actor_type IN ('technician','system','automation','agent','user')),
  actor_label text NOT NULL DEFAULT 'SYSTEM',
  event_type text NOT NULL,
  category text NOT NULL DEFAULT 'device',
  summary text NOT NULL,
  detail text NOT NULL DEFAULT '',
  outcome text NOT NULL DEFAULT 'info' CHECK (outcome IN ('info','requested','running','success','failed','cancelled')),
  severity text NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warning','critical')),
  correlation_id uuid,
  job_id uuid REFERENCES rmm_agent_jobs(id) ON DELETE SET NULL,
  remote_session_id uuid REFERENCES rmm_remote_sessions(id) ON DELETE SET NULL,
  tool_session_id uuid REFERENCES rmm_tool_sessions(id) ON DELETE SET NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_activity_events_tenant_created_idx
  ON rmm_activity_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_activity_events_device_created_idx
  ON rmm_activity_events(agent_device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_activity_events_actor_created_idx
  ON rmm_activity_events(tenant_id, actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_activity_events_type_created_idx
  ON rmm_activity_events(tenant_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS rmm_activity_events_correlation_idx
  ON rmm_activity_events(tenant_id, correlation_id)
  WHERE correlation_id IS NOT NULL;
