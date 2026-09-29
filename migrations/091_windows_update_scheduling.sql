CREATE TABLE IF NOT EXISTS rmm_windows_update_observations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  agent_device_id uuid REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  update_key text NOT NULL,
  update_id text NOT NULL DEFAULT '',
  revision_number integer NOT NULL DEFAULT 0,
  title text NOT NULL,
  kb_articles jsonb NOT NULL DEFAULT '[]'::jsonb,
  categories jsonb NOT NULL DEFAULT '[]'::jsonb,
  severity text NOT NULL DEFAULT '',
  update_class text NOT NULL DEFAULT 'quality'
    CHECK (update_class IN ('critical','security','quality','feature','driver','definition','other')),
  downloaded boolean NOT NULL DEFAULT false,
  mandatory boolean NOT NULL DEFAULT false,
  reboot_required boolean NOT NULL DEFAULT false,
  auto_select boolean NOT NULL DEFAULT false,
  browse_only boolean NOT NULL DEFAULT false,
  release_at timestamptz,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  last_scan_at timestamptz,
  pending boolean NOT NULL DEFAULT true,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, inventory_id, update_key)
);

CREATE INDEX IF NOT EXISTS rmm_windows_update_observations_pending_idx
  ON rmm_windows_update_observations(tenant_id, pending, update_class, first_seen_at);

CREATE INDEX IF NOT EXISTS rmm_windows_update_observations_device_idx
  ON rmm_windows_update_observations(tenant_id, inventory_id, pending, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS rmm_windows_patch_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  inventory_id uuid NOT NULL REFERENCES rmm_device_inventory(id) ON DELETE CASCADE,
  agent_device_id uuid REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  policy_id uuid REFERENCES rmm_patch_policies(id) ON DELETE SET NULL,
  agent_job_id uuid REFERENCES rmm_agent_jobs(id) ON DELETE SET NULL,
  state text NOT NULL DEFAULT 'waiting'
    CHECK (state IN ('waiting','eligible','dispatched','completed','failed','reboot_required','blocked','offline')),
  reason text NOT NULL DEFAULT '',
  eligible_update_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
  decision jsonb NOT NULL DEFAULT '{}'::jsonb,
  evaluated_at timestamptz NOT NULL DEFAULT now(),
  dispatched_at timestamptz,
  completed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, inventory_id)
);

CREATE INDEX IF NOT EXISTS rmm_windows_patch_decisions_state_idx
  ON rmm_windows_patch_decisions(tenant_id, state, evaluated_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS rmm_windows_patch_active_job_uniq
  ON rmm_agent_jobs(tenant_id, agent_device_id)
  WHERE job_type='windows_update.install'
    AND status IN ('queued','claimed')
    AND request_metadata->>'source'='windows_patch_schedule';
