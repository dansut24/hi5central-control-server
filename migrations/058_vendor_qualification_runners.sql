CREATE TABLE IF NOT EXISTS rmm_software_vendor_qualification_runners (
  agent_device_id uuid PRIMARY KEY REFERENCES rmm_agent_devices(id) ON DELETE CASCADE,
  enabled boolean NOT NULL DEFAULT true,
  notes text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_vendor_qualification_runners_enabled_idx
  ON rmm_software_vendor_qualification_runners(enabled, updated_at DESC);
