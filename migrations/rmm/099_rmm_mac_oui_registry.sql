CREATE TABLE IF NOT EXISTS rmm_mac_oui_registry (
  assignment text PRIMARY KEY,
  registry text NOT NULL,
  organization_name text NOT NULL,
  last_seen_sync uuid NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS rmm_mac_oui_registry_org_idx
  ON rmm_mac_oui_registry(lower(organization_name));

CREATE TABLE IF NOT EXISTS rmm_mac_oui_sync_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  status text NOT NULL DEFAULT 'never'
    CHECK (status IN ('never','running','ok','failed')),
  last_started_at timestamptz,
  last_completed_at timestamptz,
  last_error text NOT NULL DEFAULT '',
  row_count integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO rmm_mac_oui_sync_state(singleton,status)
VALUES (true,'never')
ON CONFLICT (singleton) DO NOTHING;
