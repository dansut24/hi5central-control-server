-- Server-backed Live Chat analyst presence.
-- desired_status records the analyst's choice; last_seen_at makes Online/Away
-- expire naturally when the workspace browser is closed or suspended.

CREATE TABLE IF NOT EXISTS live_chat_agent_presence (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  person_id uuid REFERENCES organisation_people(id) ON DELETE SET NULL,
  desired_status text NOT NULL DEFAULT 'Offline'
    CHECK (desired_status IN ('Online', 'Away', 'Offline')),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_live_chat_agent_presence_tenant_status
  ON live_chat_agent_presence (tenant_id, desired_status, last_seen_at DESC);
