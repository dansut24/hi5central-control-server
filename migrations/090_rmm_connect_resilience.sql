ALTER TABLE rmm_connect_sessions
  ADD COLUMN IF NOT EXISTS held_until timestamptz,
  ADD COLUMN IF NOT EXISTS hold_requested_at timestamptz,
  ADD COLUMN IF NOT EXISTS hold_approved_at timestamptz,
  ADD COLUMN IF NOT EXISTS host_disconnected_at timestamptz,
  ADD COLUMN IF NOT EXISTS host_elevated boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS file_access_granted_at timestamptz,
  ADD COLUMN IF NOT EXISTS elevation_granted_at timestamptz;

CREATE INDEX IF NOT EXISTS idx_rmm_connect_sessions_held_until
  ON rmm_connect_sessions (held_until)
  WHERE held_until IS NOT NULL;
