ALTER TABLE rmm_agent_enrollment_packages
  ADD COLUMN IF NOT EXISTS persistent boolean NOT NULL DEFAULT false;

ALTER TABLE rmm_agent_enrollment_packages
  ADD COLUMN IF NOT EXISTS artifact_build_requested_at timestamptz;

ALTER TABLE rmm_agent_enrollment_packages
  ADD COLUMN IF NOT EXISTS artifact_build_completed_at timestamptz;

ALTER TABLE rmm_agent_enrollment_packages
  ADD COLUMN IF NOT EXISTS artifact_build_error text;

CREATE INDEX IF NOT EXISTS rmm_agent_enrollment_packages_active_persistent_idx
  ON rmm_agent_enrollment_packages(tenant_id, created_at DESC)
  WHERE persistent = true AND revoked_at IS NULL;