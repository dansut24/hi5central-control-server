ALTER TABLE rmm_agent_enrollment_packages
  ADD COLUMN IF NOT EXISTS parent_deployment_id uuid
    REFERENCES rmm_agent_enrollment_packages(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS rmm_agent_enrollment_packages_parent_deployment_idx
  ON rmm_agent_enrollment_packages(parent_deployment_id)
  WHERE parent_deployment_id IS NOT NULL;