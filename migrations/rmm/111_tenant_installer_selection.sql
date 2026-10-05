ALTER TABLE rmm_agent_enrollment_packages
  ADD COLUMN IF NOT EXISTS installer_platform text,
  ADD COLUMN IF NOT EXISTS installer_format text;

ALTER TABLE rmm_agent_enrollment_packages
  DROP CONSTRAINT IF EXISTS rmm_agent_enrollment_packages_installer_platform_check,
  ADD CONSTRAINT rmm_agent_enrollment_packages_installer_platform_check
    CHECK (installer_platform IS NULL OR installer_platform IN ('windows','macos','linux'));

ALTER TABLE rmm_agent_enrollment_packages
  DROP CONSTRAINT IF EXISTS rmm_agent_enrollment_packages_installer_format_check,
  ADD CONSTRAINT rmm_agent_enrollment_packages_installer_format_check
    CHECK (installer_format IS NULL OR installer_format IN ('exe','msi','app','pkg','dmg','run','deb','rpm'));

CREATE INDEX IF NOT EXISTS rmm_agent_enrollment_packages_installer_selection_idx
  ON rmm_agent_enrollment_packages(tenant_id, installer_platform, installer_format, created_at DESC)
  WHERE persistent = true;