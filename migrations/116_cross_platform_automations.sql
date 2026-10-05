ALTER TABLE rmm_automations DROP CONSTRAINT IF EXISTS rmm_automations_platform_check;
ALTER TABLE rmm_automations DROP CONSTRAINT IF EXISTS rmm_automations_language_check;

ALTER TABLE rmm_automations
  ADD CONSTRAINT rmm_automations_platform_check
  CHECK (platform IN ('windows','macos','linux'));

ALTER TABLE rmm_automations
  ADD CONSTRAINT rmm_automations_language_check
  CHECK (language IN ('powershell','cmd','shell'));