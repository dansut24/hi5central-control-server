ALTER TABLE rmm_patch_deployments DROP CONSTRAINT IF EXISTS rmm_patch_deployments_status_check;
ALTER TABLE rmm_patch_deployments ADD CONSTRAINT rmm_patch_deployments_status_check
  CHECK (status = ANY (ARRAY['planned','eligible','running','succeeded','failed','cancelled','verification_failed','reboot_required','remediation_required']::text[]));
