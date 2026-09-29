ALTER TABLE rmm_software_vendor_qualification_runners
  ADD COLUMN IF NOT EXISTS dispatch_enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS pause_reason text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS paused_at timestamptz,
  ADD COLUMN IF NOT EXISTS paused_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL;

UPDATE rmm_software_vendor_qualification_runners
SET dispatch_enabled=true
WHERE dispatch_enabled IS NULL;
