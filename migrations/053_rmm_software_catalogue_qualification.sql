ALTER TABLE rmm_software_catalogue
  ADD COLUMN IF NOT EXISTS qualification_state text NOT NULL DEFAULT 'intelligence_only',
  ADD COLUMN IF NOT EXISTS qualification_version text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS qualification_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS qualification_notes text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS qualified_at timestamptz,
  ADD COLUMN IF NOT EXISTS qualified_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname = 'rmm_software_catalogue_qualification_state_check'
  ) THEN
    ALTER TABLE rmm_software_catalogue
      ADD CONSTRAINT rmm_software_catalogue_qualification_state_check
      CHECK (qualification_state IN ('intelligence_only','deployment_candidate','qualified','blocked'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS rmm_software_catalogue_qualification_idx
  ON rmm_software_catalogue(qualification_state, lower(canonical_name))
  WHERE status <> 'archived';

UPDATE rmm_software_catalogue
   SET qualification_state = CASE
         WHEN tenant_id IS NULL
          AND canonical_name IN ('Microsoft PowerToys','KeePassXC','ShareX','WinMerge','VLC media player')
           THEN 'qualified'
         WHEN COALESCE(source_metadata->>'deploymentMode','') IN ('winget_preferred','vendor_direct')
           THEN 'deployment_candidate'
         WHEN tenant_id IS NOT NULL AND target_version <> ''
           THEN 'deployment_candidate'
         ELSE 'intelligence_only'
       END,
       qualification_version = CASE
         WHEN tenant_id IS NULL
          AND canonical_name IN ('Microsoft PowerToys','KeePassXC','ShareX','WinMerge','VLC media player')
           THEN target_version
         ELSE qualification_version
       END,
       qualification_evidence = CASE
         WHEN tenant_id IS NULL
          AND canonical_name IN ('Microsoft PowerToys','KeePassXC','ShareX','WinMerge','VLC media player')
           THEN qualification_evidence || jsonb_build_object(
             'source','qualification_pass_2026-09-20',
             'freshInstallVerified',true,
             'inventoryVerified',true,
             'vulnerabilityStateVerified',true,
             'uninstallVerified',true,
             'postUninstallInventoryVerified',true
           )
         ELSE qualification_evidence
       END,
       qualification_notes = CASE
         WHEN tenant_id IS NULL
          AND canonical_name IN ('Microsoft PowerToys','KeePassXC','ShareX','WinMerge','VLC media player')
           THEN 'Qualified through the September 2026 five-application end-to-end deployment pass.'
         ELSE qualification_notes
       END,
       qualified_at = CASE
         WHEN tenant_id IS NULL
          AND canonical_name IN ('Microsoft PowerToys','KeePassXC','ShareX','WinMerge','VLC media player')
           THEN COALESCE(qualified_at, now())
         ELSE qualified_at
       END,
       updated_at = now()
 WHERE status <> 'archived';
