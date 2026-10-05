DO $$
BEGIN
  IF EXISTS (
    SELECT 1
      FROM pg_constraint
     WHERE conname='rmm_software_catalogue_qualification_state_check'
       AND conrelid='rmm_software_catalogue'::regclass
  ) THEN
    ALTER TABLE rmm_software_catalogue
      DROP CONSTRAINT rmm_software_catalogue_qualification_state_check;
  END IF;
END $$;

ALTER TABLE rmm_software_catalogue
  ADD CONSTRAINT rmm_software_catalogue_qualification_state_check
  CHECK (qualification_state IN (
    'intelligence_only',
    'deployment_candidate',
    'qualified',
    'qualified_limited',
    'blocked'
  ));
