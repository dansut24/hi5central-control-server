BEGIN;

ALTER TABLE rmm_software_qualification_queue
  DROP CONSTRAINT IF EXISTS rmm_software_qualification_queue_test_type_check;

ALTER TABLE rmm_software_qualification_queue
  ADD CONSTRAINT rmm_software_qualification_queue_test_type_check
  CHECK (test_type = ANY (ARRAY['clean_install'::text, 'upgrade'::text, 'rollback'::text]));

COMMIT;
