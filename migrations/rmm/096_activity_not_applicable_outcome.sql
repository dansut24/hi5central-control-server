BEGIN;

ALTER TABLE rmm_activity_events
  DROP CONSTRAINT IF EXISTS rmm_activity_events_outcome_check;

ALTER TABLE rmm_activity_events
  ADD CONSTRAINT rmm_activity_events_outcome_check
  CHECK (
    outcome = ANY (
      ARRAY[
        'info'::text,
        'requested'::text,
        'running'::text,
        'success'::text,
        'failed'::text,
        'cancelled'::text,
        'not_applicable'::text
      ]
    )
  );

COMMIT;
