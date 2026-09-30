-- Allow a persisted Saved View to target the cross-process All Records queue.
ALTER TABLE itsm_saved_views
  DROP CONSTRAINT IF EXISTS itsm_saved_views_record_type_check;

ALTER TABLE itsm_saved_views
  ADD CONSTRAINT itsm_saved_views_record_type_check
  CHECK (record_type IN ('All','Incident','Service Request','Problem','Change'));