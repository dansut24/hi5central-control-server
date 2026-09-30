-- Keep Service Request ownership independent from approval and fulfilment-task routing.
-- Pending approvals live in the approval queue with no parent team/person owner.
-- Approval completion releases workflow tasks but never silently restores parent ownership.

UPDATE service_requests
SET fulfilment_team_id = NULL,
    fulfilment_team_snapshot = '{}'::jsonb,
    assigned_person_id = NULL,
    operational_data = COALESCE(operational_data, '{}'::jsonb) - 'pendingAssigneePersonId',
    updated_at = now()
WHERE status = 'Pending Approval'
  AND (
    fulfilment_team_id IS NOT NULL
    OR assigned_person_id IS NOT NULL
    OR COALESCE(fulfilment_team_snapshot, '{}'::jsonb) <> '{}'::jsonb
    OR COALESCE(operational_data, '{}'::jsonb) ? 'pendingAssigneePersonId'
  );

CREATE OR REPLACE FUNCTION hi5_service_request_pending_approval_unassigned()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.status = 'Pending Approval' THEN
    NEW.fulfilment_team_id := NULL;
    NEW.fulfilment_team_snapshot := '{}'::jsonb;
    NEW.assigned_person_id := NULL;
  END IF;

  NEW.operational_data := COALESCE(NEW.operational_data, '{}'::jsonb) - 'pendingAssigneePersonId';
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS service_request_pending_approval_unassigned ON service_requests;
CREATE TRIGGER service_request_pending_approval_unassigned
BEFORE INSERT OR UPDATE OF status, assigned_person_id, fulfilment_team_id, fulfilment_team_snapshot
ON service_requests
FOR EACH ROW
EXECUTE FUNCTION hi5_service_request_pending_approval_unassigned();
