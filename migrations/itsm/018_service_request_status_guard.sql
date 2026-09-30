CREATE OR REPLACE FUNCTION hi5_service_request_status_guard()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  -- Legacy approval handling historically moved an approved request back to
  -- New after the final decision. Preserve the explicit Approved lifecycle
  -- state introduced by the end-to-end workflow engine.
  IF OLD.status = 'Approved' AND NEW.status = 'New' THEN
    IF EXISTS (
      SELECT 1
      FROM service_request_approvals a
      WHERE a.request_id = OLD.id
    ) AND NOT EXISTS (
      SELECT 1
      FROM service_request_approvals a
      WHERE a.request_id = OLD.id
        AND a.status <> 'Approved'
    ) THEN
      NEW.status := 'Approved';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS hi5_service_request_status_guard_trigger ON service_requests;
CREATE TRIGGER hi5_service_request_status_guard_trigger
BEFORE UPDATE OF status ON service_requests
FOR EACH ROW EXECUTE FUNCTION hi5_service_request_status_guard();
