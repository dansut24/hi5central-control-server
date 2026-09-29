-- Make person reassignment a first-class notification event.
-- The previous trigger emitted a generic "Incident updated" notification and
-- depended on a valid assigned_person_id. This version gives the newly assigned
-- account a clear assignment notification while preserving create/status/update
-- notifications for the rest of the record lifecycle.

CREATE OR REPLACE FUNCTION hi5_itsm_record_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_event_id uuid;
  v_requester_user uuid;
  v_assignee_user uuid;
  v_event_type text;
  v_prefix text;
  v_status_changed boolean := false;
  v_data_changed boolean := false;
  v_team_changed boolean := false;
  v_assignee_changed boolean := false;
BEGIN
  v_prefix := lower(replace(NEW.record_type, ' ', '_'));

  SELECT user_id INTO v_requester_user
  FROM organisation_people
  WHERE id = NEW.requester_person_id
  LIMIT 1;

  SELECT user_id INTO v_assignee_user
  FROM organisation_people
  WHERE id = NEW.assigned_person_id
  LIMIT 1;

  IF TG_OP = 'INSERT' THEN
    v_event_type := v_prefix || '.created';

    INSERT INTO domain_events (
      tenant_id, event_type, aggregate_type, aggregate_reference, payload
    ) VALUES (
      NEW.tenant_id,
      v_event_type,
      NEW.record_type,
      NEW.reference,
      jsonb_build_object(
        'status', NEW.status,
        'recordData', NEW.record_data,
        'assignee', NEW.assignee_snapshot,
        'team', NEW.assignment_team_snapshot
      )
    ) RETURNING id INTO v_event_id;

    PERFORM hi5_insert_notification(
      NEW.tenant_id,
      v_assignee_user,
      v_event_id,
      v_event_type,
      NEW.reference || ' · ' || NEW.title,
      NEW.record_type || ' created.',
      NEW.record_type,
      NEW.reference,
      jsonb_build_object('status', NEW.status, 'assignee', NEW.assignee_snapshot)
    );

    IF v_requester_user IS DISTINCT FROM v_assignee_user THEN
      PERFORM hi5_insert_notification(
        NEW.tenant_id,
        v_requester_user,
        v_event_id,
        v_event_type,
        NEW.reference || ' · ' || NEW.title,
        NEW.record_type || ' created.',
        NEW.record_type,
        NEW.reference,
        jsonb_build_object('status', NEW.status)
      );
    END IF;

    RETURN NEW;
  END IF;

  v_status_changed := NEW.status IS DISTINCT FROM OLD.status;
  v_data_changed := NEW.record_data IS DISTINCT FROM OLD.record_data;
  v_team_changed := NEW.assignment_team_snapshot IS DISTINCT FROM OLD.assignment_team_snapshot;
  v_assignee_changed := NEW.assigned_person_id IS DISTINCT FROM OLD.assigned_person_id
    OR NEW.assignee_snapshot IS DISTINCT FROM OLD.assignee_snapshot;

  IF NOT v_status_changed
     AND NOT v_data_changed
     AND NOT v_team_changed
     AND NOT v_assignee_changed THEN
    RETURN NEW;
  END IF;

  -- A person reassignment gets its own event so the new assignee always has a
  -- deterministic notification even when another field changes in the same API call.
  IF v_assignee_changed THEN
    INSERT INTO domain_events (
      tenant_id, event_type, aggregate_type, aggregate_reference, payload
    ) VALUES (
      NEW.tenant_id,
      v_prefix || '.assigned',
      NEW.record_type,
      NEW.reference,
      jsonb_build_object(
        'status', NEW.status,
        'previousAssignee', OLD.assignee_snapshot,
        'assignee', NEW.assignee_snapshot,
        'team', NEW.assignment_team_snapshot
      )
    ) RETURNING id INTO v_event_id;

    PERFORM hi5_insert_notification(
      NEW.tenant_id,
      v_assignee_user,
      v_event_id,
      v_prefix || '.assigned',
      NEW.reference || ' assigned to you',
      NEW.title || ' · ' || NEW.status,
      NEW.record_type,
      NEW.reference,
      jsonb_build_object(
        'status', NEW.status,
        'previousAssignee', OLD.assignee_snapshot,
        'assignee', NEW.assignee_snapshot,
        'team', NEW.assignment_team_snapshot
      )
    );
  END IF;

  -- If the assignee was the only thing changed, the explicit assignment event
  -- above is sufficient and avoids a duplicate generic "updated" notification.
  IF v_assignee_changed
     AND NOT v_status_changed
     AND NOT v_data_changed
     AND NOT v_team_changed THEN
    RETURN NEW;
  END IF;

  v_event_type := v_prefix ||
    CASE
      WHEN v_status_changed THEN '.status_changed'
      WHEN v_team_changed THEN '.assigned'
      ELSE '.updated'
    END;

  INSERT INTO domain_events (
    tenant_id, event_type, aggregate_type, aggregate_reference, payload
  ) VALUES (
    NEW.tenant_id,
    v_event_type,
    NEW.record_type,
    NEW.reference,
    jsonb_build_object(
      'status', NEW.status,
      'previousStatus', CASE WHEN v_status_changed THEN OLD.status ELSE NULL END,
      'recordData', NEW.record_data,
      'assignee', NEW.assignee_snapshot,
      'team', NEW.assignment_team_snapshot
    )
  ) RETURNING id INTO v_event_id;

  -- Avoid duplicating the explicit assignment notification if the same update
  -- also changed data/team. Status changes remain useful as a separate event.
  IF NOT v_assignee_changed OR v_status_changed THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id,
      v_assignee_user,
      v_event_id,
      v_event_type,
      NEW.reference || ' · ' || NEW.title,
      CASE
        WHEN v_status_changed THEN 'Status changed from ' || OLD.status || ' to ' || NEW.status || '.'
        WHEN v_team_changed THEN 'Assignment team changed.'
        ELSE NEW.record_type || ' updated.'
      END,
      NEW.record_type,
      NEW.reference,
      jsonb_build_object('status', NEW.status, 'assignee', NEW.assignee_snapshot, 'team', NEW.assignment_team_snapshot)
    );
  END IF;

  IF v_status_changed AND v_requester_user IS DISTINCT FROM v_assignee_user THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id,
      v_requester_user,
      v_event_id,
      v_event_type,
      NEW.reference || ' · ' || NEW.title,
      'Status changed to ' || NEW.status || '.',
      NEW.record_type,
      NEW.reference,
      jsonb_build_object('status', NEW.status)
    );
  END IF;

  RETURN NEW;
END;
$$;
