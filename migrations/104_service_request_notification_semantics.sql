-- Give Service Request creation, lifecycle transitions and comments distinct
-- notification event types so requester notification policy can control them.
CREATE OR REPLACE FUNCTION hi5_service_request_activity_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_request service_requests%ROWTYPE;
  v_event_id uuid;
  v_requester uuid;
  v_assignee_user uuid;
  v_source_event text;
  v_event_type text;
  v_title text;
BEGIN
  SELECT * INTO v_request FROM service_requests WHERE id = NEW.request_id;
  IF NOT FOUND THEN RETURN NEW; END IF;

  v_source_event := coalesce(NEW.metadata->>'event', '');
  v_event_type := CASE
    WHEN v_source_event = 'request.submitted' THEN 'service_request.created'
    WHEN v_source_event = 'request.transitioned' THEN 'service_request.status_changed'
    WHEN NEW.visibility = 'customer' THEN 'service_request.customer_update_added'
    ELSE 'service_request.internal_note_added'
  END;  v_title := CASE
    WHEN v_event_type = 'service_request.created' THEN v_request.reference || ' · ' || v_request.title
    WHEN v_event_type = 'service_request.status_changed' THEN v_request.reference || ' status updated'
    WHEN NEW.visibility = 'customer' THEN v_request.reference || ' has a new update'
    ELSE v_request.reference || ' was updated'
  END;

  INSERT INTO domain_events (
    tenant_id, event_type, aggregate_type, aggregate_reference, actor_user_id, payload
  ) VALUES (
    NEW.tenant_id, v_event_type, 'Service Request', v_request.reference, NEW.actor_user_id,
    jsonb_build_object(
      'activityId', NEW.id,
      'visibility', NEW.visibility,
      'sourceEvent', v_source_event,
      'metadata', NEW.metadata
    )
  ) RETURNING id INTO v_event_id;

  v_requester := v_request.requester_user_id;
  SELECT user_id INTO v_assignee_user
  FROM organisation_people
  WHERE id = v_request.assigned_person_id
  LIMIT 1;  IF v_requester IS NOT NULL
     AND NEW.visibility = 'customer'
     AND (v_event_type = 'service_request.created' OR v_requester IS DISTINCT FROM NEW.actor_user_id) THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id,
      v_requester,
      v_event_id,
      v_event_type,
      v_title,
      left(NEW.body_text, 500),
      'Service Request',
      v_request.reference,
      jsonb_build_object(
        'activityId', NEW.id,
        'sourceEvent', v_source_event,
        'status', v_request.status
      )
    );
  END IF;

  IF v_assignee_user IS NOT NULL AND v_assignee_user IS DISTINCT FROM NEW.actor_user_id THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id,
      v_assignee_user,
      v_event_id,
      v_event_type,
      v_title,
      left(NEW.body_text, 500),
      'Service Request',
      v_request.reference,
      jsonb_build_object(
        'activityId', NEW.id,
        'visibility', NEW.visibility,
        'sourceEvent', v_source_event,
        'status', v_request.status
      )
    );
  END IF;

  RETURN NEW;
END;
$$;DROP TRIGGER IF EXISTS hi5_service_request_activity_event_trigger ON service_request_activities;
CREATE TRIGGER hi5_service_request_activity_event_trigger
AFTER INSERT ON service_request_activities
FOR EACH ROW EXECUTE FUNCTION hi5_service_request_activity_event();
