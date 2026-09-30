CREATE OR REPLACE FUNCTION hi5_service_request_task_reconcile()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_request service_requests%ROWTYPE;
  v_event_id uuid;
  v_requester uuid;
  v_task_user uuid;
  v_total integer;
  v_complete integer;
  v_blocked integer;
  v_in_progress integer;
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
    RETURN NEW;
  END IF;

  SELECT * INTO v_request FROM service_requests WHERE id = NEW.request_id;
  IF NOT FOUND THEN RETURN NEW; END IF;

  INSERT INTO domain_events (
    tenant_id, event_type, aggregate_type, aggregate_reference, payload
  ) VALUES (
    NEW.tenant_id,
    'service_request.task_' || lower(replace(NEW.status, ' ', '_')),
    'Service Request', v_request.reference,
    jsonb_build_object('taskKey', NEW.external_key, 'title', NEW.title, 'status', NEW.status)
  ) RETURNING id INTO v_event_id;

  v_requester := v_request.requester_user_id;
  SELECT user_id INTO v_task_user
  FROM organisation_people WHERE id = NEW.assignee_person_id LIMIT 1;

  PERFORM hi5_insert_notification(
    NEW.tenant_id, v_task_user, v_event_id,
    'service_request.task_' || lower(replace(NEW.status, ' ', '_')),
    v_request.reference || ' · ' || NEW.title,
    'Task is now ' || NEW.status || '.',
    'Service Request', v_request.reference,
    jsonb_build_object('taskKey', NEW.external_key, 'status', NEW.status)
  );

  IF NEW.status IN ('Completed', 'Blocked') AND v_requester IS DISTINCT FROM v_task_user THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id, v_requester, v_event_id,
      'service_request.task_' || lower(replace(NEW.status, ' ', '_')),
      v_request.reference || ' fulfilment update',
      NEW.title || ' is ' || lower(NEW.status) || '.',
      'Service Request', v_request.reference,
      jsonb_build_object('taskKey', NEW.external_key, 'status', NEW.status)
    );
  END IF;

  IF v_request.status IN ('Approved', 'In Progress') THEN
    UPDATE service_request_tasks t
    SET status = 'Ready', updated_at = now()
    WHERE t.request_id = NEW.request_id
      AND t.status = 'Waiting'
      AND NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements_text(coalesce(t.dependencies, '[]'::jsonb)) dep(key)
        LEFT JOIN service_request_tasks prerequisite
          ON prerequisite.request_id = t.request_id
         AND prerequisite.external_key = dep.key
        WHERE prerequisite.id IS NULL OR prerequisite.status <> 'Completed'
      );
  END IF;

  SELECT count(*),
         count(*) FILTER (WHERE status = 'Completed'),
         count(*) FILTER (WHERE status = 'Blocked'),
         count(*) FILTER (WHERE status = 'In Progress')
    INTO v_total, v_complete, v_blocked, v_in_progress
  FROM service_request_tasks
  WHERE request_id = NEW.request_id;

  UPDATE service_requests
  SET status = CASE
        WHEN status = 'Approved' AND (v_in_progress > 0 OR v_complete > 0) THEN 'In Progress'
        ELSE status
      END,
      workflow_state = coalesce(workflow_state, '{}'::jsonb) || jsonb_build_object(
        'taskTotal', v_total,
        'taskComplete', v_complete,
        'taskBlocked', v_blocked,
        'readyForCompletion', v_total > 0 AND v_complete = v_total,
        'readyForFulfilment', v_request.status IN ('Approved', 'In Progress') AND v_blocked = 0
      ),
      updated_at = now()
  WHERE id = NEW.request_id;

  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION hi5_itsm_activity_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_record itsm_records%ROWTYPE;
  v_event_id uuid;
  v_requester_user uuid;
  v_assignee_user uuid;
  v_event_type text;
BEGIN
  -- Workflow transitions already generate a record-level domain event. The
  -- companion timeline entry is audit context, not a second notification.
  IF NEW.kind = 'workflow' THEN
    RETURN NEW;
  END IF;

  SELECT * INTO v_record FROM itsm_records WHERE id = NEW.record_id;
  IF NOT FOUND THEN RETURN NEW; END IF;

  v_event_type := lower(replace(v_record.record_type, ' ', '_')) ||
    CASE WHEN NEW.visibility = 'customer' THEN '.customer_update_added' ELSE '.internal_note_added' END;

  INSERT INTO domain_events (
    tenant_id, event_type, aggregate_type, aggregate_reference, actor_user_id, payload
  ) VALUES (
    NEW.tenant_id, v_event_type, v_record.record_type, v_record.reference, NEW.actor_user_id,
    jsonb_build_object('activityId', NEW.id, 'visibility', NEW.visibility)
  ) RETURNING id INTO v_event_id;

  SELECT user_id INTO v_requester_user FROM organisation_people WHERE id = v_record.requester_person_id LIMIT 1;
  SELECT user_id INTO v_assignee_user FROM organisation_people WHERE id = v_record.assigned_person_id LIMIT 1;

  IF NEW.visibility = 'customer' AND v_requester_user IS DISTINCT FROM NEW.actor_user_id THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id, v_requester_user, v_event_id, v_event_type,
      v_record.reference || ' has a new update',
      left(NEW.body_text, 500),
      v_record.record_type, v_record.reference,
      jsonb_build_object('activityId', NEW.id)
    );
  END IF;

  IF v_assignee_user IS DISTINCT FROM NEW.actor_user_id THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id, v_assignee_user, v_event_id, v_event_type,
      v_record.reference || ' was updated',
      left(NEW.body_text, 500),
      v_record.record_type, v_record.reference,
      jsonb_build_object('activityId', NEW.id, 'visibility', NEW.visibility)
    );
  END IF;

  RETURN NEW;
END;
$$;
