-- Workflow tasks are internal fulfilment work. Requesters should not receive
-- email/browser updates for each task state change; the parent Service Request
-- sends the meaningful customer update when the request itself is completed.
CREATE OR REPLACE FUNCTION hi5_service_request_task_reconcile()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_request service_requests%ROWTYPE;
  v_event_id uuid;
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

  SELECT user_id INTO v_task_user
  FROM organisation_people WHERE id = NEW.assignee_person_id LIMIT 1;

  -- The assignee still receives the operational task notification. The
  -- Service Request requester deliberately does not receive task-level noise.
  PERFORM hi5_insert_notification(
    NEW.tenant_id, v_task_user, v_event_id,
    'service_request.task_' || lower(replace(NEW.status, ' ', '_')),
    v_request.reference || ' · ' || NEW.title,
    'Task is now ' || NEW.status || '.',
    'Service Request', v_request.reference,
    jsonb_build_object('taskKey', NEW.external_key, 'status', NEW.status)
  );

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
