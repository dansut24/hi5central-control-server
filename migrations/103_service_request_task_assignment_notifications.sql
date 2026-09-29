-- Notify technicians when Service Request tasks are assigned or re-routed.
-- Requesters remain protected from task-level operational noise.
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
  v_status_changed boolean := false;
  v_assignee_changed boolean := false;
  v_team_changed boolean := false;
  v_event_type text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_status_changed := true;
  ELSE
    v_status_changed := NEW.status IS DISTINCT FROM OLD.status;
    v_assignee_changed := NEW.assignee_person_id IS DISTINCT FROM OLD.assignee_person_id;
    v_team_changed := NEW.team_id IS DISTINCT FROM OLD.team_id;
    IF NOT v_status_changed AND NOT v_assignee_changed AND NOT v_team_changed THEN
      RETURN NEW;
    END IF;
  END IF;
  SELECT * INTO v_request
  FROM service_requests
  WHERE id = NEW.request_id;
  IF NOT FOUND THEN RETURN NEW; END IF;

  v_event_type := CASE
    WHEN v_status_changed THEN 'service_request.task_' || lower(replace(NEW.status, ' ', '_'))
    WHEN v_assignee_changed THEN 'service_request.task_assigned'
    ELSE 'service_request.task_routed'
  END;

  INSERT INTO domain_events (
    tenant_id, event_type, aggregate_type, aggregate_reference, payload
  ) VALUES (
    NEW.tenant_id,
    v_event_type,
    'Service Request',
    v_request.reference,
    jsonb_build_object(
      'taskKey', NEW.external_key,
      'title', NEW.title,
      'status', NEW.status,
      'assignee', NEW.assignee_snapshot,
      'team', NEW.team_snapshot
    )
  ) RETURNING id INTO v_event_id;
  SELECT user_id INTO v_task_user
  FROM organisation_people
  WHERE id = NEW.assignee_person_id
  LIMIT 1;

  IF v_task_user IS NOT NULL THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id,
      v_task_user,
      v_event_id,
      v_event_type,
      v_request.reference || ' · ' || NEW.title,
      CASE
        WHEN v_status_changed THEN 'Task is now ' || NEW.status || '.'
        WHEN v_assignee_changed THEN 'A Service Request task was assigned to you.'
        ELSE 'Task routing changed.'
      END,
      'Service Request',
      v_request.reference,
      jsonb_build_object(
        'taskKey', NEW.external_key,
        'status', NEW.status,
        'assignee', NEW.assignee_snapshot,
        'team', NEW.team_snapshot
      )
    );
  END IF;

  IF NOT v_status_changed THEN
    RETURN NEW;
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

DROP TRIGGER IF EXISTS hi5_service_request_task_reconcile_trigger ON service_request_tasks;
CREATE TRIGGER hi5_service_request_task_reconcile_trigger
AFTER INSERT OR UPDATE OF status, assignee_person_id, team_id ON service_request_tasks
FOR EACH ROW EXECUTE FUNCTION hi5_service_request_task_reconcile();
