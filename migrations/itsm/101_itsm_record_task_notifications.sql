-- First-class lifecycle notifications for Incident/Problem/Change record tasks.
CREATE OR REPLACE FUNCTION hi5_itsm_record_task_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_record itsm_records%ROWTYPE;
  v_event_id uuid;
  v_assignee_user uuid;
  v_record_assignee_user uuid;
  v_event_type text;
  v_prefix text;
  v_status_changed boolean := false;
  v_assignee_changed boolean := false;
  v_team_changed boolean := false;
BEGIN
  SELECT * INTO v_record FROM itsm_records WHERE id = NEW.record_id;
  IF NOT FOUND THEN RETURN NEW; END IF;

  v_prefix := lower(replace(v_record.record_type, ' ', '_'));
  SELECT user_id INTO v_assignee_user
    FROM organisation_people WHERE id = NEW.assignee_person_id LIMIT 1;
  SELECT user_id INTO v_record_assignee_user
    FROM organisation_people WHERE id = v_record.assigned_person_id LIMIT 1;

  IF TG_OP = 'INSERT' THEN
    v_event_type := v_prefix || '.task_created';
  ELSE
    v_status_changed := NEW.status IS DISTINCT FROM OLD.status;
    v_assignee_changed := NEW.assignee_person_id IS DISTINCT FROM OLD.assignee_person_id;
    v_team_changed := NEW.team_id IS DISTINCT FROM OLD.team_id;
    IF NOT v_status_changed AND NOT v_assignee_changed AND NOT v_team_changed THEN
      RETURN NEW;
    END IF;
    v_event_type := v_prefix ||
      CASE
        WHEN v_status_changed THEN '.task_' || lower(replace(NEW.status, ' ', '_'))
        WHEN v_assignee_changed THEN '.task_assigned'
        ELSE '.task_routed'
      END;
  END IF;

  INSERT INTO domain_events (
    tenant_id,event_type,aggregate_type,aggregate_reference,payload
  ) VALUES (
    NEW.tenant_id,v_event_type,v_record.record_type,v_record.reference,
    jsonb_build_object(
      'taskId',NEW.id,'taskTitle',NEW.title,'status',NEW.status,
      'assignee',NEW.assignee_snapshot,'team',NEW.team_snapshot
    )
  ) RETURNING id INTO v_event_id;

  IF v_assignee_user IS NOT NULL THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id,v_assignee_user,v_event_id,v_event_type,
      v_record.reference || ' · ' || NEW.title,
      CASE WHEN TG_OP = 'INSERT' THEN 'A task was assigned to you.'
           WHEN v_status_changed THEN 'Task status changed to ' || NEW.status || '.'
           ELSE 'Task assignment changed.' END,
      v_record.record_type,v_record.reference,
      jsonb_build_object('taskId',NEW.id,'status',NEW.status)
    );
  END IF;

  IF v_status_changed
     AND v_record_assignee_user IS NOT NULL
     AND v_record_assignee_user IS DISTINCT FROM v_assignee_user THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id,v_record_assignee_user,v_event_id,v_event_type,
      v_record.reference || ' · task update',
      NEW.title || ' is now ' || NEW.status || '.',
      v_record.record_type,v_record.reference,
      jsonb_build_object('taskId',NEW.id,'status',NEW.status)
    );
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS hi5_itsm_record_task_event_trigger ON itsm_record_tasks;
CREATE TRIGGER hi5_itsm_record_task_event_trigger
AFTER INSERT OR UPDATE OF status, assignee_person_id, team_id ON itsm_record_tasks
FOR EACH ROW EXECUTE FUNCTION hi5_itsm_record_task_event();
