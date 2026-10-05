ALTER TABLE service_requests
  ADD COLUMN IF NOT EXISTS workflow_state jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE itsm_records
  ADD COLUMN IF NOT EXISTS workflow_state jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS domain_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  event_type text NOT NULL,
  aggregate_type text NOT NULL,
  aggregate_reference text NOT NULL,
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS domain_events_tenant_created_idx
  ON domain_events(tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS domain_events_aggregate_idx
  ON domain_events(tenant_id, aggregate_reference, created_at DESC);

CREATE TABLE IF NOT EXISTS workflow_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  record_reference text NOT NULL,
  record_type text NOT NULL,
  approval_type text NOT NULL DEFAULT 'workflow',
  sequence integer NOT NULL DEFAULT 1 CHECK (sequence > 0),
  status text NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Approved', 'Rejected', 'Cancelled')),
  approver_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  approver_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  decision_note text NOT NULL DEFAULT '',
  decided_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS workflow_approvals_record_idx
  ON workflow_approvals(tenant_id, record_reference, sequence, created_at);

CREATE TABLE IF NOT EXISTS user_notification_preferences (
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  preferences jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS tenant_notification_settings (
  tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  settings jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS platform_notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_id uuid REFERENCES domain_events(id) ON DELETE SET NULL,
  event_type text NOT NULL,
  title text NOT NULL,
  body text NOT NULL DEFAULT '',
  target_type text NOT NULL DEFAULT '',
  target_reference text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  read_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS platform_notifications_user_idx
  ON platform_notifications(tenant_id, user_id, read_at, created_at DESC);

CREATE TABLE IF NOT EXISTS notification_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  notification_id uuid NOT NULL REFERENCES platform_notifications(id) ON DELETE CASCADE,
  channel text NOT NULL CHECK (channel IN ('email', 'browser')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'suppressed')),
  attempts integer NOT NULL DEFAULT 0,
  last_error text NOT NULL DEFAULT '',
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (notification_id, channel)
);

CREATE INDEX IF NOT EXISTS notification_deliveries_pending_idx
  ON notification_deliveries(status, next_attempt_at)
  WHERE status IN ('pending', 'failed');

CREATE OR REPLACE FUNCTION hi5_insert_notification(
  p_tenant_id uuid,
  p_user_id uuid,
  p_event_id uuid,
  p_event_type text,
  p_title text,
  p_body text,
  p_target_type text,
  p_target_reference text,
  p_metadata jsonb DEFAULT '{}'::jsonb
) RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
  v_notification_id uuid;
BEGIN
  IF p_user_id IS NULL THEN
    RETURN NULL;
  END IF;

  INSERT INTO platform_notifications (
    tenant_id, user_id, event_id, event_type, title, body,
    target_type, target_reference, metadata
  ) VALUES (
    p_tenant_id, p_user_id, p_event_id, p_event_type,
    left(coalesce(p_title, ''), 240), left(coalesce(p_body, ''), 2000),
    left(coalesce(p_target_type, ''), 80), left(coalesce(p_target_reference, ''), 120),
    coalesce(p_metadata, '{}'::jsonb)
  )
  RETURNING id INTO v_notification_id;

  INSERT INTO notification_deliveries (notification_id, channel)
  VALUES (v_notification_id, 'email'), (v_notification_id, 'browser')
  ON CONFLICT DO NOTHING;

  RETURN v_notification_id;
END;
$$;

CREATE OR REPLACE FUNCTION hi5_service_request_approval_reconcile()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_request service_requests%ROWTYPE;
  v_event_id uuid;
  v_requester uuid;
  v_assignee_user uuid;
  v_created_by uuid;
  v_has_pending boolean;
  v_has_rejected boolean;
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
    CASE NEW.status
      WHEN 'Approved' THEN 'service_request.approval_approved'
      WHEN 'Rejected' THEN 'service_request.approval_rejected'
      ELSE 'service_request.approval_changed'
    END,
    'Service Request', v_request.reference,
    jsonb_build_object('approvalId', NEW.id, 'label', NEW.label, 'status', NEW.status)
  ) RETURNING id INTO v_event_id;

  v_requester := v_request.requester_user_id;
  v_created_by := v_request.created_by_user_id;
  SELECT user_id INTO v_assignee_user
  FROM organisation_people WHERE id = v_request.assigned_person_id LIMIT 1;

  PERFORM hi5_insert_notification(
    NEW.tenant_id, v_requester, v_event_id,
    CASE NEW.status WHEN 'Approved' THEN 'service_request.approval_approved' WHEN 'Rejected' THEN 'service_request.approval_rejected' ELSE 'service_request.approval_changed' END,
    v_request.reference || ' approval ' || lower(NEW.status),
    NEW.label || CASE WHEN NEW.decision_note <> '' THEN ' — ' || NEW.decision_note ELSE '' END,
    'Service Request', v_request.reference,
    jsonb_build_object('approvalId', NEW.id, 'status', NEW.status)
  );

  IF v_assignee_user IS DISTINCT FROM v_requester THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id, v_assignee_user, v_event_id,
      CASE NEW.status WHEN 'Approved' THEN 'service_request.approval_approved' WHEN 'Rejected' THEN 'service_request.approval_rejected' ELSE 'service_request.approval_changed' END,
      v_request.reference || ' approval ' || lower(NEW.status),
      NEW.label,
      'Service Request', v_request.reference,
      jsonb_build_object('approvalId', NEW.id, 'status', NEW.status)
    );
  END IF;

  IF v_created_by IS DISTINCT FROM v_requester AND v_created_by IS DISTINCT FROM v_assignee_user THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id, v_created_by, v_event_id,
      CASE NEW.status WHEN 'Approved' THEN 'service_request.approval_approved' WHEN 'Rejected' THEN 'service_request.approval_rejected' ELSE 'service_request.approval_changed' END,
      v_request.reference || ' approval ' || lower(NEW.status),
      NEW.label,
      'Service Request', v_request.reference,
      jsonb_build_object('approvalId', NEW.id, 'status', NEW.status)
    );
  END IF;

  SELECT EXISTS(
    SELECT 1 FROM service_request_approvals WHERE request_id = NEW.request_id AND status = 'Pending'
  ) INTO v_has_pending;
  SELECT EXISTS(
    SELECT 1 FROM service_request_approvals WHERE request_id = NEW.request_id AND status = 'Rejected'
  ) INTO v_has_rejected;

  IF v_has_rejected THEN
    UPDATE service_requests
    SET status = 'Rejected',
        workflow_state = coalesce(workflow_state, '{}'::jsonb) || jsonb_build_object(
          'approvalState', 'Rejected',
          'readyForFulfilment', false,
          'readyForCompletion', false
        ),
        updated_at = now()
    WHERE id = NEW.request_id AND status NOT IN ('Closed');
  ELSIF NOT v_has_pending THEN
    UPDATE service_requests
    SET status = CASE WHEN status IN ('New', 'Pending Approval') THEN 'Approved' ELSE status END,
        workflow_state = coalesce(workflow_state, '{}'::jsonb) || jsonb_build_object(
          'approvalState', 'Approved',
          'readyForFulfilment', true
        ),
        updated_at = now()
    WHERE id = NEW.request_id;

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

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS hi5_service_request_approval_reconcile_trigger ON service_request_approvals;
CREATE TRIGGER hi5_service_request_approval_reconcile_trigger
AFTER INSERT OR UPDATE OF status ON service_request_approvals
FOR EACH ROW EXECUTE FUNCTION hi5_service_request_approval_reconcile();

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
        'readyForFulfilment', v_blocked = 0
      ),
      updated_at = now()
  WHERE id = NEW.request_id;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS hi5_service_request_task_reconcile_trigger ON service_request_tasks;
CREATE TRIGGER hi5_service_request_task_reconcile_trigger
AFTER INSERT OR UPDATE OF status ON service_request_tasks
FOR EACH ROW EXECUTE FUNCTION hi5_service_request_task_reconcile();

CREATE OR REPLACE FUNCTION hi5_service_request_activity_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_request service_requests%ROWTYPE;
  v_event_id uuid;
  v_requester uuid;
  v_assignee_user uuid;
BEGIN
  SELECT * INTO v_request FROM service_requests WHERE id = NEW.request_id;
  IF NOT FOUND THEN RETURN NEW; END IF;

  INSERT INTO domain_events (
    tenant_id, event_type, aggregate_type, aggregate_reference, actor_user_id, payload
  ) VALUES (
    NEW.tenant_id,
    CASE WHEN NEW.visibility = 'customer' THEN 'service_request.customer_update_added' ELSE 'service_request.internal_note_added' END,
    'Service Request', v_request.reference, NEW.actor_user_id,
    jsonb_build_object('activityId', NEW.id, 'visibility', NEW.visibility)
  ) RETURNING id INTO v_event_id;

  v_requester := v_request.requester_user_id;
  SELECT user_id INTO v_assignee_user FROM organisation_people WHERE id = v_request.assigned_person_id LIMIT 1;

  IF NEW.visibility = 'customer' AND v_requester IS DISTINCT FROM NEW.actor_user_id THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id, v_requester, v_event_id,
      'service_request.customer_update_added',
      v_request.reference || ' has a new update',
      left(NEW.body_text, 500),
      'Service Request', v_request.reference,
      jsonb_build_object('activityId', NEW.id)
    );
  END IF;

  IF v_assignee_user IS DISTINCT FROM NEW.actor_user_id THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id, v_assignee_user, v_event_id,
      CASE WHEN NEW.visibility = 'customer' THEN 'service_request.customer_update_added' ELSE 'service_request.internal_note_added' END,
      v_request.reference || ' was updated',
      left(NEW.body_text, 500),
      'Service Request', v_request.reference,
      jsonb_build_object('activityId', NEW.id, 'visibility', NEW.visibility)
    );
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS hi5_service_request_activity_event_trigger ON service_request_activities;
CREATE TRIGGER hi5_service_request_activity_event_trigger
AFTER INSERT ON service_request_activities
FOR EACH ROW EXECUTE FUNCTION hi5_service_request_activity_event();

CREATE OR REPLACE FUNCTION hi5_itsm_record_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  v_event_id uuid;
  v_requester_user uuid;
  v_assignee_user uuid;
  v_event_type text;
BEGIN
  IF TG_OP = 'UPDATE'
     AND NEW.status IS NOT DISTINCT FROM OLD.status
     AND NEW.record_data IS NOT DISTINCT FROM OLD.record_data
     AND NEW.assignment_team_snapshot IS NOT DISTINCT FROM OLD.assignment_team_snapshot
     AND NEW.assignee_snapshot IS NOT DISTINCT FROM OLD.assignee_snapshot THEN
    RETURN NEW;
  END IF;

  v_event_type := lower(replace(NEW.record_type, ' ', '_')) ||
    CASE
      WHEN TG_OP = 'INSERT' THEN '.created'
      WHEN NEW.status IS DISTINCT FROM OLD.status THEN '.status_changed'
      WHEN NEW.assignee_snapshot IS DISTINCT FROM OLD.assignee_snapshot OR NEW.assignment_team_snapshot IS DISTINCT FROM OLD.assignment_team_snapshot THEN '.assigned'
      ELSE '.updated'
    END;

  INSERT INTO domain_events (
    tenant_id, event_type, aggregate_type, aggregate_reference, payload
  ) VALUES (
    NEW.tenant_id, v_event_type, NEW.record_type, NEW.reference,
    jsonb_build_object(
      'status', NEW.status,
      'previousStatus', CASE WHEN TG_OP = 'UPDATE' THEN OLD.status ELSE NULL END,
      'recordData', NEW.record_data
    )
  ) RETURNING id INTO v_event_id;

  SELECT user_id INTO v_requester_user FROM organisation_people WHERE id = NEW.requester_person_id LIMIT 1;
  SELECT user_id INTO v_assignee_user FROM organisation_people WHERE id = NEW.assigned_person_id LIMIT 1;

  PERFORM hi5_insert_notification(
    NEW.tenant_id, v_assignee_user, v_event_id, v_event_type,
    NEW.reference || ' · ' || NEW.title,
    CASE WHEN TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status
      THEN 'Status changed from ' || OLD.status || ' to ' || NEW.status || '.'
      ELSE NEW.record_type || ' updated.' END,
    NEW.record_type, NEW.reference,
    jsonb_build_object('status', NEW.status)
  );

  IF v_requester_user IS DISTINCT FROM v_assignee_user AND (
    TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status)
  ) THEN
    PERFORM hi5_insert_notification(
      NEW.tenant_id, v_requester_user, v_event_id, v_event_type,
      NEW.reference || ' · ' || NEW.title,
      CASE WHEN TG_OP = 'UPDATE' AND NEW.status IS DISTINCT FROM OLD.status
        THEN 'Status changed to ' || NEW.status || '.'
        ELSE NEW.record_type || ' created.' END,
      NEW.record_type, NEW.reference,
      jsonb_build_object('status', NEW.status)
    );
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS hi5_itsm_record_event_trigger ON itsm_records;
CREATE TRIGGER hi5_itsm_record_event_trigger
AFTER INSERT OR UPDATE ON itsm_records
FOR EACH ROW EXECUTE FUNCTION hi5_itsm_record_event();

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

DROP TRIGGER IF EXISTS hi5_itsm_activity_event_trigger ON itsm_record_activities;
CREATE TRIGGER hi5_itsm_activity_event_trigger
AFTER INSERT ON itsm_record_activities
FOR EACH ROW EXECUTE FUNCTION hi5_itsm_activity_event();
