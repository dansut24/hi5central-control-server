-- First-class task queue support and approval-state assignment guarantees.

UPDATE service_requests
SET assigned_person_id = NULL,
    updated_at = now()
WHERE status = 'Pending Approval'
  AND assigned_person_id IS NOT NULL;

CREATE OR REPLACE FUNCTION hi5_service_request_pending_approval_unassigned()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.status = 'Pending Approval' THEN
    IF NEW.assigned_person_id IS NOT NULL THEN
      NEW.operational_data := COALESCE(NEW.operational_data, '{}'::jsonb)
        || jsonb_build_object('pendingAssigneePersonId', NEW.assigned_person_id::text);
    END IF;
    NEW.assigned_person_id := NULL;
  ELSIF TG_OP = 'UPDATE' AND OLD.status = 'Pending Approval' THEN
    IF NEW.status = 'Approved' AND NEW.assigned_person_id IS NULL THEN
      BEGIN
        NEW.assigned_person_id := NULLIF(NEW.operational_data->>'pendingAssigneePersonId', '')::uuid;
      EXCEPTION WHEN invalid_text_representation THEN
        NEW.assigned_person_id := NULL;
      END;
    END IF;
    NEW.operational_data := COALESCE(NEW.operational_data, '{}'::jsonb) - 'pendingAssigneePersonId';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS service_request_pending_approval_unassigned ON service_requests;
CREATE TRIGGER service_request_pending_approval_unassigned
BEFORE INSERT OR UPDATE OF status, assigned_person_id
ON service_requests
FOR EACH ROW
EXECUTE FUNCTION hi5_service_request_pending_approval_unassigned();

CREATE INDEX IF NOT EXISTS service_request_tasks_active_queue_idx
  ON service_request_tasks(tenant_id, status, updated_at DESC)
  WHERE status <> 'Waiting';

CREATE OR REPLACE FUNCTION hi5_service_request_task_completion_activity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  matching_activity uuid;
  actor_name text := 'Hi5Central';
  completion_body text;
BEGIN
  IF NEW.status <> 'Completed' OR OLD.status = 'Completed' THEN
    RETURN NEW;
  END IF;

  SELECT a.id, COALESCE(NULLIF(a.actor_snapshot->>'name', ''), 'Hi5Central')
    INTO matching_activity, actor_name
  FROM service_request_activities a
  WHERE a.tenant_id = NEW.tenant_id
    AND a.request_id = NEW.request_id
    AND a.metadata->>'event' = 'request.task.updated'
    AND a.metadata->>'taskKey' = NEW.external_key
    AND a.created_at >= transaction_timestamp()
  ORDER BY a.created_at DESC
  LIMIT 1;

  actor_name := COALESCE(NULLIF(actor_name, ''), 'Hi5Central');
  completion_body := 'Task ' || NEW.external_key || ' "' || NEW.title || '" completed by ' || actor_name;
  IF NULLIF(btrim(NEW.completion_notes), '') IS NOT NULL THEN
    completion_body := completion_body || ' — ' || NEW.completion_notes;
  END IF;
  completion_body := completion_body || '.';

  IF matching_activity IS NOT NULL THEN
    UPDATE service_request_activities
    SET kind = 'system',
        visibility = 'internal',
        body_text = completion_body,
        metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object(
          'event', 'request.task.completed',
          'taskKey', NEW.external_key,
          'taskTitle', NEW.title,
          'status', 'Completed'
        )
    WHERE id = matching_activity;
  ELSE
    INSERT INTO service_request_activities (
      tenant_id,
      request_id,
      actor_snapshot,
      kind,
      visibility,
      body_text,
      metadata
    ) VALUES (
      NEW.tenant_id,
      NEW.request_id,
      jsonb_build_object('name', 'Hi5Central'),
      'system',
      'internal',
      completion_body,
      jsonb_build_object(
        'event', 'request.task.completed',
        'taskKey', NEW.external_key,
        'taskTitle', NEW.title,
        'status', 'Completed'
      )
    );
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS service_request_task_completion_activity ON service_request_tasks;
CREATE CONSTRAINT TRIGGER service_request_task_completion_activity
AFTER UPDATE ON service_request_tasks
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION hi5_service_request_task_completion_activity();

-- Upgrade untouched Hi5Central default forms to select real catalogue products/models.
-- Customised tenant forms are deliberately not changed.
UPDATE service_catalogue_items item
SET form_schema = (
      SELECT COALESCE(jsonb_agg(
        CASE WHEN field->>'id' = 'equipmentType' THEN
          field || jsonb_build_object(
            'label', 'Equipment model / item',
            'type', 'product',
            'options', COALESCE((
              SELECT jsonb_agg(
                jsonb_build_object(
                  'value', product.external_key,
                  'label', product.title,
                  'itemId', product.external_key,
                  'category', COALESCE(category.name, 'Hardware')
                )
                ORDER BY CASE product.external_key
                  WHEN 'CAT-HW-T14' THEN 1
                  WHEN 'CAT-HW-MBA13' THEN 2
                  WHEN 'CAT-HW-MON27' THEN 3
                  WHEN 'CAT-HW-DOCK' THEN 4
                  WHEN 'CAT-HW-HEADSET' THEN 5
                  ELSE 99
                END
              )
              FROM service_catalogue_items product
              LEFT JOIN service_catalogue_categories category ON category.id = product.category_id
              WHERE product.tenant_id = item.tenant_id
                AND product.kind = 'product'
                AND product.active = true
                AND product.external_key = ANY(ARRAY['CAT-HW-T14','CAT-HW-MBA13','CAT-HW-MON27','CAT-HW-DOCK','CAT-HW-HEADSET'])
            ), '[]'::jsonb)
          )
        ELSE field END
        ORDER BY ordinal
      ), '[]'::jsonb)
      FROM jsonb_array_elements(item.form_schema) WITH ORDINALITY AS fields(field, ordinal)
    ),
    price_mode = 'calculated',
    source = COALESCE(item.source, '{}'::jsonb) || jsonb_build_object('modelChoicesVersion', 1),
    updated_at = now()
WHERE item.external_key = 'CAT-EQUIPMENT'
  AND item.kind = 'request-form'
  AND item.request_type = 'Service Request'
  AND item.source->>'provider' = 'hi5central'
  AND COALESCE(item.source->>'customised', 'false') <> 'true'
  AND EXISTS (
    SELECT 1 FROM service_catalogue_items product
    WHERE product.tenant_id = item.tenant_id
      AND product.kind = 'product'
      AND product.active = true
      AND product.external_key = ANY(ARRAY['CAT-HW-T14','CAT-HW-MBA13'])
  );

UPDATE service_catalogue_items item
SET form_schema = (
      SELECT COALESCE(jsonb_agg(
        CASE WHEN field->>'id' = 'deviceRequirement' THEN
          field || jsonb_build_object(
            'label', 'Primary device model',
            'type', 'product',
            'options', COALESCE((
              SELECT jsonb_agg(
                jsonb_build_object(
                  'value', product.external_key,
                  'label', product.title,
                  'itemId', product.external_key,
                  'category', COALESCE(category.name, 'Hardware')
                )
                ORDER BY CASE product.external_key
                  WHEN 'CAT-HW-T14' THEN 1
                  WHEN 'CAT-HW-MBA13' THEN 2
                  ELSE 99
                END
              )
              FROM service_catalogue_items product
              LEFT JOIN service_catalogue_categories category ON category.id = product.category_id
              WHERE product.tenant_id = item.tenant_id
                AND product.kind = 'product'
                AND product.active = true
                AND product.external_key = ANY(ARRAY['CAT-HW-T14','CAT-HW-MBA13'])
            ), '[]'::jsonb)
          )
        ELSE field END
        ORDER BY ordinal
      ), '[]'::jsonb)
      FROM jsonb_array_elements(item.form_schema) WITH ORDINALITY AS fields(field, ordinal)
    ),
    price_mode = 'calculated',
    source = COALESCE(item.source, '{}'::jsonb) || jsonb_build_object('modelChoicesVersion', 1),
    updated_at = now()
WHERE item.external_key = 'CAT-ONBOARDING'
  AND item.kind = 'request-form'
  AND item.request_type = 'Service Request'
  AND item.source->>'provider' = 'hi5central'
  AND COALESCE(item.source->>'customised', 'false') <> 'true'
  AND EXISTS (
    SELECT 1 FROM service_catalogue_items product
    WHERE product.tenant_id = item.tenant_id
      AND product.kind = 'product'
      AND product.active = true
      AND product.external_key = ANY(ARRAY['CAT-HW-T14','CAT-HW-MBA13'])
  );
