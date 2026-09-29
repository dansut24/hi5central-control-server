-- Enforce requester delivery policy at notification creation time.
-- This keeps customer delivery rules consistent even when a shared/older
-- background worker claims the delivery queue.
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
  v_tenant_role text;
  v_settings jsonb := '{}'::jsonb;
  v_event_class text;
  v_requester_delivery_allowed boolean := true;
BEGIN
  IF p_user_id IS NULL THEN
    RETURN NULL;
  END IF;

  SELECT m.role INTO v_tenant_role
  FROM tenant_memberships m
  WHERE m.tenant_id = p_tenant_id
    AND m.user_id = p_user_id
  LIMIT 1;

  IF v_tenant_role = 'requester' THEN
    SELECT coalesce(s.settings, '{}'::jsonb) INTO v_settings
    FROM tenant_notification_settings s
    WHERE s.tenant_id = p_tenant_id
    LIMIT 1;

    v_event_class := CASE
      WHEN lower(coalesce(p_event_type, '')) LIKE '%customer_update%' THEN 'customerUpdates'
      WHEN lower(coalesce(p_event_type, '')) LIKE '%approval%' THEN 'approvals'
      WHEN lower(coalesce(p_event_type, '')) LIKE '%.task_%'
        OR lower(coalesce(p_event_type, '')) LIKE '%.task.%' THEN 'taskUpdates'
      WHEN lower(coalesce(p_event_type, '')) LIKE '%.created'
        OR lower(coalesce(p_event_type, '')) LIKE '%submitted%' THEN 'recordCreated'
      WHEN lower(coalesce(p_event_type, '')) LIKE '%status_changed%'
        OR lower(coalesce(p_event_type, '')) LIKE '%transitioned%' THEN 'statusChanges'
      ELSE 'systemUpdates'
    END;

    v_requester_delivery_allowed := CASE v_event_class
      WHEN 'customerUpdates' THEN coalesce((v_settings->'requesterEvents'->>'customerUpdates')::boolean, true)
      WHEN 'statusChanges' THEN coalesce((v_settings->'requesterEvents'->>'statusChanges')::boolean, true)
      WHEN 'recordCreated' THEN coalesce((v_settings->'requesterEvents'->>'recordCreated')::boolean, true)
      WHEN 'approvals' THEN coalesce((v_settings->'requesterEvents'->>'approvals')::boolean, true)
      WHEN 'taskUpdates' THEN coalesce((v_settings->'requesterEvents'->>'taskUpdates')::boolean, false)
      ELSE coalesce((v_settings->'requesterEvents'->>'systemUpdates')::boolean, false)
    END;
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

  IF v_requester_delivery_allowed THEN
    INSERT INTO notification_deliveries (notification_id, channel)
    VALUES (v_notification_id, 'email'), (v_notification_id, 'browser')
    ON CONFLICT DO NOTHING;
  END IF;

  RETURN v_notification_id;
END;
$$;
