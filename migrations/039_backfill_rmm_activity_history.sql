-- Backfill factual RMM history that already existed before the append-only activity stream.
-- Read-only inventory/list jobs are intentionally excluded to avoid turning automatic refreshes into audit noise.

INSERT INTO rmm_activity_events
  (tenant_id,agent_device_id,inventory_id,actor_user_id,actor_type,actor_label,
   event_type,category,summary,detail,outcome,severity,correlation_id,job_id,metadata,created_at)
SELECT
  j.tenant_id,
  j.agent_device_id,
  a.inventory_id,
  j.queued_by_user_id,
  CASE WHEN j.initiated_by IN ('technician','system','automation','agent') THEN j.initiated_by ELSE 'technician' END,
  COALESCE(NULLIF(j.initiated_by_label,''), CASE WHEN j.initiated_by='automation' THEN 'AUTOMATION' ELSE 'SYSTEM' END),
  CASE
    WHEN j.job_type='software.uninstall' THEN 'software.uninstall'
    WHEN j.job_type='process.kill' THEN 'process.end'
    ELSE j.job_type
  END,
  CASE
    WHEN j.job_type LIKE 'software.%' THEN 'software'
    WHEN j.job_type LIKE 'process.%' THEN 'process'
    WHEN j.job_type LIKE 'services.%' THEN 'service'
    WHEN j.job_type LIKE 'registry.%' THEN 'registry'
    WHEN j.job_type LIKE 'windows_update.%' OR j.job_type LIKE 'patch.%' THEN 'updates'
    WHEN j.job_type='inventory.scan' THEN 'inventory'
    ELSE 'job'
  END,
  CASE
    WHEN j.job_type='software.uninstall' AND j.status='completed'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' uninstalled “' || COALESCE(NULLIF(j.payload->>'name',''),'software') || '”'
    WHEN j.job_type='software.uninstall'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' attempted to uninstall “' || COALESCE(NULLIF(j.payload->>'name',''),'software') || '”'
    WHEN j.job_type='process.kill' AND j.status='completed'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' ended process PID ' || COALESCE(j.payload->>'pid','')
    WHEN j.job_type='process.restart' AND j.status='completed'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' restarted process PID ' || COALESCE(j.payload->>'pid','')
    WHEN j.job_type='services.start' AND j.status='completed'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' started service “' || COALESCE(j.payload->>'serviceName','service') || '”'
    WHEN j.job_type='services.stop' AND j.status='completed'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' stopped service “' || COALESCE(j.payload->>'serviceName','service') || '”'
    WHEN j.job_type='services.restart' AND j.status='completed'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' restarted service “' || COALESCE(j.payload->>'serviceName','service') || '”'
    WHEN j.job_type='services.set_start_type' AND j.status='completed'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' changed service “' || COALESCE(j.payload->>'serviceName','service') || '” startup type'
    WHEN j.job_type LIKE 'registry.%' AND j.status='completed'
      THEN COALESCE(NULLIF(j.initiated_by_label,''),'Technician') || ' completed ' || replace(j.job_type,'.',' ')
    ELSE COALESCE(NULLIF(j.initiated_by_label,''),'SYSTEM') || ' ' ||
         CASE WHEN j.status='completed' THEN 'completed ' WHEN j.status='cancelled' THEN 'cancelled ' ELSE 'failed ' END ||
         replace(j.job_type,'.',' ')
  END,
  CASE
    WHEN j.status='completed' THEN 'Job successful · See details'
    WHEN j.status='cancelled' THEN 'Job cancelled · See details'
    ELSE 'Job failed' || CASE WHEN COALESCE(j.error_message,'')<>'' THEN ' · ' || left(j.error_message,260) ELSE '' END || ' · See details'
  END,
  CASE WHEN j.status='completed' THEN 'success' WHEN j.status='cancelled' THEN 'cancelled' ELSE 'failed' END,
  CASE WHEN j.status='failed' THEN 'warning' ELSE 'info' END,
  j.correlation_id,
  j.id,
  jsonb_build_object('backfilled',true),
  COALESCE(j.completed_at,j.updated_at,j.created_at)
FROM rmm_agent_jobs j
LEFT JOIN rmm_agent_devices a ON a.id=j.agent_device_id
WHERE j.status IN ('completed','failed','cancelled')
  AND j.job_type NOT IN ('processes.list','services.list','files.list','registry.list','events.list')
  AND NOT EXISTS (SELECT 1 FROM rmm_activity_events e WHERE e.job_id=j.id);

INSERT INTO rmm_activity_events
  (tenant_id,agent_device_id,inventory_id,actor_user_id,actor_type,actor_label,
   event_type,category,summary,detail,outcome,severity,remote_session_id,metadata,created_at)
SELECT
  s.tenant_id,
  s.agent_device_id,
  s.inventory_id,
  s.created_by_user_id,
  'technician',
  COALESCE(NULLIF(u.name,''),u.email,'Technician'),
  CASE WHEN s.mode='backstage' THEN 'remote.background_started' ELSE 'remote.console_started' END,
  'remote',
  COALESCE(NULLIF(u.name,''),u.email,'Technician') || ' started a ' ||
    CASE WHEN s.mode='backstage' THEN 'Background' ELSE 'remote' END || ' session',
  'Historical persisted remote-session record.',
  'success',
  'info',
  s.id,
  jsonb_build_object('mode',s.mode,'viewerClient',s.viewer_client,'backfilled',true),
  s.started_at
FROM rmm_remote_sessions s
LEFT JOIN users u ON u.id=s.created_by_user_id
WHERE s.started_at IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM rmm_activity_events e
    WHERE e.remote_session_id=s.id
      AND e.event_type=CASE WHEN s.mode='backstage' THEN 'remote.background_started' ELSE 'remote.console_started' END
  );

INSERT INTO rmm_activity_events
  (tenant_id,agent_device_id,inventory_id,actor_user_id,actor_type,actor_label,
   event_type,category,summary,detail,outcome,severity,remote_session_id,metadata,created_at)
SELECT
  s.tenant_id,
  s.agent_device_id,
  s.inventory_id,
  s.created_by_user_id,
  'technician',
  COALESCE(NULLIF(u.name,''),u.email,'Technician'),
  CASE WHEN s.mode='backstage' THEN 'remote.background_ended' ELSE 'remote.console_ended' END,
  'remote',
  COALESCE(NULLIF(u.name,''),u.email,'Technician') || ' ended a ' ||
    CASE WHEN s.mode='backstage' THEN 'Background' ELSE 'remote' END || ' session',
  CASE
    WHEN s.started_at IS NULL THEN 'Remote session ended.'
    ELSE 'Session duration ' || GREATEST(0,round(extract(epoch from (s.ended_at-s.started_at))))::bigint || ' seconds.'
  END,
  CASE WHEN s.status='failed' THEN 'failed' ELSE 'success' END,
  CASE WHEN s.status='failed' THEN 'warning' ELSE 'info' END,
  s.id,
  jsonb_build_object(
    'mode',s.mode,
    'viewerClient',s.viewer_client,
    'endReason',COALESCE(s.end_reason,''),
    'durationSeconds',CASE WHEN s.started_at IS NULL THEN NULL ELSE GREATEST(0,round(extract(epoch from (s.ended_at-s.started_at))))::bigint END,
    'backfilled',true
  ),
  s.ended_at
FROM rmm_remote_sessions s
LEFT JOIN users u ON u.id=s.created_by_user_id
WHERE s.ended_at IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM rmm_activity_events e
    WHERE e.remote_session_id=s.id
      AND e.event_type=CASE WHEN s.mode='backstage' THEN 'remote.background_ended' ELSE 'remote.console_ended' END
  );
