WITH cancelled AS (
  UPDATE rmm_agent_jobs j
     SET status='cancelled',
         completed_at=COALESCE(j.completed_at,now()),
         error_message=COALESCE(j.error_message,'Device was offline when offline execution protection was enabled. The job was not retained for reconnect.'),
         updated_at=now()
    FROM rmm_agent_devices a
   WHERE j.agent_device_id=a.id
     AND j.status='queued'
     AND (
       a.websocket_status IS DISTINCT FROM 'Connected'
       OR a.last_telemetry_at IS NULL
       OR a.last_telemetry_at <= now()-interval '90 seconds'
     )
  RETURNING j.id,j.tenant_id,j.agent_device_id,a.inventory_id,j.queued_by_user_id,
            j.initiated_by_label,j.job_type,j.correlation_id
)
INSERT INTO rmm_activity_events
  (tenant_id,agent_device_id,inventory_id,actor_user_id,actor_type,actor_label,
   event_type,category,summary,detail,outcome,severity,correlation_id,job_id,metadata)
SELECT tenant_id,agent_device_id,inventory_id,queued_by_user_id,'system','SYSTEM',
       'job.cancelled_offline','job',
       'SYSTEM: cancelled queued ' || job_type || ' because the device was offline',
       CASE WHEN NULLIF(initiated_by_label,'') IS NOT NULL
            THEN 'Originally requested by ' || initiated_by_label || '.'
            ELSE 'The job had not started.' END,
       'cancelled','warning',correlation_id,id,
       jsonb_build_object('reason','offline_execution_protection_enabled','requestedBy',COALESCE(initiated_by_label,''))
FROM cancelled;
