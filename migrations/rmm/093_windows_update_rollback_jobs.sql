CREATE UNIQUE INDEX IF NOT EXISTS rmm_windows_rollback_active_job_uniq
  ON rmm_agent_jobs(tenant_id, agent_device_id)
  WHERE job_type='windows_update.rollback'
    AND status IN ('queued','claimed')
    AND request_metadata->>'source'='windows_update_rollback';
