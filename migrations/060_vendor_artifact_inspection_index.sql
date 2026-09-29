CREATE INDEX IF NOT EXISTS rmm_agent_jobs_vendor_artifact_inspect_idx
  ON rmm_agent_jobs((request_metadata->>'vendor_release_id'), status, created_at DESC)
  WHERE job_type='patch.vendor_artifact.inspect'
    AND request_metadata->>'source'='vendor_artifact_trust_probe';
