ALTER TABLE rmm_software_vendor_releases
  ADD COLUMN IF NOT EXISTS release_url text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS asset_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS trust_state text NOT NULL DEFAULT 'version_only',
  ADD COLUMN IF NOT EXISTS trust_evidence jsonb NOT NULL DEFAULT '{}'::jsonb;

UPDATE rmm_software_vendor_releases
   SET trust_state = COALESCE(NULLIF(source_payload->>'trustState',''),'version_only'),
       release_url = COALESCE(NULLIF(source_payload->>'releaseUrl',''),release_url),
       trust_evidence = trust_evidence || jsonb_build_object(
         'backfilledFromSourcePayload', true,
         'backfilledAt', now()
       )
 WHERE trust_state = 'version_only'
    OR release_url = '';

CREATE INDEX IF NOT EXISTS rmm_software_vendor_releases_trust_idx
  ON rmm_software_vendor_releases(trust_state, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS rmm_agent_jobs_vendor_artifact_probe_idx
  ON rmm_agent_jobs((request_metadata->>'vendor_release_id'), status, created_at DESC)
  WHERE job_type='custom.command'
    AND request_metadata->>'source'='vendor_artifact_trust_probe';
