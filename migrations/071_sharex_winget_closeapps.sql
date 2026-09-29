UPDATE rmm_software_catalogue
   SET execution = COALESCE(execution,'{}'::jsonb) || '{"installArguments":"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CLOSEAPPLICATIONS"}'::jsonb,
       source_metadata = COALESCE(source_metadata,'{}'::jsonb) || '{"trustState":"winget_ready","deploymentMode":"winget_preferred","wingetFallbackReady":true}'::jsonb,
       updated_at=now()
 WHERE canonical_name='ShareX' AND status='active' AND provider_package_id='vendor:gh_sharex_sharex';
UPDATE rmm_software_vendor_releases SET trust_state='winget_ready' WHERE source_key='gh_sharex_sharex' AND version='21.0.0' AND trust_state='rejected';
