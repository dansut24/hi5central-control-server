-- Observed signed Git for Windows install: Git, publisher The Git Development
-- Community, registry version 2.55.0.5 for upstream 2.55.0.windows.5.
-- Keep release versions, hashes, signer policy and qualification evidence intact.
UPDATE rmm_software_vendor_bindings
   SET metadata=metadata || jsonb_build_object(
         'namePattern','Git',
         'publisherPattern','The Git Development Community',
         'verificationConfig',COALESCE(metadata->'verificationConfig','{}'::jsonb)
           || jsonb_build_object(
             'method','uninstall_registry',
             'displayNameContains','Git',
             'publisherContains','The Git Development Community',
             'versionTransform','git_windows_registry'))
 WHERE source_key='gh_git_for_windows_git'
   AND provider_package_id='vendor:gh_git_for_windows_git';

UPDATE rmm_software_catalogue
   SET name_pattern='Git',
       publisher_pattern='The Git Development Community',
       verification=COALESCE(verification,'{}'::jsonb) || jsonb_build_object(
         'method','uninstall_registry',
         'displayNameContains','Git',
         'publisherContains','The Git Development Community',
         'versionTransform','git_windows_registry'),
       updated_at=now()
 WHERE tenant_id IS NULL AND external_key='vendor:gh_git_for_windows_git';

UPDATE rmm_software_vendor_releases
   SET source_payload=source_payload || jsonb_build_object(
         'verification',COALESCE(source_payload->'verification','{}'::jsonb)
           || jsonb_build_object(
             'method','uninstall_registry',
             'displayNameContains','Git',
             'publisherContains','The Git Development Community',
             'versionTransform','git_windows_registry'))
 WHERE provider_package_id='vendor:gh_git_for_windows_git';
