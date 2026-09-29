-- Salt Windows MSI registers under Salt Minion and encodes 3008.x-y as 30.08.x.y.
UPDATE rmm_software_vendor_bindings
   SET publisher='Salt Project',
       metadata=metadata || jsonb_build_object(
         'namePattern','Salt Minion',
         'publisherPattern','Salt Project',
         'verificationConfig',
           COALESCE(metadata->'verificationConfig','{}'::jsonb)
           || jsonb_build_object(
             'method','uninstall_registry',
             'displayNameContains','Salt Minion',
             'publisherContains','Salt Project',
             'versionTransform','salt_windows_msi'
           )
       )
 WHERE source_key='gh_saltstack_salt'
   AND provider_package_id='vendor:gh_saltstack_salt';

UPDATE rmm_software_catalogue
   SET publisher='Salt Project',
       name_pattern='Salt Minion',
       publisher_pattern='Salt Project',
       verification=COALESCE(verification,'{}'::jsonb) || jsonb_build_object(
         'method','uninstall_registry',
         'displayNameContains','Salt Minion',
         'publisherContains','Salt Project',
         'versionTransform','salt_windows_msi'
       ),
       updated_at=now()
 WHERE tenant_id IS NULL
   AND external_key='vendor:gh_saltstack_salt';

UPDATE rmm_software_vendor_releases
   SET publisher='Salt Project',
       source_payload=source_payload || jsonb_build_object(
         'verification',
           COALESCE(source_payload->'verification','{}'::jsonb)
           || jsonb_build_object(
             'method','uninstall_registry',
             'displayNameContains','Salt Minion',
             'publisherContains','Salt Project',
             'versionTransform','salt_windows_msi'
           )
       ),
       last_seen_at=last_seen_at
 WHERE provider_package_id='vendor:gh_saltstack_salt';
