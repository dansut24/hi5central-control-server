UPDATE rmm_software_catalogue
   SET qualification_state = 'deployment_candidate',
       qualification_notes = 'Brave Windows/WinGet versions carry a Chromium-major prefix while upstream/NVD use the Brave product version. Installed/provider versions are normalized by stripping one leading numeric segment before patch and vulnerability comparison.',
       source_metadata = source_metadata || jsonb_build_object(
         'versionNormalization', jsonb_build_object(
           'strategy','strip_leading_numeric_segments',
           'installedSegmentsToStrip',1,
           'providerSegmentsToStrip',1,
           'expectedRemainingSegments',3
         ),
         'qualificationStatePinned', true
       ),
       updated_at = now()
 WHERE tenant_id IS NULL
   AND status = 'active'
   AND canonical_name = 'Brave Browser'
   AND source_metadata->>'latestSource' = 'gh_brave_brave_browser';

UPDATE rmm_software_vendor_sources
   SET metadata = metadata || jsonb_build_object(
         'versionNormalization', jsonb_build_object(
           'strategy','strip_leading_numeric_segments',
           'installedSegmentsToStrip',1,
           'providerSegmentsToStrip',1,
           'expectedRemainingSegments',3
         )
       ),
       updated_at = now()
 WHERE source_key = 'gh_brave_brave_browser';

UPDATE rmm_software_vendor_bindings
   SET metadata = metadata || jsonb_build_object(
         'versionNormalization', jsonb_build_object(
           'strategy','strip_leading_numeric_segments',
           'installedSegmentsToStrip',1,
           'providerSegmentsToStrip',1,
           'expectedRemainingSegments',3
         )
       )
 WHERE source_key = 'gh_brave_brave_browser';
