-- Some authoritative Chocolatey versions omit a packaging zero segment that
-- WinGet retains. Normalize only the provider side for these exact products;
-- the target and installed versions remain untouched.
UPDATE rmm_software_vendor_bindings
   SET metadata=metadata || jsonb_build_object(
     'versionNormalization',jsonb_build_object(
       'strategy','strip_leading_numeric_segments',
       'installedSegmentsToStrip',0,
       'providerSegmentsToStrip',1,
       'expectedRemainingSegments',3
     )
   )
 WHERE source_key IN ('registry_chocolatey_ccleaner','registry_chocolatey_everything');

UPDATE rmm_software_catalogue
   SET source_metadata=source_metadata || jsonb_build_object(
     'versionNormalization',jsonb_build_object(
       'strategy','strip_leading_numeric_segments',
       'installedSegmentsToStrip',0,
       'providerSegmentsToStrip',1,
       'expectedRemainingSegments',3
     )
   ), updated_at=now()
 WHERE external_key IN ('vendor:registry_chocolatey_ccleaner','vendor:registry_chocolatey_everything')
   AND tenant_id IS NULL AND status='active';
