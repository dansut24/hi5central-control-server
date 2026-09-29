UPDATE rmm_software_catalogue
   SET qualification_state = 'blocked',
       qualification_evidence = qualification_evidence || jsonb_build_object(
         'source','qualification_pass_2026-09-20_batch15',
         'blockReason','version_namespace_mismatch',
         'catalogueTargetVersion','1.95.104',
         'providerInstalledVersion','153.1.95.104',
         'installObserved',true,
         'inventoryVerified',true,
         'transportReconnectObserved',true,
         'installJobId','eddca2d2-d4db-4968-b6ed-e722183f0902',
         'agentVersion','0.1.80',
         'patchHostVersion','0.2.5'
       ),
       qualification_notes = 'Blocked during qualification: Brave GitHub release target 1.95.104 maps to Windows/WinGet version 153.1.95.104. Explicit version normalization is required before deployment can be trusted.',
       updated_at = now()
 WHERE tenant_id IS NULL
   AND status = 'active'
   AND canonical_name = 'Brave Browser'
   AND source_metadata->>'latestSource' = 'gh_brave_brave_browser';
