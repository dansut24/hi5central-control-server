UPDATE rmm_software_catalogue
   SET qualification_state = 'qualified',
       qualification_version = '2.0.28',
       qualification_evidence = qualification_evidence || jsonb_build_object(
         'source','qualification_pass_2026-09-20_batch15',
         'freshInstallVerified',true,
         'inventoryVerified',true,
         'vulnerabilityStateVerified',true,
         'vulnerabilityIdentity','cpe:2.3:a:autohotkey:autohotkey:*:*:*:*:*:*:*:*',
         'vulnerabilityMatcherVersion',5,
         'applicableCves',0,
         'uninstallVerified',true,
         'postUninstallInventoryVerified',true,
         'installJobId','6082c5ba-f749-4c9d-ae3b-510a4c0b3309',
         'uninstallJobId','d540976a-7e29-4af7-9ff6-1305675d4684',
         'agentVersion','0.1.80',
         'patchHostVersion','0.2.5'
       ),
       qualification_notes = 'Qualified end-to-end: fresh install, inventory detection, authoritative NVD/CPE check, uninstall, and post-uninstall inventory verification.',
       qualified_at = COALESCE(qualified_at, now()),
       updated_at = now()
 WHERE tenant_id IS NULL
   AND status = 'active'
   AND canonical_name = 'AutoHotkey'
   AND source_metadata->>'latestSource' = 'gh_autohotkey_autohotkey';
