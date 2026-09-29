UPDATE rmm_software_catalogue
   SET qualification_state='qualified',
       qualification_version='1.4.9',
       qualification_evidence=qualification_evidence || jsonb_build_object(
         'qualificationType','vendor_direct_end_to_end',
         'qualifiedAt',now(),
         'artifactInspectionJobId','8f2b82f9-28f6-4fe2-9ccc-e002ac9ac28e',
         'installJobId','412aa489-c46b-424a-a986-5c85962c69b6',
         'uninstallJobId','abfd3e9c-053d-4c15-b466-bd5ad145a202',
         'agentVersion','0.1.81',
         'patchHostVersion','0.2.6',
         'targetVersion','1.4.9',
         'verifiedInstalledVersion','1.4.9.29722256',
         'expectedSigner','PURSLANE',
         'sha256','C87D2F4CEF2A5ACD6003B6507DCFBF5D5168A256DB082CD90B54D35193224AAA',
         'hashProvenance','endpoint_pinned_sha256',
         'signatureVerified',true,
         'sha256Verified',true,
         'installVerified',true,
         'inventoryVerified',true,
         'vulnerabilityEvaluationRan',true,
         'vulnerabilityIdentityResolved',false,
         'vulnerabilityOpenExposures',0,
         'uninstallVerified',true,
         'postUninstallInventoryVerified',true,
         'uninstallStrategy','msi_product_code',
         'uninstallRebootReported',true
       ),
       qualification_notes='Vendor-direct qualification passed: PatchHost artifact trust inspection, SHA-256 and Authenticode validation, silent MSI install, post-install registry/inventory verification, vulnerability evaluation, MSI product-code uninstall, and post-uninstall inventory verification.',
       qualified_at=now(),
       qualified_by_user_id=NULL,
       updated_at=now()
 WHERE tenant_id IS NULL
   AND status='active'
   AND catalogue_source='vendor'
   AND canonical_name='RustDesk'
   AND target_version='1.4.9';
