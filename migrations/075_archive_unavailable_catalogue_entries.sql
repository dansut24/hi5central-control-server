-- Hide catalogue entries with no validated deployment route; preserve source intelligence.
-- Verified WinGet mappings remain visible even when behind the vendor target.
UPDATE rmm_software_catalogue c
SET status='archived',
    source_metadata=c.source_metadata || jsonb_build_object(
      'catalogueArchiveReason','no_validated_installation_route',
      'catalogueArchivedAt',now(),
      'cataloguePreviousStatus',c.status),
    updated_at=now()
WHERE c.tenant_id IS NULL AND c.catalogue_source='vendor' AND c.status='active'
  AND NOT COALESCE((c.qualification_state='qualified'
 OR (COALESCE(c.source_metadata->>'wingetPackageId',c.source_metadata->>'autoWingetPackageId','')<>'' AND COALESCE(c.source_metadata->>'wingetPackageVersion',c.source_metadata->>'autoWingetVersion','')<>'' AND c.source_metadata->>'wingetPackageSource'='https://cdn.winget.microsoft.com/cache/source2.msix')
 OR EXISTS (SELECT 1 FROM rmm_software_vendor_releases r WHERE r.provider_package_id=c.external_key AND r.version=c.target_version AND r.trust_state='direct_ready' AND r.installer_type IN ('msi','exe') AND r.installer_url LIKE 'https://%' AND r.installer_sha256 ~* '^[a-f0-9]{64}$' AND (COALESCE(r.trust_evidence->>'signatureVerified','false')='true' OR COALESCE(r.source_payload->>'expectedSigner','')<>'')) OR (c.provider='winget' AND c.provider_package_id<>'' AND c.source_metadata->>'trustState'='winget_ready')),false);
