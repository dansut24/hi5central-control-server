ALTER TABLE rmm_software_patch_observations
  DROP CONSTRAINT IF EXISTS rmm_software_patch_observations_patch_status_check;

ALTER TABLE rmm_software_patch_observations
  ADD CONSTRAINT rmm_software_patch_observations_patch_status_check
  CHECK (patch_status = ANY (ARRAY[
    'unmapped'::text,
    'detection_pending'::text,
    'current'::text,
    'update_available'::text,
    'provider_blocked'::text,
    'unsupported'::text
  ]));

WITH latest_blocked AS (
  SELECT DISTINCT ON (d.inventory_id,lower(d.provider_package_id))
         d.inventory_id,
         d.provider_package_id,
         d.agent_job_id,
         d.result,
         d.completed_at
    FROM rmm_patch_deployments d
   WHERE d.provider='winget'
     AND d.status='verification_failed'
     AND d.provider_package_id<>''
     AND (
       lower(COALESCE(d.result->>'installerOutput','')) LIKE '%no available upgrade found%'
       OR lower(COALESCE(d.result->>'installerOutput','')) LIKE '%no newer package versions are available%'
     )
   ORDER BY d.inventory_id,lower(d.provider_package_id),d.completed_at DESC NULLS LAST,d.created_at DESC
)
UPDATE rmm_software_patch_observations o
   SET patch_status='provider_blocked',
       evidence=o.evidence || jsonb_build_object(
         'providerBlockedReason','winget_no_available_upgrade',
         'providerBlockedAt',p.completed_at,
         'providerBlockedJobId',p.agent_job_id,
         'providerBlockedDetail','WinGet reports no available upgrade while exact-package verification still finds an instance below target.'
       ),
       updated_at=now()
  FROM latest_blocked p
 WHERE o.inventory_id=p.inventory_id
   AND lower(o.provider_package_id)=lower(p.provider_package_id)
   AND o.patch_status='update_available';

UPDATE rmm_activity_events a
   SET outcome='failed',
       severity='warning',
       summary=COALESCE(NULLIF(a.actor_label,''),'Technician') || ' failed to patch “' || d.application_name || '”',
       detail=d.installed_version || ' → ' || d.target_version
         || CASE WHEN d.provider<>'' THEN ' · Provider: ' || d.provider ELSE '' END
         || ' · Verification failed'
         || CASE
              WHEN lower(COALESCE(d.result->>'installerOutput','')) LIKE '%no available upgrade found%'
                OR lower(COALESCE(d.result->>'installerOutput','')) LIKE '%no newer package versions are available%'
              THEN ' · WinGet reports no applicable upgrade'
              ELSE ''
            END
         || ' · See details',
       metadata=a.metadata || jsonb_build_object(
         'targetVersion',d.target_version,
         'verifiedVersion',COALESCE(d.result->>'verifiedVersion',''),
         'providerBlocked',
           (
             lower(COALESCE(d.result->>'installerOutput','')) LIKE '%no available upgrade found%'
             OR lower(COALESCE(d.result->>'installerOutput','')) LIKE '%no newer package versions are available%'
           )
       )
  FROM rmm_patch_deployments d
 WHERE a.job_id=d.agent_job_id
   AND a.event_type='patch.software'
   AND d.status='verification_failed';

