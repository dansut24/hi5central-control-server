UPDATE rmm_software_vendor_releases
   SET source_payload=source_payload || jsonb_build_object(
     'trustState','direct_ready',
     'deploymentMode','vendor_direct'
   ),
       last_seen_at=now()
 WHERE trust_state='direct_ready';
