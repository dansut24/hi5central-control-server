export function qualificationFailureClass(row = {}) {
  const error = String(row.last_error || '').toLowerCase()
  if (/target_version|verification/.test(error)) return 'identity_version'
  if (/patchhost did not return|no.result/.test(error)) return 'patchhost_result'
  if (/download/.test(error)) return 'download'
  if (/silent_install_strategy/.test(error)) return 'silent_strategy'
  if (/scope_mismatch/.test(error)) return 'install_scope'
  if (/runner_not_clean|contaminat/.test(error)) return 'runner_cleanup'
  if (/installer_failed|installer_timeout/.test(error)) return 'installer_execution'
  if (row.cleanup_job_id || /uninstall|residue|cleanup/.test(error)) return 'uninstall_cleanup'
  if (/source|artifact|release|signer/.test(error)) return 'release_readiness'
  return 'other'
}

const labels = {
  identity_version: ['Identity / version verification','Correct the package identity and version mapping, then requalify.'],
  patchhost_result: ['Missing PatchHost result','Check agent version and logs before a controlled retry.'],
  download: ['Vendor download','Diagnose the endpoint download and verify the vendor asset.'],
  silent_strategy: ['Silent install strategy','Validate installer-specific unattended arguments.'],
  install_scope: ['User installation scope','Find a machine installer or qualify on a dedicated user runner.'],
  runner_cleanup: ['Existing installation','Clean the test endpoint before retrying a clean installation.'],
  installer_execution: ['Installer execution','Group by installer technology and inspect exit codes and logs.'],
  uninstall_cleanup: ['Uninstall / cleanup','Correct removal and verify inventory absence and residual files.'],
  release_readiness: ['Release trust / readiness','Complete the missing source and artifact verification.'],
  other: ['Other review','Inspect the job evidence before retrying.'],
}

export function qualificationFailureGroups(rows = []) {
  const groups = new Map()
  for (const row of rows.filter(r => r.state === 'review_required')) {
    const key = qualificationFailureClass(row)
    if (!groups.has(key)) groups.set(key,{key,label:labels[key][0],nextAction:labels[key][1],count:0,applications:[]})
    const group=groups.get(key)
    group.count++
    group.applications.push({id:row.id,catalogueId:row.catalogue_id,name:row.canonical_name,error:row.last_error,
      installerTechnology:row.installer_technology || row.installer_type || 'unknown',testType:row.test_type})
  }
  return [...groups.values()].sort((a,b)=>b.count-a.count || a.key.localeCompare(b.key))
}
