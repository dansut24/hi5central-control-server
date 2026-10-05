-- Align SNMPv3 credential algorithm storage with the normalized API/Agent vocabulary
-- while retaining legacy values so previously stored credentials remain readable.
ALTER TABLE rmm_network_discovery_credentials
  DROP CONSTRAINT IF EXISTS rmm_network_discovery_credentials_auth_protocol_check;

ALTER TABLE rmm_network_discovery_credentials
  ADD CONSTRAINT rmm_network_discovery_credentials_auth_protocol_check
  CHECK (auth_protocol IN (
    '',
    'sha1','sha256',
    'MD5','SHA','SHA224','SHA256','SHA384','SHA512'
  ));

ALTER TABLE rmm_network_discovery_credentials
  DROP CONSTRAINT IF EXISTS rmm_network_discovery_credentials_privacy_protocol_check;

ALTER TABLE rmm_network_discovery_credentials
  ADD CONSTRAINT rmm_network_discovery_credentials_privacy_protocol_check
  CHECK (privacy_protocol IN (
    '',
    'aes128',
    'DES','AES','AES192','AES256'
  ));
