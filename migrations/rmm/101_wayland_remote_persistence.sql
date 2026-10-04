ALTER TABLE rmm_remote_sessions
  ADD COLUMN IF NOT EXISTS wayland_persistence boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN rmm_remote_sessions.wayland_persistence IS
  'Opt-in request to restore and rotate XDG Wayland RemoteDesktop portal permission for this session.';
