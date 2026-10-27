-- Apply only after the frontend using profiles_public and its RPC helpers is live.
-- This removes direct table reads while leaving owner-scoped profile UPDATEs.
-- Rollback: GRANT SELECT ON TABLE public.profiles TO anon, authenticated;

begin;

revoke select (
  id, username, color, avatar, avatar_url, status, is_admin,
  intro_url, intro_until, relationship, last_seen, show_presence,
  bg, bg_url, bg_url2, blocked_until
) on table public.profiles from anon, authenticated;

revoke select, insert, delete, references, trigger, truncate
  on table public.profiles from anon, authenticated;

commit;

