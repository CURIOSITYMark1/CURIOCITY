-- Apply only after the frontend using profiles_public and its RPC helpers is live.
-- This removes direct sensitive table reads while leaving the public ID field
-- available to authenticated UPDATE filters such as .eq("id", auth.uid()).
-- Rollback: GRANT SELECT ON TABLE public.profiles TO anon, authenticated;

begin;

do $guard$
begin
  if to_regclass('public.profiles_public') is null
     or to_regprocedure('public.my_profile_private()') is null
     or to_regprocedure('public.admin_profile_status()') is null then
    raise exception 'Profile accessor migration is missing; aborting direct SELECT restriction';
  end if;
end
$guard$;

revoke select (
  id, username, color, avatar, avatar_url, status, is_admin,
  intro_url, intro_until, relationship, last_seen, show_presence,
  bg, bg_url, bg_url2, blocked_until
) on table public.profiles from anon, authenticated;

revoke select, insert, delete, references, trigger, truncate
  on table public.profiles from anon, authenticated;

grant select (id) on table public.profiles to authenticated;

commit;

