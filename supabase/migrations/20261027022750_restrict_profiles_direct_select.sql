-- Applied to project tubqwifsrrkfncokmbji as migration 20261027022750.
-- Restricts direct access only after frontend uses profiles_public and scoped RPCs.
-- Rollback ACL snapshot is documented in outputs/CURIOCITY_profiles_privilege_backup_20261026.md.

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

revoke select, insert, delete, references, trigger, truncate, maintain
  on table public.profiles from anon, authenticated;

grant select (id) on table public.profiles to authenticated;

commit;
