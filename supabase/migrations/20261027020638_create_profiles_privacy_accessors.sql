-- CURIOCITY: additive profile privacy accessors.
-- This migration does NOT revoke the current direct SELECT privileges on
-- public.profiles. Apply the later contract migration only after the frontend
-- switches from profiles to profiles_public and has been deployed.

create or replace view public.profiles_public
with (security_barrier = true)
as
select id, username, color, avatar, avatar_url, intro_url, intro_until,
       relationship, last_seen, show_presence,
       (status = 'blocked' or blocked_until > now()) as is_blocked
from public.profiles;

revoke all on table public.profiles_public from public;
grant select on table public.profiles_public to anon, authenticated;

create or replace function public.my_profile_private()
returns jsonb
language sql
stable
security definer
set search_path = ''
as $function$
  select jsonb_build_object(
    'bg', p.bg,
    'bg_url', p.bg_url,
    'bg_url2', p.bg_url2,
    'status', p.status,
    'blocked_until', p.blocked_until,
    'is_admin', p.is_admin
  )
  from public.profiles as p
  where p.id = (select auth.uid());
$function$;

revoke all on function public.my_profile_private() from public, anon;
grant execute on function public.my_profile_private() to authenticated, service_role;

create or replace function public.admin_profile_status()
returns table(id uuid, status text, blocked_until timestamptz, is_admin boolean)
language sql
stable
security definer
set search_path = ''
as $function$
  select p.id, p.status, p.blocked_until, p.is_admin
  from public.profiles as p
  where public.is_admin();
$function$;

revoke all on function public.admin_profile_status() from public, anon;
grant execute on function public.admin_profile_status() to authenticated, service_role;

-- All audited SECURITY DEFINER bodies use schema-qualified application objects.
-- Pinning an empty search_path prevents object-shadowing through later schemas.
alter function public.admin_set_status(uuid, text) set search_path = '';
alter function public.admin_unblock(uuid) set search_path = '';
alter function public.create_story(text, text, double precision) set search_path = '';
alter function public.handle_new_user() set search_path = '';
alter function public.is_admin() set search_path = '';
alter function public.my_status() set search_path = '';
alter function public.pigeon_inbox() set search_path = '';
alter function public.pigeon_last() set search_path = '';
alter function public.pigeon_seen(bigint) set search_path = '';
alter function public.rate_guard() set search_path = '';
alter function public.send_pigeon(uuid, text) set search_path = '';

