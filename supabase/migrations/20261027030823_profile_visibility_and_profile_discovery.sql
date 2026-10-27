-- CURIOCITY: privacy controls for profile visibility.
-- This migration is additive. Existing profiles retain the current public visibility
-- until each owner changes it. "private" means only the owner and moderators can
-- read the profile row; public moments and public Storage URLs remain separate.
begin;

alter table public.profiles
  add column if not exists profile_visibility text not null default 'public';

do $constraint$
begin
  if not exists (
    select 1
    from pg_constraint
    where conrelid = 'public.profiles'::regclass
      and conname = 'profiles_profile_visibility_check'
  ) then
    alter table public.profiles
      add constraint profiles_profile_visibility_check
      check (profile_visibility in ('public', 'friends', 'private'));
  end if;
end
$constraint$;

create index if not exists friendships_accepted_requester_addressee_idx
  on public.friendships (requester, addressee)
  where status = 'accepted';
create index if not exists friendships_accepted_addressee_requester_idx
  on public.friendships (addressee, requester)
  where status = 'accepted';

create or replace function app_private.profiles_public_rows()
returns table(
  id uuid,
  username text,
  color text,
  avatar text,
  avatar_url text,
  intro_url text,
  intro_until timestamp with time zone,
  relationship text,
  last_seen timestamp with time zone,
  show_presence boolean,
  is_blocked boolean
)
language sql
stable
security definer
set search_path to ''
as $function$
  select p.id, p.username, p.color, p.avatar, p.avatar_url,
         p.intro_url, p.intro_until, p.relationship, p.last_seen,
         p.show_presence,
         (p.status = 'blocked' or p.blocked_until > now()) as is_blocked
  from public.profiles as p
  where p.profile_visibility = 'public'
     or p.id = (select auth.uid())
     or (
       p.profile_visibility = 'friends'
       and (select auth.uid()) is not null
       and exists (
         select 1
         from public.friendships as f
         where f.status = 'accepted'
           and (
             (f.requester = p.id and f.addressee = (select auth.uid()))
             or
             (f.addressee = p.id and f.requester = (select auth.uid()))
           )
       )
     )
     or (select public.is_admin());
$function$;

create or replace function public.my_profile_private()
returns jsonb
language sql
stable
security definer
set search_path to ''
as $function$
  select jsonb_build_object(
    'bg', p.bg,
    'bg_url', p.bg_url,
    'bg_url2', p.bg_url2,
    'status', p.status,
    'blocked_until', p.blocked_until,
    'is_admin', p.is_admin,
    'profile_visibility', p.profile_visibility
  )
  from public.profiles as p
  where p.id = (select auth.uid());
$function$;

create or replace function public.set_my_profile_visibility(p_visibility text)
returns void
language plpgsql
security definer
set search_path to ''
as $function$
begin
  if (select auth.uid()) is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;

  if p_visibility is null or p_visibility not in ('public', 'friends', 'private') then
    raise exception 'Invalid profile visibility' using errcode = '22023';
  end if;

  update public.profiles
     set profile_visibility = p_visibility
   where id = (select auth.uid());

  if not found then
    raise exception 'Profile not found' using errcode = 'P0002';
  end if;
end;
$function$;

revoke all on function public.set_my_profile_visibility(text) from public;
revoke execute on function public.set_my_profile_visibility(text) from anon;
grant execute on function public.set_my_profile_visibility(text) to authenticated, service_role;

commit;


