-- Replace the default SECURITY DEFINER view with an invoker view.
-- The helper is a deliberately public read-only projection with no parameters;
-- it returns only the public profile fields already intended for the UI.

create or replace function public.profiles_public_rows()
returns table(
  id uuid,
  username text,
  color text,
  avatar text,
  avatar_url text,
  intro_url text,
  intro_until timestamptz,
  relationship text,
  last_seen timestamptz,
  show_presence boolean,
  is_blocked boolean
)
language sql
stable
security definer
set search_path = ''
as $function$
  select p.id, p.username, p.color, p.avatar, p.avatar_url,
         p.intro_url, p.intro_until, p.relationship, p.last_seen,
         p.show_presence,
         (p.status = 'blocked' or p.blocked_until > now()) as is_blocked
  from public.profiles as p;
$function$;

revoke all on function public.profiles_public_rows() from public;
grant execute on function public.profiles_public_rows() to anon, authenticated, service_role;

create or replace view public.profiles_public
with (security_barrier = true, security_invoker = true)
as
select * from public.profiles_public_rows();

revoke all on table public.profiles_public from public;
grant select on table public.profiles_public to anon, authenticated, service_role;

