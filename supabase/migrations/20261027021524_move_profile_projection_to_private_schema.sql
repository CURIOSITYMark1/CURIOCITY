-- Keep the SECURITY DEFINER projection outside the exposed public API schema.
-- Supabase's public view remains security-invoker and calls this restricted helper.

create schema if not exists app_private;
revoke all on schema app_private from public;
grant usage on schema app_private to anon, authenticated, service_role;

create or replace function app_private.profiles_public_rows()
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

revoke all on function app_private.profiles_public_rows() from public;
grant execute on function app_private.profiles_public_rows() to anon, authenticated, service_role;

create or replace view public.profiles_public
with (security_barrier = true, security_invoker = true)
as
select * from app_private.profiles_public_rows();

drop function public.profiles_public_rows();

