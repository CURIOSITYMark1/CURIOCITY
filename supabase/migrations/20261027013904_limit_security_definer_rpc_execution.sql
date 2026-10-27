-- CURIOCITY security patch: limit SECURITY DEFINER RPC execution.
-- Applied to Supabase project tubqwifsrrkfncokmbji as migration:
-- 20261027013904 / limit_security_definer_rpc_execution
--
-- Keep is_admin() and my_status() callable by PUBLIC because current RLS
-- policies invoke them. They read only auth.uid()'s profile and return
-- false/'blocked' for callers without a user identity.

begin;

revoke execute on function public.admin_set_status(uuid, text) from public, anon;
grant execute on function public.admin_set_status(uuid, text) to authenticated, service_role;

revoke execute on function public.admin_unblock(uuid) from public, anon;
grant execute on function public.admin_unblock(uuid) to authenticated, service_role;

revoke execute on function public.create_story(text, text, double precision) from public, anon;
grant execute on function public.create_story(text, text, double precision) to authenticated, service_role;

revoke execute on function public.pigeon_inbox() from public, anon;
grant execute on function public.pigeon_inbox() to authenticated, service_role;

revoke execute on function public.pigeon_last() from public, anon;
grant execute on function public.pigeon_last() to authenticated, service_role;

revoke execute on function public.pigeon_seen(bigint) from public, anon;
grant execute on function public.pigeon_seen(bigint) to authenticated, service_role;

revoke execute on function public.send_pigeon(uuid, text) from public, anon;
grant execute on function public.send_pigeon(uuid, text) to authenticated, service_role;

-- Trigger functions are not public RPC endpoints. Existing triggers remain.
revoke execute on function public.handle_new_user() from public, anon, authenticated;
revoke execute on function public.rate_guard() from public, anon, authenticated;

commit;


