-- Keep the privileged role check out of the exposed Data API schema.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to anon, authenticated;

create or replace function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $function$
  select exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'::public.app_role
  );
$function$;

revoke all on function private.is_admin() from public;
grant execute on function private.is_admin() to anon, authenticated;

-- Keep existing RLS policies compatible, but make the exposed wrapper SECURITY INVOKER.
create or replace function public.is_admin()
returns boolean
language sql
stable
security invoker
set search_path = pg_catalog, public, private
as $function$
  select private.is_admin();
$function$;

revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;
