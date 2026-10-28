-- Samsar frontend integration fields and stronger owner listing insert controls
alter table public.properties
  add column if not exists suggested_price_egp numeric,
  add column if not exists contract_details text,
  add column if not exists map_url text;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'properties_suggested_price_nonnegative'
      and conrelid = 'public.properties'::regclass
  ) then
    alter table public.properties
      add constraint properties_suggested_price_nonnegative
      check (suggested_price_egp is null or suggested_price_egp >= 0);
  end if;
end $$;

alter table public.viewing_requests
  add column if not exists customer_name text,
  add column if not exists customer_phone text,
  add column if not exists owner_proposed_scheduled_at timestamptz;

drop policy if exists properties_owner_insert on public.properties;

create policy properties_owner_insert
on public.properties
for insert
to authenticated
with check (
  owner_id = (select auth.uid())
  and not (select public.is_admin())
  and status = 'draft'::property_status
  and owner_fee_status = 'unpaid'
  and verified_at is null
  and rejection_reason is null
  and published_at is null
);
