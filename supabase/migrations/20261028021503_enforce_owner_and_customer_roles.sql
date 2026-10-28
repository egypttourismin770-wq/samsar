-- Enforce account roles at the database boundary, not only in the browser.
drop policy if exists properties_owner_insert on public.properties;

create policy properties_owner_insert
on public.properties
for insert
to authenticated
with check (
  owner_id = (select auth.uid())
  and exists (
    select 1 from public.profiles profile
    where profile.id = (select auth.uid())
      and profile.role = 'owner'::app_role
  )
  and status = 'draft'::property_status
  and owner_fee_status = 'unpaid'
  and verified_at is null
  and rejection_reason is null
  and published_at is null
);

drop policy if exists viewings_customer_create on public.viewing_requests;

create policy viewings_customer_create
on public.viewing_requests
for insert
to authenticated
with check (
  customer_id = (select auth.uid())
  and exists (
    select 1 from public.profiles profile
    where profile.id = (select auth.uid())
      and profile.role = 'customer'::app_role
  )
  and exists (
    select 1 from public.properties property
    where property.id = viewing_requests.property_id
      and property.status = 'published'::property_status
      and property.owner_id = viewing_requests.owner_id
  )
);
