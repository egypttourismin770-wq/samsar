-- Samsar: allow the frontend to read only intentionally public configuration
-- and correct the ownership check for customer viewing requests.
grant select on table public.platform_settings to anon, authenticated;
grant select on table public.payment_methods to anon, authenticated;
grant select on table public.ai_knowledge_articles to anon, authenticated;

drop policy if exists viewings_customer_create on public.viewing_requests;

create policy viewings_customer_create
on public.viewing_requests
for insert
to authenticated
with check (
  customer_id = (select auth.uid())
  and exists (
    select 1
    from public.properties as p
    where p.id = viewing_requests.property_id
      and p.status = 'published'
      and p.owner_id = viewing_requests.owner_id
  )
);
