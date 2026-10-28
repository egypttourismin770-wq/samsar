-- Samsar: allow staff to review listings and coordinate viewing requests with limited workflow rights.
create or replace function private.is_staff()
returns boolean
language sql
stable
security definer
set search_path = pg_catalog, public
as $function$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid()
      and p.role = 'staff'::public.app_role
  );
$function$;

revoke all on function private.is_staff() from public;
grant execute on function private.is_staff() to anon, authenticated;

drop policy if exists properties_read_published_or_owner_or_staff on public.properties;
create policy properties_read_published_or_owner_or_staff
on public.properties for select to anon, authenticated
using (
  status = 'published'::public.property_status
  or owner_id = (select auth.uid())
  or (select public.is_admin())
  or (select private.is_staff())
);

drop policy if exists amenities_read_published_or_owner on public.property_amenities;
create policy amenities_read_published_or_owner
on public.property_amenities for select to anon, authenticated
using (
  exists (
    select 1 from public.properties p
    where p.id = property_amenities.property_id
      and (
        p.status = 'published'::public.property_status
        or p.owner_id = (select auth.uid())
        or (select public.is_admin())
        or (select private.is_staff())
      )
  )
);

drop policy if exists images_read_published_or_owner on public.property_images;
create policy images_read_published_or_owner
on public.property_images for select to anon, authenticated
using (
  exists (
    select 1 from public.properties p
    where p.id = property_images.property_id
      and (
        p.status = 'published'::public.property_status
        or p.owner_id = (select auth.uid())
        or (select public.is_admin())
        or (select private.is_staff())
      )
  )
);

drop policy if exists viewings_participants_read on public.viewing_requests;
create policy viewings_participants_read
on public.viewing_requests for select to authenticated
using (
  customer_id = (select auth.uid())
  or owner_id = (select auth.uid())
  or (select public.is_admin())
  or (select private.is_staff())
);

drop policy if exists viewings_participants_update on public.viewing_requests;
create policy viewings_participants_update
on public.viewing_requests for update to authenticated
using (
  customer_id = (select auth.uid())
  or owner_id = (select auth.uid())
  or (select public.is_admin())
  or (select private.is_staff())
)
with check (
  customer_id = (select auth.uid())
  or owner_id = (select auth.uid())
  or (select public.is_admin())
  or (select private.is_staff())
);

create or replace function public.guard_viewing_request_participants()
returns trigger
language plpgsql
security definer
set search_path to 'public', 'private'
as $function$
begin
  if public.is_admin() then
    new.updated_at := now();
    return new;
  end if;

  if new.customer_id is distinct from old.customer_id
     or new.owner_id is distinct from old.owner_id
     or new.property_id is distinct from old.property_id then
    raise exception 'Participants and property cannot be changed after a viewing request is created';
  end if;

  if auth.uid() = old.customer_id then
    if new.owner_note is distinct from old.owner_note
       or new.owner_proposed_scheduled_at is distinct from old.owner_proposed_scheduled_at
       or new.owner_proposed_at is distinct from old.owner_proposed_at then
      raise exception 'Customer cannot change owner-only viewing fields';
    end if;
    if new.status in ('completed','owner_proposed','rejected') then
      raise exception 'Customer cannot set owner-only viewing statuses';
    end if;
    if new.status = 'confirmed' then
      if old.status <> 'owner_proposed'
         or new.scheduled_at is distinct from old.owner_proposed_scheduled_at then
        raise exception 'Customer can confirm only the proposed viewing time';
      end if;
    elsif new.scheduled_at is distinct from old.scheduled_at then
      raise exception 'Customer cannot change the viewing time directly';
    end if;

  elsif auth.uid() = old.owner_id then
    if new.customer_note is distinct from old.customer_note
       or new.customer_name is distinct from old.customer_name
       or new.customer_phone is distinct from old.customer_phone
       or new.customer_proposed_at is distinct from old.customer_proposed_at then
      raise exception 'Owner cannot change customer-only viewing fields';
    end if;
    if new.status = 'customer_proposed' then
      raise exception 'Owner cannot set customer-only viewing statuses';
    end if;
    if new.scheduled_at is distinct from old.scheduled_at then
      raise exception 'Owner must propose another time instead of changing the requested time';
    end if;

  elsif private.is_staff() then
    if new.customer_note is distinct from old.customer_note
       or new.customer_name is distinct from old.customer_name
       or new.customer_phone is distinct from old.customer_phone
       or new.customer_proposed_at is distinct from old.customer_proposed_at
       or new.owner_proposed_at is distinct from old.owner_proposed_at
       or new.cancelled_by is distinct from old.cancelled_by
       or new.cancellation_reason is distinct from old.cancellation_reason then
      raise exception 'Staff cannot edit customer contact fields or cancellation metadata';
    end if;
    if new.status not in ('owner_proposed','confirmed','completed','rejected') then
      raise exception 'Staff may only propose, confirm, complete or reject a viewing request';
    end if;
    if new.status = 'owner_proposed' then
      if new.owner_proposed_scheduled_at is null
         or new.scheduled_at is distinct from old.scheduled_at then
        raise exception 'Staff must propose an alternate time without changing the requested time';
      end if;
    elsif new.status = 'confirmed' then
      if old.status = 'owner_proposed' then
        if new.scheduled_at is distinct from old.owner_proposed_scheduled_at then
          raise exception 'The confirmed time must match the proposed time';
        end if;
      elsif new.scheduled_at is distinct from old.scheduled_at then
        raise exception 'Staff cannot change the requested time directly';
      end if;
    elsif new.status = 'completed' then
      if old.status <> 'confirmed' then
        raise exception 'Only confirmed viewings can be completed';
      end if;
    elsif new.status = 'rejected' then
      if new.scheduled_at is distinct from old.scheduled_at then
        raise exception 'Staff cannot change the requested time when rejecting';
      end if;
    end if;

  else
    raise exception 'Not a participant or authorized staff member';
  end if;

  new.updated_at := now();
  return new;
end;
$function$;

revoke all on function public.guard_viewing_request_participants() from public, anon, authenticated;
