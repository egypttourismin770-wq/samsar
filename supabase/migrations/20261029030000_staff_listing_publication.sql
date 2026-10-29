-- Separate staff listing publication from admin-only workflows.
-- Staff can publish only reviewed, non-demo listings whose owner fee is paid/waived.
create or replace function public.guard_property_workflow()
returns trigger
language plpgsql
security definer
set search_path to 'public', 'private', 'pg_temp'
as $function$
declare
  staff_can_review boolean := private.has_staff_permission('listings_review');
  staff_can_operate boolean := private.has_staff_permission('operations');
  valid_staff_publish boolean;
begin
  if public.is_admin() then
    new.updated_at := now();
    return new;
  end if;

  valid_staff_publish :=
    staff_can_review
    and old.status = 'pending_review'::public.property_status
    and new.status = 'published'::public.property_status
    and old.owner_fee_status in ('paid', 'waived')
    and new.owner_fee_status = old.owner_fee_status
    and new.published_at is not null
    and new.verified_at is not null
    and new.rejection_reason is null
    and not old.is_demo
    and not new.is_demo;

  if new.status is distinct from old.status and not (staff_can_review or staff_can_operate) then
    raise exception 'Only authorized listing staff/admin may change listing status';
  end if;

  if new.owner_fee_status is distinct from old.owner_fee_status then
    raise exception 'Only payment/admin workflows may change owner fee status';
  end if;

  if new.verified_at is distinct from old.verified_at
     or new.rejection_reason is distinct from old.rejection_reason
     or new.published_at is distinct from old.published_at then
    if not valid_staff_publish then
      raise exception 'Only an authorized listing reviewer may publish a paid listing from review';
    end if;
  end if;

  if staff_can_review or staff_can_operate then
    if valid_staff_publish then
      if (to_jsonb(new) - ARRAY['status','published_at','verified_at','rejection_reason','updated_at'])
         is distinct from
         (to_jsonb(old) - ARRAY['status','published_at','verified_at','rejection_reason','updated_at']) then
        raise exception 'Staff may only update listing status during publication';
      end if;
    else
      if new.status = 'published'::public.property_status then
        raise exception 'Publishing requires listing review permission and a paid listing in review';
      end if;
      if (to_jsonb(new) - ARRAY['status','updated_at'])
         is distinct from
         (to_jsonb(old) - ARRAY['status','updated_at']) then
        raise exception 'Staff may only update listing status';
      end if;
    end if;
  end if;

  new.updated_at := now();
  return new;
end;
$function$;

create or replace function public.publish_listing_by_staff(p_property_id uuid)
returns void
language plpgsql
security definer
set search_path to 'public', 'private', 'pg_temp'
as $function$
declare
  target public.properties%rowtype;
begin
  if auth.uid() is null
     or not exists (
       select 1 from public.profiles p
       where p.id = auth.uid()
         and p.role = 'staff'::public.app_role
     )
     or not private.has_staff_permission('listings_review') then
    raise exception 'Only staff with listing review permission may publish listings';
  end if;

  select * into target
  from public.properties
  where id = p_property_id
  for update;

  if not found then
    raise exception 'Listing not found';
  end if;
  if target.is_demo then
    raise exception 'Demo listings cannot be published';
  end if;
  if target.status <> 'pending_review'::public.property_status then
    raise exception 'Only listings in review can be published';
  end if;
  if target.owner_fee_status not in ('paid', 'waived') then
    raise exception 'The listing fee must be approved before publication';
  end if;

  update public.properties
  set status = 'published'::public.property_status,
      published_at = now(),
      verified_at = now(),
      rejection_reason = null,
      updated_at = now()
  where id = p_property_id;
end;
$function$;

revoke all on function public.publish_listing_by_staff(uuid) from public, anon;
grant execute on function public.publish_listing_by_staff(uuid) to authenticated;
