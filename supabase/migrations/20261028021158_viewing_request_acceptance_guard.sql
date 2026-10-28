-- Samsar: restrict owner-created rows to unverified, unpaid drafts.
-- Also enforce a safe owner-proposed viewing slot workflow.

create or replace function public.guard_viewing_request_participants()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $function$
begin
  if not public.is_admin() then
    if new.customer_id is distinct from old.customer_id
       or new.owner_id is distinct from old.owner_id
       or new.property_id is distinct from old.property_id then
      raise exception 'Participants and property cannot be changed after a viewing request is created';
    end if;

    if auth.uid() = old.customer_id then
      if new.owner_note is distinct from old.owner_note
         or new.owner_proposed_scheduled_at is distinct from old.owner_proposed_scheduled_at then
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
         or new.status = 'customer_proposed' then
        raise exception 'Owner cannot set customer-only fields or statuses';
      end if;

      if new.scheduled_at is distinct from old.scheduled_at then
        raise exception 'Owner must propose another time instead of changing the requested time';
      end if;

    else
      raise exception 'Not a participant in this viewing request';
    end if;
  end if;

  new.updated_at := now();
  return new;
end;
$function$;

revoke all on function public.guard_viewing_request_participants() from public, anon, authenticated;
