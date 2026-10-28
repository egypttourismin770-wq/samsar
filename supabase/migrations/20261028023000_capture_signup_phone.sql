-- Keep the optional phone collected at sign-up in the user's own profile.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $function$
begin
  insert into public.profiles (id, full_name, phone, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name'),
    coalesce(new.phone, nullif(trim(new.raw_user_meta_data->>'phone'), '')),
    'customer'
  )
  on conflict (id) do nothing;
  return new;
end;
$function$;
