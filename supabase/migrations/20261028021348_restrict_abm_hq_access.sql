-- Keep ABM target access within their assigned HQs. Admin remains global;
-- field users retain their existing assigned-HQ data policies and cannot
-- access target data through these policies.
drop policy if exists targets_select_admin_abm on public.targets;
drop policy if exists targets_insert_admin_abm on public.targets;
drop policy if exists targets_update_admin_abm on public.targets;
drop policy if exists targets_delete_admin on public.targets;

create policy targets_select_admin_assigned_abm
on public.targets for select to authenticated
using (
  exists (
    select 1 from public.user_profiles p
    where p.id = (select auth.uid())
      and p.active = true
      and (
        p.role = 'Admin'
        or (p.role = 'ABM' and (select public.is_assigned_hq(targets.hq_id)))
      )
  )
);

create policy targets_write_admin_assigned_abm
on public.targets for all to authenticated
using (
  exists (
    select 1 from public.user_profiles p
    where p.id = (select auth.uid())
      and p.active = true
      and (
        p.role = 'Admin'
        or (p.role = 'ABM' and (select public.is_assigned_hq(targets.hq_id)))
      )
  )
)
with check (
  exists (
    select 1 from public.user_profiles p
    where p.id = (select auth.uid())
      and p.active = true
      and (
        p.role = 'Admin'
        or (p.role = 'ABM' and (select public.is_assigned_hq(targets.hq_id)))
      )
  )
);

drop policy if exists "hq monthly targets read assigned hqs" on public.hq_monthly_targets;
drop policy if exists "hq monthly targets write admin abm" on public.hq_monthly_targets;

create policy hq_monthly_targets_select_admin_assigned_abm
on public.hq_monthly_targets for select to authenticated
using (
  exists (
    select 1 from public.user_profiles p
    where p.id = (select auth.uid())
      and p.active = true
      and (
        p.role = 'Admin'
        or (p.role = 'ABM' and (select public.is_assigned_hq(hq_monthly_targets.hq_id)))
      )
  )
);

create policy hq_monthly_targets_write_admin_assigned_abm
on public.hq_monthly_targets for all to authenticated
using (
  exists (
    select 1 from public.user_profiles p
    where p.id = (select auth.uid())
      and p.active = true
      and (
        p.role = 'Admin'
        or (p.role = 'ABM' and (select public.is_assigned_hq(hq_monthly_targets.hq_id)))
      )
  )
)
with check (
  exists (
    select 1 from public.user_profiles p
    where p.id = (select auth.uid())
      and p.active = true
      and (
        p.role = 'Admin'
        or (p.role = 'ABM' and (select public.is_assigned_hq(hq_monthly_targets.hq_id)))
      )
  )
);

-- Let an ABM review sales submitted by field users inside assigned HQs.
-- Field-user SELECT behavior and all sales write policies remain unchanged.
drop policy if exists sales_entry_header_select on public.sales_entry_header;
create policy sales_entry_header_select
on public.sales_entry_header for select to authenticated
using (
  (select public.is_admin())
  or exists (
    select 1 from public.user_profiles p
    where p.id = (select auth.uid())
      and p.active = true
      and (
        (p.role = 'ABM' and (select public.is_assigned_hq(sales_entry_header.hq_id)))
        or (p.role <> 'ABM' and sales_entry_header.entered_by = (select auth.uid()))
      )
  )
);

drop policy if exists sales_entry_details_select on public.sales_entry_details;
create policy sales_entry_details_select
on public.sales_entry_details for select to authenticated
using (
  (select public.is_admin())
  or exists (
    select 1 from public.sales_entry_header h
    where h.id = sales_entry_details.entry_id
      and (
        exists (
          select 1 from public.user_profiles p
          where p.id = (select auth.uid())
            and p.active = true
            and (
              (p.role = 'ABM' and (select public.is_assigned_hq(h.hq_id)))
              or (p.role <> 'ABM' and h.entered_by = (select auth.uid()))
            )
        )
      )
  )
);

-- One row per user/HQ pair, so an assignment set can be updated safely.
create unique index if not exists user_hq_mapping_user_hq_uidx
  on public.user_hq_mapping (user_id, hq_id);

-- Invoker rights retain the caller's RLS context. Admin-only authorization is
-- checked inside the function, and the existing mapping policies remain active.
create or replace function public.set_user_hq_assignments(
  p_user_id uuid,
  p_hq_ids uuid[]
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare
  v_hq_ids uuid[];
  v_role text;
  v_valid_count integer;
begin
  if auth.uid() is null or not public.is_admin() then
    raise exception 'Administrator permission is required.' using errcode = '42501';
  end if;

  select p.role into v_role
  from public.user_profiles p
  where p.id = p_user_id;

  if not found then
    raise exception 'User profile was not found.' using errcode = '22023';
  end if;

  select coalesce(array_agg(distinct x.hq_id order by x.hq_id), array[]::uuid[])
  into v_hq_ids
  from unnest(coalesce(p_hq_ids, array[]::uuid[])) as x(hq_id)
  where x.hq_id is not null;

  if v_role = 'ABM' and cardinality(v_hq_ids) = 0 then
    raise exception 'Assign at least one HQ to an ABM.' using errcode = '22023';
  elsif v_role = 'Field Staff' and cardinality(v_hq_ids) <> 1 then
    raise exception 'Field Staff must have exactly one assigned HQ.' using errcode = '22023';
  elsif v_role not in ('Admin', 'ABM', 'Field Staff') then
    raise exception 'Unsupported user role.' using errcode = '22023';
  end if;

  select count(*) into v_valid_count
  from public.hqs h
  where h.id = any(v_hq_ids) and h.active = true;

  if v_valid_count <> cardinality(v_hq_ids) then
    raise exception 'Every assigned HQ must exist and be active.' using errcode = '22023';
  end if;

  delete from public.user_hq_mapping m
  where m.user_id = p_user_id
    and not (m.hq_id = any(v_hq_ids));

  insert into public.user_hq_mapping (user_id, hq_id)
  select p_user_id, x.hq_id
  from unnest(v_hq_ids) as x(hq_id)
  on conflict (user_id, hq_id) do nothing;
end;
$$;

revoke execute on function public.set_user_hq_assignments(uuid, uuid[]) from public, anon;
grant execute on function public.set_user_hq_assignments(uuid, uuid[]) to authenticated;
