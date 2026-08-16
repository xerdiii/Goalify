-- ============================================================================
-- GOALIFY · PRIVILEGE HARDENING (2026-08)
-- ============================================================================
-- Closes a privilege-escalation + paywall-bypass chain.
--
-- BEFORE this migration:
--   profiles_update_own_or_admin allows a user to UPDATE their own row with no
--   column restriction, and `plan` + `role` live on that row. So any signed-up
--   user could run, straight from the browser console:
--
--       sb.from('profiles').update({ plan: 'business' }).eq('id', myId)  -- free Business
--       sb.from('profiles').update({ role: 'admin'    }).eq('id', myId)  -- becomes admin
--
--   The second one is the serious one: is_admin() reads role from this same
--   table, so self-promoting to admin then grants SELECT/UPDATE on EVERY other
--   profile row — including email, dob and monthly_income.
--
-- AFTER: `plan` and `role` are immutable to normal clients. They can only be
-- changed by the service role (Paddle webhook, admin tooling) or by the
-- redeem_promo() RPC below, which enforces redemption rules in the database.
--
-- Safe to run more than once.
-- ============================================================================

begin;

-- ── 1 ── freeze privileged columns against client writes ────────────────────
create or replace function public.protect_profile_privileges()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  jwt_role text := coalesce(
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role',
    ''
  );
begin
  -- Server-side callers (service_role key) may change anything.
  if jwt_role = 'service_role' then
    return new;
  end if;

  -- Trusted SECURITY DEFINER routines opt in via a transaction-local flag.
  -- PostgREST exposes no way for a client to set this itself.
  if coalesce(current_setting('app.privileged_write', true), '') = 'on' then
    return new;
  end if;

  -- Everyone else: silently keep the old values. Using assignment rather than
  -- raising keeps unrelated profile saves (name, bio, theme…) working even
  -- when the client echoes back a full row that happens to include plan/role.
  new.plan := old.plan;
  new.role := old.role;
  return new;
end;
$$;

revoke all on function public.protect_profile_privileges() from public, anon, authenticated;

drop trigger if exists profiles_protect_privileges on public.profiles;
create trigger profiles_protect_privileges
  before update on public.profiles
  for each row
  execute function public.protect_profile_privileges();

-- ── 2 ── server-owned promo codes (replaces the hardcoded client list) ──────
create table if not exists public.promo_codes (
  code       text primary key,
  plan       text not null check (plan in ('pro','premium','business')),
  max_uses   integer,                      -- null = unlimited
  uses       integer not null default 0 check (uses >= 0),
  expires_at timestamptz,                  -- null = never expires
  active     boolean not null default true,
  created_at timestamptz not null default now()
);
alter table public.promo_codes enable row level security;
-- No policies: the table is unreadable to clients. Only the SECURITY DEFINER
-- RPC below (and the service role) can see it, so codes never reach the browser.

create table if not exists public.promo_redemptions (
  user_id     uuid not null references auth.users(id) on delete cascade,
  code        text not null references public.promo_codes(code) on delete cascade,
  plan        text not null,
  redeemed_at timestamptz not null default now(),
  primary key (user_id, code)
);
alter table public.promo_redemptions enable row level security;

drop policy if exists promo_redemptions_select_own on public.promo_redemptions;
create policy promo_redemptions_select_own on public.promo_redemptions
  for select using (auth.uid() = user_id or public.is_admin());

-- ── 3 ── redemption RPC: all validation happens in the database ─────────────
create or replace function public.redeem_promo(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user uuid := auth.uid();
  v_code public.promo_codes%rowtype;
  v_current_plan text;
  v_rank_new int;
  v_rank_cur int;
begin
  if v_user is null then
    return jsonb_build_object('ok', false, 'error', 'Not signed in.');
  end if;

  -- Lock the row so concurrent redemptions can't race past max_uses.
  select * into v_code
  from public.promo_codes
  where code = upper(btrim(p_code))
  for update;

  if not found or not v_code.active
     or (v_code.expires_at is not null and v_code.expires_at < now())
     or (v_code.max_uses  is not null and v_code.uses >= v_code.max_uses) then
    return jsonb_build_object('ok', false, 'error', 'Invalid or expired code.');
  end if;

  if exists (select 1 from public.promo_redemptions
             where user_id = v_user and code = v_code.code) then
    return jsonb_build_object('ok', false, 'error', 'You have already used this code.');
  end if;

  -- Never downgrade someone who already pays for a higher tier.
  select plan into v_current_plan from public.profiles where id = v_user;
  v_rank_new := array_position(array['free','pro','premium','business'], v_code.plan);
  v_rank_cur := array_position(array['free','pro','premium','business'], coalesce(v_current_plan,'free'));
  if v_rank_cur >= v_rank_new then
    return jsonb_build_object('ok', false, 'error', 'Your current plan is already equal or better.');
  end if;

  insert into public.promo_redemptions(user_id, code, plan)
  values (v_user, v_code.code, v_code.plan);

  update public.promo_codes set uses = uses + 1 where code = v_code.code;

  -- Opt through the privilege trigger for this statement only.
  perform set_config('app.privileged_write', 'on', true);
  update public.profiles
     set plan = v_code.plan, updated_at = now()
   where id = v_user;
  perform set_config('app.privileged_write', 'off', true);

  return jsonb_build_object('ok', true, 'plan', v_code.plan);
end;
$$;

revoke all on function public.redeem_promo(text) from public, anon;
grant execute on function public.redeem_promo(text) to authenticated;

-- ── 4 ── seed the codes that were previously hardcoded in app.js ────────────
-- They were public in the page source, so treat them as burned: single-use each
-- and inactive by default. Flip `active` / issue fresh codes from the dashboard.
insert into public.promo_codes (code, plan, max_uses, active) values
  ('FORESTPRO2026-FP2-PRP',     'pro',      1, false),
  ('FORESTPREMIUM2026-FP6-PP',  'premium',  1, false),
  ('FORESTBUSINESS2026-FB2-BP', 'business', 1, false)
on conflict (code) do nothing;

-- ── 5 ── keep the legitimate admin plan-writes working ─────────────────────
-- These are SECURITY DEFINER and is_admin()-guarded, but they run under the
-- calling admin's JWT (role 'authenticated'), so the trigger above would
-- silently discard their writes. They opt in through the same flag.
create or replace function public.approve_student(p_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare v_user uuid;
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  update public.student_verifications
     set status='approved', reviewed_by=auth.uid(),
         free_pro_until = now() + interval '2 years'
   where id=p_id returning user_id into v_user;

  perform set_config('app.privileged_write', 'on', true);
  update public.profiles set plan='pro', updated_at=now() where id=v_user;
  perform set_config('app.privileged_write', 'off', true);

  insert into public.subscriptions(user_id, plan, status, is_student, current_period_end)
    values (v_user, 'pro', 'student', true, now() + interval '2 years');
end; $$;

create or replace function public.admin_set_plan(p_user uuid, p_plan text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'not authorized'; end if;
  if p_plan not in ('free','pro','premium','business') then
    raise exception 'invalid plan';
  end if;

  perform set_config('app.privileged_write', 'on', true);
  update public.profiles set plan=p_plan, updated_at=now() where id=p_user;
  perform set_config('app.privileged_write', 'off', true);
end; $$;

-- ── 6 ── cap award_xp (it trusted any client-supplied amount) ───────────────
-- Unlike credit_coins, award_xp took p_amount straight from the browser, so
-- sb.rpc('award_xp',{p_amount:999999}) jumped instantly to level 100 and
-- unlocked every cosmetic frame. Largest legitimate single award is 150
-- (the 'Save €100 in 14 Days' challenge), so 200/call is generous headroom.
create table if not exists public.xp_ledger (
  id         bigserial primary key,
  user_id    uuid not null references auth.users(id) on delete cascade,
  delta      integer not null,
  created_at timestamptz not null default now()
);
alter table public.xp_ledger enable row level security;
create index if not exists xp_ledger_user_day_idx on public.xp_ledger(user_id, created_at);

drop policy if exists xp_ledger_select_own on public.xp_ledger;
create policy xp_ledger_select_own on public.xp_ledger
  for select using (auth.uid() = user_id or public.is_admin());
-- No insert/update/delete policies: only award_xp() (SECURITY DEFINER) writes here.

create or replace function public.award_xp(p_amount integer)
returns void language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  amt int;
  today_total int;
begin
  if uid is null then raise exception 'not authenticated'; end if;

  amt := least(greatest(coalesce(p_amount, 0), 0), 200);   -- clamp per call
  if amt = 0 then return; end if;

  select coalesce(sum(delta),0) into today_total
    from public.xp_ledger where user_id = uid and created_at::date = current_date;
  if today_total >= 600 then return; end if;                -- daily ceiling
  amt := least(amt, 600 - today_total);

  insert into public.xp_ledger(user_id, delta) values (uid, amt);

  update public.profiles
     set xp    = greatest(0, xp + amt),
         level = greatest(1, floor(greatest(0, xp + amt) / 100.0)::int + 1),
         updated_at = now()
   where id = uid;
end; $$;

revoke execute on function public.award_xp(integer) from public, anon;
grant  execute on function public.award_xp(integer) to authenticated;

-- ── 7 ── prestige: the Level-100 gate was checked only in the browser ───────
create or replace function public.prestige_up()
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  v_xp int;
  v_prestige int;
begin
  if uid is null then raise exception 'not authenticated'; end if;

  select xp, prestige into v_xp, v_prestige from public.profiles where id = uid;
  -- level = floor(xp/100)+1, so Level 100 means at least 9900 XP.
  if coalesce(v_xp,0) < 9900 then
    return jsonb_build_object('ok', false, 'error', 'Reach Level 100 to prestige.');
  end if;

  update public.profiles
     set prestige = coalesce(prestige,0) + 1, xp = 0, level = 1,
         prestige_at = now(), updated_at = now()
   where id = uid;

  return jsonb_build_object('ok', true, 'prestige', coalesce(v_prestige,0) + 1);
end; $$;

revoke execute on function public.prestige_up() from public, anon;
grant  execute on function public.prestige_up() to authenticated;

commit;

-- ============================================================================
-- VERIFY (run as a normal signed-in user; both should be no-ops)
--   update public.profiles set role = 'admin'    where id = auth.uid();
--   update public.profiles set plan = 'business' where id = auth.uid();
--   select plan, role from public.profiles where id = auth.uid();
--
-- GRANT YOURSELF ADMIN (SQL editor runs as a superuser, so the trigger's
-- service_role branch does not apply — set the flag explicitly):
--   select set_config('app.privileged_write','on',true);
--   update public.profiles set role = 'admin' where email = 'you@example.com';
-- ============================================================================
