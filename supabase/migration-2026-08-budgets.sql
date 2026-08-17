-- ============================================================================
-- GOALIFY · CATEGORY BUDGETS (2026-08)
-- ============================================================================
-- Monthly spending caps per category, e.g. {"restaurants": 120, "shopping": 80}.
--
-- Stored on the profile rather than a separate table: it is a small, bounded
-- map that is always read together with the profile, and it inherits the
-- existing owner-only RLS for free. The privilege trigger from
-- migration-2026-08-plan-security.sql only freezes plan/role, so owners can
-- write this column normally.
--
-- Free-tier ceilings are enforced in the UI (caps().budgetLimit). Budgets are
-- a planning aid, not a paid entitlement that costs anything to serve, so there
-- is deliberately no server-side count check here.
--
-- Safe to run more than once.
-- ============================================================================

begin;

alter table public.profiles
  add column if not exists budgets jsonb not null default '{}'::jsonb;

-- keep it an object, and small enough that it can never be used as a blob store
alter table public.profiles drop constraint if exists profiles_budgets_shape;
alter table public.profiles add constraint profiles_budgets_shape
  check (jsonb_typeof(budgets) = 'object' and length(budgets::text) <= 2000);

commit;

-- ============================================================================
-- VERIFY
--   select budgets from public.profiles where id = auth.uid();
--   update public.profiles set budgets = '{"restaurants": 120}'::jsonb
--     where id = auth.uid();          -- should succeed
--   update public.profiles set budgets = '"nope"'::jsonb
--     where id = auth.uid();          -- should fail the shape constraint
-- ============================================================================
