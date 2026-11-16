-- Vibe Fit shared store: accounts, one row per account per day, competition chat.

create table public.vf_admins (
  key text primary key
);
insert into public.vf_admins (key) values ('kemo fit');

create table public.accounts (
  id          text primary key check (char_length(id) between 2 and 40),
  user_id     uuid not null unique references auth.users (id) on delete cascade,
  key         text not null unique check (char_length(key) between 1 and 30),
  username    text not null check (char_length(username) between 1 and 30),
  created_at  bigint not null default ((extract(epoch from now()) * 1000)::bigint),
  profile     jsonb not null default '{}'::jsonb check (octet_length(profile::text) < 20000),
  pages       jsonb not null default '[]'::jsonb check (octet_length(pages::text) < 400000),
  plan        jsonb check (plan is null or octet_length(plan::text) < 400000),
  updated_at  timestamptz not null default now()
);

create table public.days (
  id          text primary key,
  acc         text not null references public.accounts (id) on delete cascade,
  user_id     uuid not null default auth.uid() references auth.users (id) on delete cascade,
  date        date not null,
  logs        jsonb not null default '[]'::jsonb check (octet_length(logs::text) < 400000),
  cardio      jsonb not null default '[]'::jsonb check (octet_length(cardio::text) < 100000),
  meals       jsonb not null default '[]'::jsonb check (octet_length(meals::text) < 100000),
  updated_at  timestamptz not null default now(),
  constraint days_id_matches check (id = acc || '_' || to_char(date, 'YYYY-MM-DD'))
);
create index days_date_idx on public.days (date);
create index days_acc_idx on public.days (acc);
create index days_user_idx on public.days (user_id);

create table public.chat (
  id          text primary key check (char_length(id) between 1 and 64),
  acc         text not null,
  user_id     uuid references auth.users (id) on delete set null,
  name        text not null default '',
  text        text not null check (char_length(text) between 1 and 500),
  ts          bigint not null default ((extract(epoch from clock_timestamp()) * 1000)::bigint),
  kind        text not null default 'msg' check (kind in ('msg', 'event'))
);
create index chat_ts_idx on public.chat (ts desc);
create index chat_user_idx on public.chat (user_id);

-- ---------- helpers ----------
create or replace function public.vf_touch() returns trigger
language plpgsql set search_path = '' as $$
begin
  new.updated_at := now();
  return new;
end $$;
create trigger accounts_touch before update on public.accounts for each row execute function public.vf_touch();
create trigger days_touch before update on public.days for each row execute function public.vf_touch();

create or replace function public.vf_my_acc() returns text
language sql stable security definer set search_path = '' as $$
  select id from public.accounts where user_id = auth.uid();
$$;

create or replace function public.vf_is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.accounts a join public.vf_admins x on x.key = a.key
    where a.user_id = auth.uid()
  );
$$;

-- Chat: the server stamps who sent it and when, so nobody can post as someone else.
create or replace function public.vf_chat_fill() returns trigger
language plpgsql security definer set search_path = '' as $$
declare a record;
begin
  select id, username into a from public.accounts where user_id = auth.uid();
  if a.id is null then
    raise exception 'no account for this user' using errcode = '42501';
  end if;
  new.user_id := auth.uid();
  new.acc := a.id;
  new.name := a.username;
  new.ts := (extract(epoch from clock_timestamp()) * 1000)::bigint;
  if new.kind is null or new.kind not in ('msg', 'event') then new.kind := 'msg'; end if;
  return new;
end $$;
create trigger chat_fill before insert on public.chat for each row execute function public.vf_chat_fill();

-- Keep the chat bounded to the newest 150 messages (the window every phone shows).
create or replace function public.vf_chat_prune() returns trigger
language plpgsql security definer set search_path = '' as $$
declare cut bigint;
begin
  select ts into cut from public.chat order by ts desc, id desc offset 149 limit 1;
  if cut is not null then
    delete from public.chat where ts < cut;
  end if;
  return null;
end $$;
create trigger chat_prune after insert on public.chat for each statement execute function public.vf_chat_prune();

-- ---------- admin & sign-in helpers ----------
create or replace function public.vf_admin_delete_account(target text) returns void
language plpgsql security definer set search_path = '' as $$
declare t uuid;
begin
  if not public.vf_is_admin() then
    raise exception 'admin only' using errcode = '42501';
  end if;
  select user_id into t from public.accounts where id = target;
  if t is null then return; end if;
  if t = auth.uid() then
    raise exception 'the admin account cannot delete itself' using errcode = '42501';
  end if;
  delete from auth.users where id = t;   -- cascades to accounts and days
end $$;

create or replace function public.vf_admin_clear_chat() returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.vf_is_admin() then
    raise exception 'admin only' using errcode = '42501';
  end if;
  delete from public.chat where true;
end $$;

-- Lets the sign-in form tell "no such user" apart from "wrong password".
create or replace function public.vf_name_exists(k text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.accounts where key = k);
$$;

-- ---------- privileges ----------
revoke all on public.vf_admins, public.accounts, public.days, public.chat from anon, authenticated;
grant select on public.accounts to authenticated;
grant update (profile, pages, plan) on public.accounts to authenticated;
grant select, delete on public.days to authenticated;
grant insert (id, acc, date, logs, cardio, meals), update (id, acc, date, logs, cardio, meals) on public.days to authenticated;
grant select, delete on public.chat to authenticated;
grant insert (id, text, kind) on public.chat to authenticated;

revoke all on function public.vf_touch() from public, anon, authenticated;
revoke all on function public.vf_chat_fill() from public, anon, authenticated;
revoke all on function public.vf_chat_prune() from public, anon, authenticated;
revoke all on function public.vf_my_acc() from public, anon;
revoke all on function public.vf_is_admin() from public, anon;
revoke all on function public.vf_admin_delete_account(text) from public, anon;
revoke all on function public.vf_admin_clear_chat() from public, anon;
revoke all on function public.vf_name_exists(text) from public;
grant execute on function public.vf_my_acc() to authenticated;
grant execute on function public.vf_is_admin() to authenticated;
grant execute on function public.vf_admin_delete_account(text) to authenticated;
grant execute on function public.vf_admin_clear_chat() to authenticated;
grant execute on function public.vf_name_exists(text) to anon, authenticated;

-- ---------- row level security ----------
alter table public.vf_admins enable row level security;
alter table public.accounts enable row level security;
alter table public.days enable row level security;
alter table public.chat enable row level security;

create policy "members read accounts" on public.accounts for select to authenticated using (true);
create policy "owner updates own account" on public.accounts for update to authenticated
  using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

create policy "members read days" on public.days for select to authenticated using (true);
create policy "owner adds own days" on public.days for insert to authenticated
  with check (user_id = (select auth.uid()) and acc = (select public.vf_my_acc()));
create policy "owner updates own days" on public.days for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()) and acc = (select public.vf_my_acc()));
create policy "owner deletes own days" on public.days for delete to authenticated
  using (user_id = (select auth.uid()));

create policy "members read chat" on public.chat for select to authenticated using (true);
create policy "members post as themselves" on public.chat for insert to authenticated
  with check (user_id = (select auth.uid()) and acc = (select public.vf_my_acc()));
create policy "admin deletes messages" on public.chat for delete to authenticated
  using ((select public.vf_is_admin()));

-- ---------- live updates ----------
alter publication supabase_realtime add table public.accounts, public.days, public.chat;
