-- TESOURARIA DHG — banco de dados (Supabase). Cole tudo no SQL Editor e clique em Run.

-- 1) PERFIS: um por usuário. O primeiro cadastro vira administrador; os demais ficam pendentes até o admin aprovar.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  name text not null,
  is_admin boolean not null default false,
  approved boolean not null default false,
  created_at timestamptz not null default now()
);

-- 2) MOVIMENTAÇÕES: caixa compartilhado por todos os usuários aprovados.
create table if not exists public.movements (
  id bigint generated always as identity primary key,
  created_by uuid default auth.uid() references public.profiles(id) on delete set null,
  type text not null check (type in ('entrada','saida')),
  description text not null check (length(trim(description)) > 0),
  amount numeric(12,2) not null check (amount > 0),
  category text not null default 'Outros',
  date date not null,
  requester_name text,
  requester_role text,
  receipt_code text unique,
  created_at timestamptz not null default now(),
  constraint saida_exige_solicitante check (
    type = 'entrada' or (
      requester_name is not null and length(trim(requester_name)) > 0 and
      requester_role in ('Presidente','Vice-presidente','Secretário-geral','1° secretário','Tesoureiro-geral','1° tesoureiro','Dir. Social','V. Dir. Social','Dir. De imprensa','V. Dir. Imprensa','Dir. De esportes','V. Dir. Esportes','Dir. De cultura','V. Dir. Cultural','Dir. De saúde e meio ambiente','V. Dir. De saúde e meio ambiente','Dir. Da mulher','V. Dir. Da mulher','Dir. De proteção a diversidade','V. Dir. De proteção à diversidade')
    )
  )
);
create index if not exists idx_movements_date on public.movements(date desc, id desc);

-- 3) FUNÇÕES AUXILIARES
create or replace function public.is_approved() returns boolean
language sql security definer stable set search_path = public as
$$ select coalesce((select approved from public.profiles where id = auth.uid()), false) $$;

create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as
$$ select coalesce((select is_admin and approved from public.profiles where id = auth.uid()), false) $$;

-- 4) NOVO USUÁRIO: só aceita Gmail e cria o perfil (o primeiro vira admin)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare primeiro boolean;
begin
  if lower(new.email) !~ '^[^@\s]+@(gmail|googlemail)\.com$' then
    raise exception 'Use um endereço Gmail';
  end if;
  select not exists (select 1 from public.profiles) into primeiro;
  insert into public.profiles (id, email, name, is_admin, approved)
  values (new.id, lower(new.email),
          coalesce(nullif(trim(new.raw_user_meta_data->>'name'), ''), split_part(new.email, '@', 1)),
          primeiro, primeiro);
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 5) CÓDIGO DO RECIBO (gerado no banco, só para saídas)
create or replace function public.set_receipt() returns trigger
language plpgsql as $$
begin
  if new.type = 'saida' then
    new.receipt_code := 'REC-' || to_char(now(), 'YYYY') || '-' || upper(substr(md5(random()::text || clock_timestamp()::text), 1, 8));
  else
    new.receipt_code := null;
  end if;
  return new;
end $$;

drop trigger if exists movements_receipt on public.movements;
create trigger movements_receipt before insert on public.movements
  for each row execute function public.set_receipt();

-- 6) PROTEÇÃO: ninguém altera a própria permissão nem o e-mail
create or replace function public.guard_profile_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null then
    if new.id <> old.id or new.email <> old.email then
      raise exception 'Alteração não permitida.';
    end if;
    if old.id = auth.uid() and (new.is_admin is distinct from old.is_admin or new.approved is distinct from old.approved) then
      raise exception 'Você não pode alterar a própria permissão.';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists guard_profile on public.profiles;
create trigger guard_profile before update on public.profiles
  for each row execute function public.guard_profile_update();

-- 7) REGRAS DE ACESSO (RLS): só usuários aprovados enxergam e registram
alter table public.profiles enable row level security;
alter table public.movements enable row level security;

drop policy if exists profiles_select on public.profiles;
drop policy if exists profiles_update on public.profiles;
drop policy if exists mov_select on public.movements;
drop policy if exists mov_insert on public.movements;
drop policy if exists mov_delete on public.movements;

create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_approved());
create policy profiles_update on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

create policy mov_select on public.movements for select to authenticated
  using (public.is_approved());
create policy mov_insert on public.movements for insert to authenticated
  with check (public.is_approved() and created_by = auth.uid());
create policy mov_delete on public.movements for delete to authenticated
  using (public.is_approved() and (public.is_admin() or created_by = auth.uid()));
