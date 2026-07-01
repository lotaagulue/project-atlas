-- Run this once in the Supabase SQL editor (Project > SQL Editor > New query).

create table if not exists targets (
    value text primary key,
    created_at timestamptz not null default now()
);

create table if not exists assets (
    id bigint generated always as identity primary key,
    target text not null,
    asset_type text not null,
    value text not null,
    source text not null,
    raw jsonb not null default '{}'::jsonb,
    fetched_at timestamptz not null default now(),
    unique (source, target, asset_type, value)
);

create table if not exists findings (
    id bigint generated always as identity primary key,
    indicator text not null,
    indicator_type text not null,
    verdict text not null,
    source text not null,
    raw jsonb not null default '{}'::jsonb,
    fetched_at timestamptz not null default now(),
    unique (source, indicator, indicator_type)
);

create index if not exists assets_target_idx on assets (target);
create index if not exists findings_indicator_idx on findings (indicator);
