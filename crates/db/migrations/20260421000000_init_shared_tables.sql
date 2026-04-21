-- Shared FerrLabs schema: users, organizations, memberships, billing.
-- Product-specific tables (releases, secrets, etc.) live in each Cloud API.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email             TEXT NOT NULL UNIQUE,
    password_hash     TEXT,
    name              TEXT,
    email_verified_at TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organizations (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE memberships (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    ferrflow_role   TEXT CHECK (ferrflow_role IN ('owner', 'admin', 'member', 'viewer')),
    ferrvault_role  TEXT CHECK (ferrvault_role IN ('owner', 'admin', 'member', 'viewer')),
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, organization_id)
);

CREATE TABLE subscriptions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    product         TEXT NOT NULL CHECK (product IN ('ferrflow', 'ferrvault')),
    plan            TEXT NOT NULL CHECK (plan IN ('free', 'team', 'business', 'enterprise')),
    stripe_sub_id   TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    seats           INTEGER NOT NULL DEFAULT 1,
    current_period_end TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, product)
);

CREATE INDEX idx_memberships_user ON memberships(user_id);
CREATE INDEX idx_memberships_org ON memberships(organization_id);
CREATE INDEX idx_subscriptions_org ON subscriptions(organization_id);
