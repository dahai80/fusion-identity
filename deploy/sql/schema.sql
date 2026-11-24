-- fusion_identity schema — tenant-identity service (multi-tenant-prd-0901 Appendix A.1)
-- Issue #26 (DB-2): fusion_identity is the single canonical database. The legacy
-- fusion_tenant name is retired; the CREATE is guarded so re-running against an
-- existing install does not fail.
--
-- Issue #105: this file is GENERATED from migrations/0001..0026 (pg_dump of a
-- migrations-only build) — DO NOT hand-edit. migrations/ is the single source
-- of truth for DDL; regenerate after adding a migration:
--   fresh PG -> run_migrations() -> pg_dump -s --no-owner --no-privileges
-- then re-append the SEED DATA block at the end (pg_dump --schema-only skips
-- data; roles + plan_templates seeds are mirrored from migrations 0001/0010).
-- Verified: a fresh DB built from this file + pre-marked schema_migrations
-- passes the full integration suite (tests/ -m integration).

SELECT 'CREATE DATABASE fusion_identity'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'fusion_identity')\gexec

\c fusion_identity

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: -
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: account_deletions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.account_deletions (
    user_id text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    purge_at timestamp with time zone NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL
);


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    key_id text NOT NULL,
    tenant_id text NOT NULL,
    user_id text,
    key_hash text NOT NULL,
    prefix text NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone
);

ALTER TABLE ONLY public.api_keys FORCE ROW LEVEL SECURITY;


--
-- Name: app_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_credentials (
    app_id text NOT NULL,
    name text NOT NULL,
    secret_enc text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    fetch_count bigint DEFAULT 0 NOT NULL,
    last_fetched_at timestamp with time zone
);


--
-- Name: app_secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_secrets (
    secret_id text NOT NULL,
    app_id text NOT NULL,
    version integer NOT NULL,
    secret_hash text NOT NULL,
    prefix text NOT NULL,
    status text NOT NULL,
    grace_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id bigint NOT NULL,
    seq bigint DEFAULT nextval('public.audit_seq_seq'::regclass) NOT NULL,
    tenant_id text NOT NULL,
    user_id text,
    jti text,
    role text,
    action text NOT NULL,
    resource text,
    detail jsonb,
    chain_hash text NOT NULL,
    prev_hash text DEFAULT ''::text NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.audit_log FORCE ROW LEVEL SECURITY;


--
-- Name: audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_log_id_seq OWNED BY public.audit_log.id;


--
-- Name: balance_ledger; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.balance_ledger (
    id bigint NOT NULL,
    tenant_id text NOT NULL,
    delta bigint NOT NULL,
    reason text NOT NULL,
    ref_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: balance_ledger_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.balance_ledger_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: balance_ledger_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.balance_ledger_id_seq OWNED BY public.balance_ledger.id;


--
-- Name: conversation_reads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conversation_reads (
    conversation_id text NOT NULL,
    user_id text NOT NULL,
    last_read_id bigint DEFAULT 0 NOT NULL
);


--
-- Name: conversations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.conversations (
    id text NOT NULL,
    tenant_id text NOT NULL,
    scope text DEFAULT 'factory_order'::text NOT NULL,
    ref text DEFAULT ''::text NOT NULL,
    subject text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'open'::text NOT NULL,
    linked_issue_id text DEFAULT ''::text NOT NULL,
    created_by text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: custom_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.custom_roles (
    role_id text NOT NULL,
    tenant_id text NOT NULL,
    display_name text NOT NULL,
    write_classes jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: departments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.departments (
    dept_id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id text NOT NULL,
    name text NOT NULL,
    parent_id uuid,
    tool_allowlist jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: event_outbox; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_outbox (
    event_id text NOT NULL,
    seq bigint NOT NULL,
    event_type text NOT NULL,
    tenant_id text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: event_outbox_seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_outbox_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_outbox_seq_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_outbox_seq_seq OWNED BY public.event_outbox.seq;


--
-- Name: idempotency_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.idempotency_keys (
    idem_key text NOT NULL,
    endpoint text NOT NULL,
    response jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: identity_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.identity_providers (
    idp_id text NOT NULL,
    tenant_id text NOT NULL,
    type text NOT NULL,
    issuer_url text,
    client_id text,
    client_secret_enc text,
    scopes text,
    auto_provision boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.identity_providers FORCE ROW LEVEL SECURITY;


--
-- Name: issued_jtis; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.issued_jtis (
    jti text NOT NULL,
    tenant_id text NOT NULL,
    user_id text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.issued_jtis FORCE ROW LEVEL SECURITY;


--
-- Name: join_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.join_requests (
    request_id text NOT NULL,
    tenant_id text NOT NULL,
    user_id text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    decided_by text,
    decided_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT join_requests_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'cancelled'::text])))
);


--
-- Name: known_menus; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.known_menus (
    tenant_id text NOT NULL,
    menu text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: lease_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lease_log (
    id bigint NOT NULL,
    tenant_id text NOT NULL,
    lease_id text NOT NULL,
    action text NOT NULL,
    reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT lease_action_chk CHECK ((action = ANY (ARRAY['acquire'::text, 'release'::text, 'expire'::text])))
);

ALTER TABLE ONLY public.lease_log FORCE ROW LEVEL SECURITY;


--
-- Name: lease_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lease_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lease_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lease_log_id_seq OWNED BY public.lease_log.id;


--
-- Name: messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages (
    id bigint NOT NULL,
    conversation_id text NOT NULL,
    tenant_id text NOT NULL,
    sender text NOT NULL,
    sender_role text NOT NULL,
    content text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT messages_sender_role_check CHECK ((sender_role = ANY (ARRAY['customer'::text, 'operator'::text, 'system'::text])))
);


--
-- Name: messages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: messages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.messages_id_seq OWNED BY public.messages.id;


--
-- Name: migration_orphans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.migration_orphans (
    id bigint NOT NULL,
    source_table text NOT NULL,
    source_pk text NOT NULL,
    reason text NOT NULL,
    detected_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: migration_orphans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.migration_orphans_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: migration_orphans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.migration_orphans_id_seq OWNED BY public.migration_orphans.id;


--
-- Name: plan_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.plan_templates (
    plan text NOT NULL,
    quota jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: prepaid_orders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.prepaid_orders (
    order_id text NOT NULL,
    tenant_id text NOT NULL,
    tokens bigint NOT NULL,
    promo_tokens bigint DEFAULT 0 NOT NULL,
    status text DEFAULT 'created'::text NOT NULL,
    provider text NOT NULL,
    provider_ref text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    paid_at timestamp with time zone,
    CONSTRAINT prepaid_orders_promo_tokens_check CHECK ((promo_tokens >= 0)),
    CONSTRAINT prepaid_orders_status_check CHECK ((status = ANY (ARRAY['created'::text, 'paid'::text, 'cancelled'::text]))),
    CONSTRAINT prepaid_orders_tokens_check CHECK ((tokens > 0))
);


--
-- Name: quotas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.quotas (
    tenant_id text NOT NULL,
    rpm integer DEFAULT 60 NOT NULL,
    tpm integer DEFAULT 100000 NOT NULL,
    concurrent integer DEFAULT 4 NOT NULL,
    storage_mb integer DEFAULT 10240 NOT NULL,
    allowed_models jsonb DEFAULT '[]'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    default_priority integer DEFAULT 0 NOT NULL,
    allowed_modules jsonb DEFAULT '[]'::jsonb NOT NULL
);

ALTER TABLE ONLY public.quotas FORCE ROW LEVEL SECURITY;


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    jti text NOT NULL,
    family_id text NOT NULL,
    tenant_id text NOT NULL,
    user_id text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    issued_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    replaced_by text,
    CONSTRAINT rt_status_chk CHECK ((status = ANY (ARRAY['active'::text, 'rotated'::text, 'revoked'::text])))
);

ALTER TABLE ONLY public.refresh_tokens FORCE ROW LEVEL SECURITY;


--
-- Name: revoked_jtis; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.revoked_jtis (
    jti text NOT NULL,
    tenant_id text NOT NULL,
    user_id text,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    reason text,
    expires_at timestamp with time zone NOT NULL
);

ALTER TABLE ONLY public.revoked_jtis FORCE ROW LEVEL SECURITY;


--
-- Name: role_menu_matrix; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_menu_matrix (
    tenant_id text NOT NULL,
    role_id text NOT NULL,
    menus jsonb DEFAULT '[]'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    role text NOT NULL,
    display_name text NOT NULL,
    permissions jsonb NOT NULL
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    version text NOT NULL,
    name text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: service_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.service_accounts (
    account_id text NOT NULL,
    tenant_id text NOT NULL,
    name text NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    cred_hash text NOT NULL,
    prefix text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    CONSTRAINT service_accounts_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])))
);


--
-- Name: sso_tickets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sso_tickets (
    ticket_hash text NOT NULL,
    user_id text NOT NULL,
    tenant_id text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tenant_invites; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_invites (
    invite_id text NOT NULL,
    tenant_id text NOT NULL,
    token_hash text NOT NULL,
    role text DEFAULT 'member'::text NOT NULL,
    email text,
    created_by text,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    used_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tenant_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_members (
    tenant_id text NOT NULL,
    user_id text NOT NULL,
    role text NOT NULL,
    added_by text,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.tenant_members FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_usage_daily; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_usage_daily (
    tenant_id text NOT NULL,
    bucket_day date NOT NULL,
    metric text NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    value bigint DEFAULT 0 NOT NULL
);

ALTER TABLE ONLY public.tenant_usage_daily FORCE ROW LEVEL SECURITY;


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    tenant_id text NOT NULL,
    display_name text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    plan text DEFAULT 'team'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    disabled_at timestamp with time zone,
    deleted_at timestamp with time zone,
    join_policy text DEFAULT 'invite'::text NOT NULL,
    CONSTRAINT tenants_status_chk CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text, 'deleted'::text])))
);

ALTER TABLE ONLY public.tenants FORCE ROW LEVEL SECURITY;


--
-- Name: usage_ledger; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_ledger (
    id bigint NOT NULL,
    tenant_id text NOT NULL,
    bucket_hour timestamp with time zone DEFAULT date_trunc('hour'::text, now()) NOT NULL,
    metric text NOT NULL,
    value bigint NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    model text,
    user_id text,
    ts timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.usage_ledger FORCE ROW LEVEL SECURITY;


--
-- Name: usage_ledger_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.usage_ledger_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: usage_ledger_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.usage_ledger_id_seq OWNED BY public.usage_ledger.id;


--
-- Name: user_mfa; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_mfa (
    user_id text NOT NULL,
    method text NOT NULL,
    secret_enc text NOT NULL,
    enrolled_at timestamp with time zone DEFAULT now() NOT NULL,
    enabled boolean DEFAULT true NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    user_id text NOT NULL,
    username text NOT NULL,
    email text,
    password_hash text DEFAULT ''::text NOT NULL,
    password_hash_v text DEFAULT ''::text NOT NULL,
    salt text DEFAULT ''::text NOT NULL,
    password_algo text DEFAULT 'scrypt'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    failed_attempts smallint DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    must_change_password boolean DEFAULT false NOT NULL,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    display_name text,
    email_verified boolean DEFAULT true NOT NULL,
    email_verify_token_hash text,
    email_verify_expires timestamp with time zone,
    password_reset_token_hash text,
    password_reset_expires timestamp with time zone,
    data_reflow_enabled boolean DEFAULT true NOT NULL,
    CONSTRAINT users_algo_chk CHECK ((password_algo = ANY (ARRAY['argon2id'::text, 'scrypt'::text, 'legacy'::text]))),
    CONSTRAINT users_status_chk CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text, 'locked'::text])))
);


--
-- Name: audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log ALTER COLUMN id SET DEFAULT nextval('public.audit_log_id_seq'::regclass);


--
-- Name: balance_ledger id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.balance_ledger ALTER COLUMN id SET DEFAULT nextval('public.balance_ledger_id_seq'::regclass);


--
-- Name: event_outbox seq; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_outbox ALTER COLUMN seq SET DEFAULT nextval('public.event_outbox_seq_seq'::regclass);


--
-- Name: lease_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lease_log ALTER COLUMN id SET DEFAULT nextval('public.lease_log_id_seq'::regclass);


--
-- Name: messages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages ALTER COLUMN id SET DEFAULT nextval('public.messages_id_seq'::regclass);


--
-- Name: migration_orphans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migration_orphans ALTER COLUMN id SET DEFAULT nextval('public.migration_orphans_id_seq'::regclass);


--
-- Name: usage_ledger id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_ledger ALTER COLUMN id SET DEFAULT nextval('public.usage_ledger_id_seq'::regclass);


--
-- Name: account_deletions account_deletions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_deletions
    ADD CONSTRAINT account_deletions_pkey PRIMARY KEY (user_id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (key_id);


--
-- Name: app_credentials app_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_credentials
    ADD CONSTRAINT app_credentials_pkey PRIMARY KEY (app_id, name);


--
-- Name: app_secrets app_secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_secrets
    ADD CONSTRAINT app_secrets_pkey PRIMARY KEY (secret_id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_seq_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_seq_key UNIQUE (seq);


--
-- Name: balance_ledger balance_ledger_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.balance_ledger
    ADD CONSTRAINT balance_ledger_pkey PRIMARY KEY (id);


--
-- Name: conversation_reads conversation_reads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversation_reads
    ADD CONSTRAINT conversation_reads_pkey PRIMARY KEY (conversation_id, user_id);


--
-- Name: conversations conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_pkey PRIMARY KEY (id);


--
-- Name: custom_roles custom_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_roles
    ADD CONSTRAINT custom_roles_pkey PRIMARY KEY (tenant_id, role_id);


--
-- Name: departments departments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_pkey PRIMARY KEY (dept_id);


--
-- Name: event_outbox event_outbox_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_outbox
    ADD CONSTRAINT event_outbox_pkey PRIMARY KEY (event_id);


--
-- Name: event_outbox event_outbox_seq_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_outbox
    ADD CONSTRAINT event_outbox_seq_key UNIQUE (seq);


--
-- Name: idempotency_keys idempotency_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (idem_key);


--
-- Name: identity_providers identity_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_providers
    ADD CONSTRAINT identity_providers_pkey PRIMARY KEY (idp_id);


--
-- Name: issued_jtis issued_jtis_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.issued_jtis
    ADD CONSTRAINT issued_jtis_pkey PRIMARY KEY (jti);


--
-- Name: join_requests join_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_pkey PRIMARY KEY (request_id);


--
-- Name: join_requests join_requests_unique_pending; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_unique_pending UNIQUE (tenant_id, user_id, status);


--
-- Name: known_menus known_menus_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.known_menus
    ADD CONSTRAINT known_menus_pkey PRIMARY KEY (tenant_id, menu);


--
-- Name: lease_log lease_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lease_log
    ADD CONSTRAINT lease_log_pkey PRIMARY KEY (id);


--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);


--
-- Name: migration_orphans migration_orphans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.migration_orphans
    ADD CONSTRAINT migration_orphans_pkey PRIMARY KEY (id);


--
-- Name: plan_templates plan_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.plan_templates
    ADD CONSTRAINT plan_templates_pkey PRIMARY KEY (plan);


--
-- Name: prepaid_orders prepaid_orders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.prepaid_orders
    ADD CONSTRAINT prepaid_orders_pkey PRIMARY KEY (order_id);


--
-- Name: quotas quotas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quotas
    ADD CONSTRAINT quotas_pkey PRIMARY KEY (tenant_id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (jti);


--
-- Name: revoked_jtis revoked_jtis_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revoked_jtis
    ADD CONSTRAINT revoked_jtis_pkey PRIMARY KEY (jti);


--
-- Name: role_menu_matrix role_menu_matrix_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_menu_matrix
    ADD CONSTRAINT role_menu_matrix_pkey PRIMARY KEY (tenant_id, role_id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);


--
-- Name: service_accounts service_accounts_cred_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_accounts
    ADD CONSTRAINT service_accounts_cred_hash_key UNIQUE (cred_hash);


--
-- Name: service_accounts service_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_accounts
    ADD CONSTRAINT service_accounts_pkey PRIMARY KEY (account_id);


--
-- Name: sso_tickets sso_tickets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_tickets
    ADD CONSTRAINT sso_tickets_pkey PRIMARY KEY (ticket_hash);


--
-- Name: tenant_invites tenant_invites_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_invites
    ADD CONSTRAINT tenant_invites_pkey PRIMARY KEY (invite_id);


--
-- Name: tenant_invites tenant_invites_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_invites
    ADD CONSTRAINT tenant_invites_token_hash_key UNIQUE (token_hash);


--
-- Name: tenant_members tenant_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_members
    ADD CONSTRAINT tenant_members_pkey PRIMARY KEY (tenant_id, user_id);


--
-- Name: tenant_usage_daily tenant_usage_daily_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_usage_daily
    ADD CONSTRAINT tenant_usage_daily_pkey PRIMARY KEY (tenant_id, bucket_day, metric, source);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (tenant_id);


--
-- Name: usage_ledger usage_ledger_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_ledger
    ADD CONSTRAINT usage_ledger_pkey PRIMARY KEY (id);


--
-- Name: usage_ledger usage_ledger_tenant_id_bucket_hour_metric_source_model_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_ledger
    ADD CONSTRAINT usage_ledger_tenant_id_bucket_hour_metric_source_model_key UNIQUE (tenant_id, bucket_hour, metric, source, model);


--
-- Name: user_mfa user_mfa_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_mfa
    ADD CONSTRAINT user_mfa_pkey PRIMARY KEY (user_id, method);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: account_deletions_purge_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX account_deletions_purge_idx ON public.account_deletions USING btree (purge_at) WHERE (status = 'pending'::text);


--
-- Name: api_keys_hash_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX api_keys_hash_idx ON public.api_keys USING btree (key_hash);


--
-- Name: api_keys_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX api_keys_tenant_idx ON public.api_keys USING btree (tenant_id);


--
-- Name: audit_log_detail_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_detail_gin ON public.audit_log USING gin (detail jsonb_path_ops);


--
-- Name: audit_log_seq_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_seq_idx ON public.audit_log USING btree (seq);


--
-- Name: audit_log_tenant_ts_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_log_tenant_ts_idx ON public.audit_log USING btree (tenant_id, ts DESC);


--
-- Name: departments_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX departments_tenant_idx ON public.departments USING btree (tenant_id);


--
-- Name: identity_providers_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX identity_providers_tenant_idx ON public.identity_providers USING btree (tenant_id);


--
-- Name: idx_balance_ledger_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_balance_ledger_tenant ON public.balance_ledger USING btree (tenant_id, id);


--
-- Name: idx_conversations_tenant_ref; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conversations_tenant_ref ON public.conversations USING btree (tenant_id, scope, ref);


--
-- Name: idx_conversations_tenant_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_conversations_tenant_updated ON public.conversations USING btree (tenant_id, updated_at DESC);


--
-- Name: idx_event_outbox_status_seq; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_event_outbox_status_seq ON public.event_outbox USING btree (status, seq);


--
-- Name: idx_messages_conv_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_conv_id ON public.messages USING btree (conversation_id, id);


--
-- Name: idx_prepaid_orders_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_prepaid_orders_tenant ON public.prepaid_orders USING btree (tenant_id, created_at);


--
-- Name: idx_service_accounts_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_service_accounts_tenant ON public.service_accounts USING btree (tenant_id, created_at);


--
-- Name: ij_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ij_expires_idx ON public.issued_jtis USING btree (expires_at);


--
-- Name: ix_app_credentials_app; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_app_credentials_app ON public.app_credentials USING btree (app_id);


--
-- Name: ix_app_secrets_app; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_app_secrets_app ON public.app_secrets USING btree (app_id);


--
-- Name: join_requests_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX join_requests_tenant_idx ON public.join_requests USING btree (tenant_id);


--
-- Name: lease_log_lease_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX lease_log_lease_idx ON public.lease_log USING btree (lease_id);


--
-- Name: lease_log_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX lease_log_tenant_idx ON public.lease_log USING btree (tenant_id, created_at DESC);


--
-- Name: rj_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rj_expires_idx ON public.revoked_jtis USING btree (expires_at);


--
-- Name: rt_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rt_expires_idx ON public.refresh_tokens USING btree (expires_at) WHERE (status <> 'revoked'::text);


--
-- Name: rt_family_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rt_family_idx ON public.refresh_tokens USING btree (family_id);


--
-- Name: rt_tenant_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rt_tenant_user_idx ON public.refresh_tokens USING btree (tenant_id, user_id);


--
-- Name: sso_tickets_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX sso_tickets_tenant_idx ON public.sso_tickets USING btree (tenant_id);


--
-- Name: tenant_invites_tenant_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tenant_invites_tenant_idx ON public.tenant_invites USING btree (tenant_id);


--
-- Name: tenant_members_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tenant_members_user_idx ON public.tenant_members USING btree (user_id);


--
-- Name: tenants_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX tenants_status_idx ON public.tenants USING btree (status) WHERE (status <> 'deleted'::text);


--
-- Name: uq_app_secrets_app_version; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_app_secrets_app_version ON public.app_secrets USING btree (app_id, version);


--
-- Name: usage_ledger_tenant_ts_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX usage_ledger_tenant_ts_idx ON public.usage_ledger USING btree (tenant_id, bucket_hour);


--
-- Name: users_username_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX users_username_idx ON public.users USING btree (username);


--
-- Name: users_username_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX users_username_uniq ON public.users USING btree (username);


--
-- Name: account_deletions account_deletions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.account_deletions
    ADD CONSTRAINT account_deletions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: balance_ledger balance_ledger_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.balance_ledger
    ADD CONSTRAINT balance_ledger_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) ON DELETE CASCADE;


--
-- Name: conversation_reads conversation_reads_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversation_reads
    ADD CONSTRAINT conversation_reads_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON DELETE CASCADE;


--
-- Name: conversations conversations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.conversations
    ADD CONSTRAINT conversations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: custom_roles custom_roles_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.custom_roles
    ADD CONSTRAINT custom_roles_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: departments departments_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.departments(dept_id);


--
-- Name: departments departments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.departments
    ADD CONSTRAINT departments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: event_outbox event_outbox_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_outbox
    ADD CONSTRAINT event_outbox_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: identity_providers identity_providers_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.identity_providers
    ADD CONSTRAINT identity_providers_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: issued_jtis issued_jtis_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.issued_jtis
    ADD CONSTRAINT issued_jtis_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: join_requests join_requests_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public.users(user_id);


--
-- Name: join_requests join_requests_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) ON DELETE CASCADE;


--
-- Name: join_requests join_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.join_requests
    ADD CONSTRAINT join_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: known_menus known_menus_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.known_menus
    ADD CONSTRAINT known_menus_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: messages messages_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.conversations(id) ON DELETE CASCADE;


--
-- Name: messages messages_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: prepaid_orders prepaid_orders_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.prepaid_orders
    ADD CONSTRAINT prepaid_orders_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) ON DELETE CASCADE;


--
-- Name: quotas quotas_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.quotas
    ADD CONSTRAINT quotas_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: refresh_tokens refresh_tokens_replaced_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_replaced_by_fkey FOREIGN KEY (replaced_by) REFERENCES public.refresh_tokens(jti);


--
-- Name: refresh_tokens refresh_tokens_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: refresh_tokens refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: revoked_jtis revoked_jtis_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revoked_jtis
    ADD CONSTRAINT revoked_jtis_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: role_menu_matrix role_menu_matrix_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_menu_matrix
    ADD CONSTRAINT role_menu_matrix_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: service_accounts service_accounts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.service_accounts
    ADD CONSTRAINT service_accounts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) ON DELETE CASCADE;


--
-- Name: sso_tickets sso_tickets_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_tickets
    ADD CONSTRAINT sso_tickets_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) ON DELETE CASCADE;


--
-- Name: sso_tickets sso_tickets_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sso_tickets
    ADD CONSTRAINT sso_tickets_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: tenant_invites tenant_invites_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_invites
    ADD CONSTRAINT tenant_invites_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id);


--
-- Name: tenant_invites tenant_invites_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_invites
    ADD CONSTRAINT tenant_invites_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) ON DELETE CASCADE;


--
-- Name: tenant_invites tenant_invites_used_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_invites
    ADD CONSTRAINT tenant_invites_used_by_fkey FOREIGN KEY (used_by) REFERENCES public.users(user_id);


--
-- Name: tenant_members tenant_members_added_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_members
    ADD CONSTRAINT tenant_members_added_by_fkey FOREIGN KEY (added_by) REFERENCES public.users(user_id);


--
-- Name: tenant_members tenant_members_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_members
    ADD CONSTRAINT tenant_members_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: tenant_members tenant_members_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_members
    ADD CONSTRAINT tenant_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: tenant_usage_daily tenant_usage_daily_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_usage_daily
    ADD CONSTRAINT tenant_usage_daily_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: usage_ledger usage_ledger_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_ledger
    ADD CONSTRAINT usage_ledger_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id);


--
-- Name: user_mfa user_mfa_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_mfa
    ADD CONSTRAINT user_mfa_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: api_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: custom_roles; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.custom_roles ENABLE ROW LEVEL SECURITY;

--
-- Name: departments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.departments ENABLE ROW LEVEL SECURITY;

--
-- Name: event_outbox; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.event_outbox ENABLE ROW LEVEL SECURITY;

--
-- Name: identity_providers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.identity_providers ENABLE ROW LEVEL SECURITY;

--
-- Name: issued_jtis; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.issued_jtis ENABLE ROW LEVEL SECURITY;

--
-- Name: known_menus; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.known_menus ENABLE ROW LEVEL SECURITY;

--
-- Name: lease_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.lease_log ENABLE ROW LEVEL SECURITY;

--
-- Name: quotas; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.quotas ENABLE ROW LEVEL SECURITY;

--
-- Name: refresh_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.refresh_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: revoked_jtis; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.revoked_jtis ENABLE ROW LEVEL SECURITY;

--
-- Name: role_menu_matrix; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.role_menu_matrix ENABLE ROW LEVEL SECURITY;

--
-- Name: api_keys tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.api_keys USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: audit_log tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.audit_log USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: custom_roles tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.custom_roles USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: departments tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.departments USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: event_outbox tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.event_outbox USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: identity_providers tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.identity_providers USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: issued_jtis tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.issued_jtis USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: known_menus tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.known_menus USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: lease_log tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.lease_log USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: quotas tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.quotas USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: refresh_tokens tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.refresh_tokens USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: revoked_jtis tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.revoked_jtis USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: role_menu_matrix tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.role_menu_matrix USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: tenant_members tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.tenant_members USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: tenant_usage_daily tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.tenant_usage_daily USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: tenants tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.tenants USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: usage_ledger tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation ON public.usage_ledger USING (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text))) WITH CHECK (((tenant_id = current_setting('app.current_tenant'::text)) OR (current_setting('app.current_tenant'::text) = '_system'::text)));


--
-- Name: tenant_members; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_members ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_usage_daily; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_usage_daily ENABLE ROW LEVEL SECURITY;

--
-- Name: tenants; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_ledger; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_ledger ENABLE ROW LEVEL SECURITY;

--

--
-- Seed data (not emitted by pg_dump --schema-only; mirrored from
-- migrations/0001_baseline.sql and migrations/0010_provisioning.sql so a
-- schema.sql-only install sees the same defaults as a migrations run).
--

INSERT INTO public.roles (role, display_name, permissions) VALUES
    ('tenant_admin', 'Tenant Admin', '{"tenants":["read","write"],"users":["read","write"],"quotas":["read","write"],"audit":["read"]}'::jsonb),
    ('operator', 'Operator', '{"models":["read","infer"],"tasks":["read","write"]}'::jsonb),
    ('member', 'Member', '{"models":["infer"],"tasks":["write"]}'::jsonb),
    ('viewer', 'Viewer', '{"models":["read"],"tasks":["read"]}'::jsonb)
ON CONFLICT (role) DO NOTHING;

INSERT INTO public.plan_templates(plan, quota) VALUES
    ('free',       '{"rpm": 10, "tpm": 20000, "concurrent": 2, "storage_mb": 1024, "allowed_models": [], "allowed_modules": [], "default_priority": 0}'),
    ('starter',    '{"rpm": 30, "tpm": 50000, "concurrent": 3, "storage_mb": 5120, "allowed_models": [], "allowed_modules": [], "default_priority": 0}'),
    ('standard',   '{"rpm": 60, "tpm": 100000, "concurrent": 4, "storage_mb": 10240, "allowed_models": [], "allowed_modules": [], "default_priority": 0}'),
    ('pro',        '{"rpm": 200, "tpm": 1000000, "concurrent": 16, "storage_mb": 51200, "allowed_models": [], "allowed_modules": [], "default_priority": 1}'),
    ('enterprise', '{"rpm": 1000, "tpm": 10000000, "concurrent": 64, "storage_mb": 204800, "allowed_models": [], "allowed_modules": [], "default_priority": 2}')
ON CONFLICT (plan) DO NOTHING;

--
-- PostgreSQL database dump complete
--

