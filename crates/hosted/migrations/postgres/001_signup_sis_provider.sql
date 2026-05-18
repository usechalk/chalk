-- 001_signup_sis_provider.sql
--
-- Phase 5a (Wave B): record the SIS provider chosen on the signup form so
-- `activate_tenant` can carry it through to the per-tenant config row that
-- Phase 1 (parallel agent) creates in `tenant_config_sis`. Nullable: the
-- chooser defaults to "I'll set this up later", which stores NULL here.
ALTER TABLE _meta.signup_pending
    ADD COLUMN IF NOT EXISTS sis_provider TEXT NULL;
