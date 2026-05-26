-- 014_webhook_deliveries_cascade.sql
--
-- Delete from /webhooks/:id/delete failed with
--   "update or delete on table webhook_endpoints violates foreign key
--    constraint webhook_deliveries_webhook_endpoint_id_fkey"
-- because the original migration 005 declared the FK without ON DELETE
-- CASCADE. Endpoint deletion is the user-facing primary action; the
-- delivery history is dependent metadata that should follow the endpoint
-- into the trash.
--
-- This migration drops and re-adds the FK with CASCADE so admins can
-- actually remove a webhook. Existing delivery rows for an endpoint are
-- now cleaned up automatically on endpoint delete.

ALTER TABLE webhook_deliveries
    DROP CONSTRAINT IF EXISTS webhook_deliveries_webhook_endpoint_id_fkey;

ALTER TABLE webhook_deliveries
    ADD CONSTRAINT webhook_deliveries_webhook_endpoint_id_fkey
    FOREIGN KEY (webhook_endpoint_id)
    REFERENCES webhook_endpoints(id)
    ON DELETE CASCADE;
