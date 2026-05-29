-- Optional read scope for API tokens. NULL means unrestricted (the OSS
-- default, preserving prior behavior). The hosted marketplace stores a JSON
-- TokenScope here when a district authorizes an app, so the app's token reads
-- only the schools/grades/subjects/sections/fields the admin shared.
ALTER TABLE api_tokens ADD COLUMN IF NOT EXISTS scope JSONB;
