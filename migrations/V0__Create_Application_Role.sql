-- V0__Create_Application_Role.sql
-- Creates a dedicated application role with limited privileges instead of using postgres superuser

-- Create the application role
CREATE ROLE server_app WITH LOGIN PASSWORD 'changeme_app_password';

-- Grant connection privileges
GRANT CONNECT ON DATABASE server_db TO server_app;

-- Grant schema usage
GRANT USAGE ON SCHEMA public TO server_app;

-- Grant table privileges (for current and future tables)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO server_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO server_app;

-- Grant sequence privileges (for auto-increment columns)
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO server_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO server_app;

-- Grant function execution privileges
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO server_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO server_app;

-- Ensure the role can create temporary tables (needed for some operations)
GRANT TEMPORARY ON DATABASE server_db TO server_app;

-- Comment for documentation
COMMENT ON ROLE server_app IS 'Application role with minimal required privileges for server authentication service';
