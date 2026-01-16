-- Migration: 013_cribl_config.sql
-- Description: Add cribl_config table for Cribl Stream log management integration
-- Date: 2024-12-24

-- Create cribl_config table
CREATE TABLE IF NOT EXISTS cribl_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE NOT NULL,
    
    -- Connection settings
    ingest_url VARCHAR(500),
    auth_token VARCHAR(500),
    verify_ssl BOOLEAN DEFAULT true,
    
    -- Feature toggles
    enabled BOOLEAN DEFAULT false,
    log_levels VARCHAR[] DEFAULT ARRAY['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    include_app_context BOOLEAN DEFAULT true,
    include_security_audit BOOLEAN DEFAULT true,
    minio_fallback BOOLEAN DEFAULT true,
    
    -- MinIO settings (for local storage/fallback)
    minio_endpoint VARCHAR(500) DEFAULT 'http://minio:9000',
    minio_bucket VARCHAR(100) DEFAULT 'auditgh-logs',
    minio_access_key VARCHAR(200),
    minio_secret_key VARCHAR(200),
    
    -- Test status
    last_test_at TIMESTAMP WITH TIME ZONE,
    last_test_status VARCHAR(50) DEFAULT 'PENDING',
    last_test_message TEXT,
    
    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on api_id for PostgREST access
CREATE INDEX IF NOT EXISTS idx_cribl_config_api_id ON cribl_config(api_id);

-- Insert default configuration row (singleton pattern)
INSERT INTO cribl_config (
    ingest_url,
    auth_token,
    verify_ssl,
    enabled,
    log_levels,
    include_app_context,
    include_security_audit,
    minio_fallback,
    minio_endpoint,
    minio_bucket,
    last_test_status
) VALUES (
    '',
    '',
    true,
    false,
    ARRAY['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    true,
    true,
    true,
    'http://minio:9000',
    'auditgh-logs',
    'PENDING'
) ON CONFLICT DO NOTHING;

-- Add comment for documentation
COMMENT ON TABLE cribl_config IS 'Configuration for Cribl Stream log management integration. Singleton table - only one row.';
COMMENT ON COLUMN cribl_config.ingest_url IS 'Cribl HTTP/S endpoint URL (e.g., https://cribl.example.com:20000)';
COMMENT ON COLUMN cribl_config.auth_token IS 'Bearer token for Cribl authentication';
COMMENT ON COLUMN cribl_config.verify_ssl IS 'Whether to validate SSL certificates when connecting to Cribl';
COMMENT ON COLUMN cribl_config.enabled IS 'Master switch for Cribl log forwarding';
COMMENT ON COLUMN cribl_config.log_levels IS 'Array of log levels to forward (DEBUG, INFO, WARNING, ERROR, CRITICAL)';
COMMENT ON COLUMN cribl_config.include_app_context IS 'Include org_id, user_id, request_id in log entries';
COMMENT ON COLUMN cribl_config.include_security_audit IS 'Include action, resource, outcome fields in log entries';
COMMENT ON COLUMN cribl_config.minio_fallback IS 'Store logs in MinIO when Cribl is unavailable';
COMMENT ON COLUMN cribl_config.minio_endpoint IS 'MinIO S3 API endpoint URL';
COMMENT ON COLUMN cribl_config.minio_bucket IS 'MinIO bucket name for log storage';
