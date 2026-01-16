-- Migration: 007_add_request_response_capture.sql
-- Description: Add columns to capture raw HTTP request/response data for credential-URL tests
-- Date: 2024-12-14

-- Add request/response capture columns to credential_url_test_results table
-- These columns store the actual HTTP request and response data for audit purposes

-- Request capture columns
ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS auth_request_method VARCHAR(10) DEFAULT 'GET';

ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS auth_request_url TEXT;

ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS auth_request_headers JSONB DEFAULT '{}';

ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS auth_request_body TEXT DEFAULT '';

-- Response capture columns
ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS auth_response_headers JSONB DEFAULT '{}';

ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS auth_response_body TEXT DEFAULT '';

ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS auth_response_body_truncated BOOLEAN DEFAULT FALSE;

-- Service detection columns
ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS detected_service VARCHAR(100);

ALTER TABLE credential_url_test_results 
ADD COLUMN IF NOT EXISTS service_detection_score INTEGER DEFAULT 0;

-- Add comments for documentation
COMMENT ON COLUMN credential_url_test_results.auth_request_method IS 'HTTP method used for authentication test (GET, POST, etc.)';
COMMENT ON COLUMN credential_url_test_results.auth_request_url IS 'Full URL used for the authentication request';
COMMENT ON COLUMN credential_url_test_results.auth_request_headers IS 'Request headers sent (with credentials masked)';
COMMENT ON COLUMN credential_url_test_results.auth_request_body IS 'Request body if any (for POST requests)';
COMMENT ON COLUMN credential_url_test_results.auth_response_headers IS 'Response headers received from server';
COMMENT ON COLUMN credential_url_test_results.auth_response_body IS 'Response body (truncated if too large)';
COMMENT ON COLUMN credential_url_test_results.auth_response_body_truncated IS 'True if response body was truncated due to size';
COMMENT ON COLUMN credential_url_test_results.detected_service IS 'Detected service type (e.g., GitHub, AWS, Slack)';
COMMENT ON COLUMN credential_url_test_results.service_detection_score IS 'Confidence score for service detection (0-100)';

-- Create index for service detection queries
CREATE INDEX IF NOT EXISTS idx_credential_url_test_results_detected_service 
ON credential_url_test_results(detected_service);
