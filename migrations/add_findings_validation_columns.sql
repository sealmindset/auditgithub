-- Migration: Add validation and investigation tracking columns to findings table
-- These columns are required by the SQLAlchemy model but missing from the database schema

-- Add verification/validation columns
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_verified_by_scanner BOOLEAN DEFAULT FALSE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_validated_active BOOLEAN DEFAULT NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_message VARCHAR DEFAULT NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validated_at TIMESTAMP DEFAULT NULL;

-- Add investigation tracking columns
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_status VARCHAR DEFAULT NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_started_at TIMESTAMP DEFAULT NULL;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_resolved_at TIMESTAMP DEFAULT NULL;
