-- Migration: Add scan schedule tables for intelligent scheduling
-- Date: 2026-01-17

-- =============================================================================
-- scan_schedules - Repository scan scheduling
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id SERIAL UNIQUE,

    -- Multi-tenant scope
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,

    -- Schedule configuration
    schedule_type VARCHAR(20) NOT NULL DEFAULT 'ai' CHECK (schedule_type IN ('ai', 'manual')),
    frequency VARCHAR(20) NOT NULL CHECK (frequency IN ('daily', 'weekly', 'bi-weekly', 'monthly')),
    day_of_week INTEGER CHECK (day_of_week >= 0 AND day_of_week <= 6),
    time_window VARCHAR(20) NOT NULL CHECK (time_window IN ('morning', 'afternoon', 'evening', 'night')),

    -- Scan arguments
    scan_arguments JSONB DEFAULT '{"overridescan": true}'::jsonb,

    -- Execution tracking
    next_scheduled_at TIMESTAMP,
    last_executed_at TIMESTAMP,
    last_execution_status VARCHAR(20) CHECK (last_execution_status IN ('success', 'failed', 'running', 'skipped')),

    -- AI analysis metadata
    ai_reasoning TEXT,
    ai_confidence NUMERIC(3, 2),
    ai_analyzed_at TIMESTAMP,

    -- Lock status
    is_locked BOOLEAN DEFAULT FALSE,
    locked_at TIMESTAMP,
    locked_by UUID REFERENCES users(id),

    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),

    -- Each repo has exactly one schedule
    CONSTRAINT unique_schedule_per_repo UNIQUE (repository_id)
);

-- Index for efficient org-scoped queries
CREATE INDEX IF NOT EXISTS idx_scan_schedules_org ON scan_schedules(organization_id);

-- Index for finding schedules due for execution
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run ON scan_schedules(next_scheduled_at) WHERE is_active = TRUE;

-- =============================================================================
-- schedule_overrides - Audit log for manual changes
-- =============================================================================

CREATE TABLE IF NOT EXISTS schedule_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id SERIAL UNIQUE,

    schedule_id UUID NOT NULL REFERENCES scan_schedules(id) ON DELETE CASCADE,

    -- Previous values
    previous_frequency VARCHAR(20),
    previous_day_of_week INTEGER,
    previous_time_window VARCHAR(20),
    previous_scan_arguments JSONB,

    -- New values
    new_frequency VARCHAR(20),
    new_day_of_week INTEGER,
    new_time_window VARCHAR(20),
    new_scan_arguments JSONB,

    -- Audit info
    override_reason TEXT,
    overridden_by UUID NOT NULL REFERENCES users(id),

    created_at TIMESTAMP DEFAULT NOW()
);

-- Index for viewing override history
CREATE INDEX IF NOT EXISTS idx_schedule_overrides_schedule ON schedule_overrides(schedule_id);

-- =============================================================================
-- Trigger to auto-update updated_at
-- =============================================================================

CREATE OR REPLACE FUNCTION update_scan_schedules_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_scan_schedules_updated_at ON scan_schedules;
CREATE TRIGGER trigger_scan_schedules_updated_at
    BEFORE UPDATE ON scan_schedules
    FOR EACH ROW
    EXECUTE FUNCTION update_scan_schedules_updated_at();

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE scan_schedules IS 'Repository scan scheduling - AI-generated or manually set';
COMMENT ON COLUMN scan_schedules.schedule_type IS 'ai = automatically determined, manual = user override';
COMMENT ON COLUMN scan_schedules.time_window IS 'morning (6-12), afternoon (12-18), evening (18-22), night (22-6)';
COMMENT ON COLUMN scan_schedules.is_locked IS 'When true, AI will not modify this schedule';
COMMENT ON TABLE schedule_overrides IS 'Audit log tracking all manual schedule modifications';
