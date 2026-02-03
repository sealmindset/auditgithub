-- Create AI conversations tables in security_portal database
-- Run this: docker exec -i auditgh_db psql -U postgres -d security_portal < create_ai_tables.sql

-- Create ENUM types (check if they exist first)
DO $$ BEGIN
    CREATE TYPE messagerole AS ENUM ('USER', 'ASSISTANT', 'SYSTEM');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE citationtype AS ENUM ('REPOSITORY', 'SCAN_RESULT', 'VULNERABILITY', 'WEB', 'DOCUMENTATION');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Create ai_conversations table
CREATE TABLE IF NOT EXISTS ai_conversations (
    id SERIAL PRIMARY KEY,
    conversation_id VARCHAR(100) NOT NULL UNIQUE,
    project_id INTEGER NOT NULL,
    repository_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    title VARCHAR(500),
    focus VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    message_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_message_at TIMESTAMP,
    FOREIGN KEY (repository_id) REFERENCES repositories(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_ai_conversations_conversation_id ON ai_conversations(conversation_id);
CREATE INDEX IF NOT EXISTS ix_ai_conversations_repository_id ON ai_conversations(repository_id);
CREATE INDEX IF NOT EXISTS ix_ai_conversations_project_id ON ai_conversations(project_id);

-- Create ai_messages table
CREATE TABLE IF NOT EXISTS ai_messages (
    id SERIAL PRIMARY KEY,
    message_id VARCHAR(100) NOT NULL UNIQUE,
    conversation_id INTEGER NOT NULL,
    role messagerole NOT NULL,
    content TEXT NOT NULL,
    thinking TEXT,
    needs_clarification BOOLEAN DEFAULT FALSE,
    clarification_question TEXT,
    context_used JSONB,
    tokens_used INTEGER,
    confidence_score INTEGER,
    web_search_performed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (conversation_id) REFERENCES ai_conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_ai_messages_message_id ON ai_messages(message_id);
CREATE INDEX IF NOT EXISTS ix_ai_messages_conversation_id ON ai_messages(conversation_id);

-- Create ai_citations table
CREATE TABLE IF NOT EXISTS ai_citations (
    id SERIAL PRIMARY KEY,
    citation_id VARCHAR(100) NOT NULL UNIQUE,
    message_id INTEGER NOT NULL,
    type citationtype NOT NULL,
    source VARCHAR(500) NOT NULL,
    reference VARCHAR(1000) NOT NULL,
    excerpt TEXT,
    url VARCHAR(2000),
    relevance_score INTEGER,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (message_id) REFERENCES ai_messages(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS ix_ai_citations_citation_id ON ai_citations(citation_id);
CREATE INDEX IF NOT EXISTS ix_ai_citations_message_id ON ai_citations(message_id);

-- Show created tables
SELECT 'AI conversation tables created successfully!' as status;
\dt ai_*
