#!/usr/bin/env python3
"""
Migration script to add investigation/journal tables and columns.
Run this to add the journal_entries table and investigation columns to findings.
"""

import os
import sys

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_migration():
    """Run migration to add investigation tracking."""
    import psycopg2
    
    # Database connection
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        database=os.getenv("POSTGRES_DB", "auditgh"),
        user=os.getenv("POSTGRES_USER", "auditgh"),
        password=os.getenv("POSTGRES_PASSWORD", "auditgh")
    )
    conn.autocommit = True
    cursor = conn.cursor()
    
    print("=" * 60)
    print("MIGRATION: Add Investigation & Journal Features")
    print("=" * 60)
    
    # 1. Add investigation columns to findings table
    print("\n1. Adding investigation columns to findings table...")
    try:
        cursor.execute("""
            ALTER TABLE findings 
            ADD COLUMN IF NOT EXISTS investigation_status VARCHAR,
            ADD COLUMN IF NOT EXISTS investigation_started_at TIMESTAMP,
            ADD COLUMN IF NOT EXISTS investigation_resolved_at TIMESTAMP
        """)
        print("   ✓ Investigation columns added to findings table")
    except Exception as e:
        print(f"   Note: {e}")
    
    # 2. Create journal_entries table
    print("\n2. Creating journal_entries table...")
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS journal_entries (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                entry_text TEXT NOT NULL,
                entry_type VARCHAR DEFAULT 'note',
                author_name VARCHAR DEFAULT 'Analyst',
                author_id UUID REFERENCES users(id),
                is_ai_generated BOOLEAN DEFAULT FALSE,
                ai_prompt TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)
        print("   ✓ journal_entries table created")
    except Exception as e:
        print(f"   Note: {e}")
    
    # 3. Create index for faster queries
    print("\n3. Creating indexes...")
    try:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_journal_entries_finding_id 
            ON journal_entries(finding_id)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_findings_investigation_status 
            ON findings(investigation_status) 
            WHERE investigation_status IS NOT NULL
        """)
        print("   ✓ Indexes created")
    except Exception as e:
        print(f"   Note: {e}")
    
    # 4. Verify columns exist
    print("\n4. Verifying migration...")
    cursor.execute("""
        SELECT column_name FROM information_schema.columns 
        WHERE table_name = 'findings' 
        AND column_name IN ('investigation_status', 'investigation_started_at', 'investigation_resolved_at')
    """)
    finding_cols = cursor.fetchall()
    print(f"   ✓ Findings columns: {[c[0] for c in finding_cols]}")
    
    cursor.execute("""
        SELECT table_name FROM information_schema.tables 
        WHERE table_name = 'journal_entries'
    """)
    journal_table = cursor.fetchall()
    print(f"   ✓ Journal table exists: {len(journal_table) > 0}")
    
    cursor.close()
    conn.close()
    
    print("\n" + "=" * 60)
    print("MIGRATION COMPLETE!")
    print("=" * 60)
    print("\nYou can now use the investigation/journal features.")
    print("Restart the API container to pick up the model changes:")
    print("  docker-compose restart auditgh_api")

if __name__ == "__main__":
    run_migration()
