import os
import logging
import hashlib
import json
from typing import Optional, Dict, Any
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

class KnowledgeBase:
    """
    Persistent Knowledge Base for AI Remediation Plans.
    Stores and retrieves remediation plans from PostgreSQL.
    """
    
    def __init__(self):
        self.conn = None
        self.enabled = False
        self._connect()
        
    def _connect(self):
        """Connect to PostgreSQL database."""
        try:
            # Get DB config from env or defaults (matching docker-compose)
            host = os.environ.get("POSTGRES_HOST", "db")
            port = os.environ.get("POSTGRES_PORT", "5432")
            user = os.environ.get("POSTGRES_USER", "auditgh")
            password = os.environ.get("POSTGRES_PASSWORD", "auditgh_secret")
            dbname = os.environ.get("POSTGRES_DB", "auditgh_kb")
            
            self.conn = psycopg2.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                dbname=dbname
            )
            self.conn.autocommit = True
            self.enabled = True
            logger.info("Connected to Knowledge Base (PostgreSQL)")
            self._init_schema()
            
        except Exception as e:
            logger.warning(f"Could not connect to Knowledge Base: {e}")
            self.enabled = False
            
    def _init_schema(self):
        """Initialize database schema."""
        if not self.enabled: return

        try:
            with self.conn.cursor() as cur:
                # Check if remediations table exists and what schema it has
                cur.execute("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'remediations'
                    AND column_name IN ('vuln_id', 'finding_id')
                """)
                columns = [row[0] for row in cur.fetchall()]

                if 'finding_id' in columns:
                    # New schema exists (managed by SQLAlchemy/API)
                    # Disable knowledge base to avoid conflicts
                    logger.info("Remediations table uses new schema (managed by API) - disabling knowledge base cache")
                    self.enabled = False
                    return
                elif 'vuln_id' in columns:
                    # Old schema exists, we can use it
                    logger.info("Using existing remediations table with legacy schema")
                    # Create index if it doesn't exist
                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_remediations_lookup
                        ON remediations(vuln_id, context_hash);
                    """)
                else:
                    # Table doesn't exist, create it with legacy schema
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS remediations (
                            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                            api_id BIGSERIAL UNIQUE,
                            vuln_id VARCHAR(255),
                            vuln_type VARCHAR(255),
                            context_hash VARCHAR(64),
                            remediation_text TEXT,
                            code_diff TEXT,
                            created_at TIMESTAMP DEFAULT NOW(),
                            UNIQUE(vuln_id, context_hash)
                        );
                        CREATE INDEX IF NOT EXISTS idx_remediations_lookup
                        ON remediations(vuln_id, context_hash);
                    """)
                    logger.info("Created remediations table with legacy schema")
        except Exception as e:
            logger.warning(f"Could not initialize knowledge base schema: {e}")
            self.enabled = False
            
    def get_remediation(self, vuln_id: str, context: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a stored remediation plan.
        
        Args:
            vuln_id: CVE ID or unique vulnerability identifier
            context: The code snippet or dependency context (will be hashed)
        """
        if not self.enabled: return None
        
        context_hash = hashlib.sha256(context.encode('utf-8')).hexdigest()
        
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT remediation_text, code_diff 
                    FROM remediations 
                    WHERE vuln_id = %s AND context_hash = %s
                """, (vuln_id, context_hash))
                result = cur.fetchone()
                
                if result:
                    logger.info(f"Found cached remediation for {vuln_id}")
                    return {
                        "remediation": result['remediation_text'],
                        "diff": result['code_diff']
                    }
        except Exception as e:
            logger.error(f"Error fetching remediation: {e}")
            
        return None
        
    def store_remediation(self, vuln_id: str, vuln_type: str, context: str, remediation: str, diff: str):
        """
        Store a new remediation plan.
        """
        if not self.enabled: return
        
        context_hash = hashlib.sha256(context.encode('utf-8')).hexdigest()
        
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO remediations 
                    (vuln_id, vuln_type, context_hash, remediation_text, code_diff)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (vuln_id, context_hash) 
                    DO UPDATE SET 
                        remediation_text = EXCLUDED.remediation_text,
                        code_diff = EXCLUDED.code_diff,
                        created_at = NOW()
                """, (vuln_id, vuln_type, context_hash, remediation, diff))
                logger.info(f"Stored remediation for {vuln_id}")
        except Exception as e:
            logger.error(f"Error storing remediation: {e}")
