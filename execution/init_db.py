#!/usr/bin/env python3
import os
import sys
import logging
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_db_connection(dbname=None):
    """Connect to PostgreSQL database."""
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    user = os.environ.get("POSTGRES_USER", "auditgh")
    password = os.environ.get("POSTGRES_PASSWORD", "auditgh_secret")
    
    # If dbname is not provided, connect to 'postgres' to create the target DB
    target_db = dbname or "postgres"
    
    try:
        conn = psycopg2.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=target_db
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        return conn
    except Exception as e:
        logger.error(f"Could not connect to database {target_db}: {e}")
        return None

def init_db():
    """Initialize the database schema."""
    target_db = os.environ.get("POSTGRES_DB", "auditgh_kb")
    
    # 1. Create database if it doesn't exist
    conn = get_db_connection()
    if not conn:
        return False
        
    try:
        with conn.cursor() as cur:
            # Check if db exists
            cur.execute(f"SELECT 1 FROM pg_database WHERE datname = '{target_db}'")
            if not cur.fetchone():
                logger.info(f"Creating database {target_db}...")
                cur.execute(f"CREATE DATABASE {target_db}")
            else:
                logger.info(f"Database {target_db} already exists.")
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        return False
    finally:
        conn.close()
        
    # 2. Apply Schema
    conn = get_db_connection(target_db)
    if not conn:
        return False
        
    schema_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "setup", "schema.sql")
    if not os.path.exists(schema_path):
        logger.error(f"Schema file not found at {schema_path}")
        return False
        
    try:
        with open(schema_path, 'r') as f:
            schema_sql = f.read()
            
        logger.info(f"Applying schema from {schema_path}...")
        with conn.cursor() as cur:
            cur.execute(schema_sql)
            
        logger.info("Database initialization completed successfully! ✅")
        return True
    except Exception as e:
        logger.error(f"Error applying schema: {e}")
        return False
    finally:
        conn.close()

if __name__ == "__main__":
    success = init_db()
    sys.exit(0 if success else 1)
