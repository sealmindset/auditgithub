#!/usr/bin/env python3
"""
Initialize the sandbox database.

Connects to PostgreSQL as the configured user and creates the
auditgh_sandbox database if it does not already exist.
Intended for use as a Docker entrypoint script or standalone invocation.
"""

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT


def init_sandbox_db():
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    user = os.environ.get("POSTGRES_USER", "postgres")
    password = os.environ.get("POSTGRES_PASSWORD", "postgres")
    sandbox_db = os.environ.get("SANDBOX_DB_NAME", "auditgh_sandbox")

    print(f"Connecting to PostgreSQL at {host}:{port} as {user}...")
    conn = psycopg2.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        dbname="postgres",
    )
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (sandbox_db,))
    if cur.fetchone():
        print(f"Database '{sandbox_db}' already exists — skipping creation.")
    else:
        cur.execute(f'CREATE DATABASE "{sandbox_db}"')
        print(f"Database '{sandbox_db}' created successfully.")

    cur.close()
    conn.close()


if __name__ == "__main__":
    try:
        init_sandbox_db()
    except Exception as e:
        print(f"ERROR: Failed to initialize sandbox database: {e}", file=sys.stderr)
        sys.exit(1)
