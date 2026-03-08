#!/bin/bash
set -e

echo "[entrypoint] Running database migrations..."
alembic upgrade head 2>&1 || echo "[entrypoint] WARNING: Alembic migrations failed (tables may already exist via create_all)"

echo "[entrypoint] Seeding prompts..."
python -m scripts.seed_prompts 2>&1 || echo "[entrypoint] WARNING: Prompt seeding failed"

echo "[entrypoint] Starting application..."
exec "$@"
