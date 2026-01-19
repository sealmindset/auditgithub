from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool, text
from alembic import context
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.api.database import SessionLocal, engine as metadata_engine
from src.api.models import Base, Tenant

# Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# SQLAlchemy metadata for autogenerate
target_metadata = Base.metadata

def run_migrations_online():
    """Run migrations in 'online' mode across all tenant schemas."""

    # Get tenant schema from -x flag (for single-tenant migrations)
    x_args = context.get_x_argument(as_dictionary=True)
    tenant_schema = x_args.get('tenant')

    connectable = metadata_engine

    if tenant_schema:
        # Single tenant migration (for testing or repair)
        with connectable.connect() as connection:
            connection.execute(text("SET search_path = :schema, public"),
                             {"schema": tenant_schema})
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                version_table='alembic_version',
                version_table_schema=tenant_schema,
                include_schemas=True
            )
            with context.begin_transaction():
                context.run_migrations()
    else:
        # Migrate all active, provisioned tenants
        db = SessionLocal()
        try:
            tenants = db.query(Tenant).filter(
                Tenant.is_active == True,
                Tenant.is_provisioned == True
            ).all()

            for tenant in tenants:
                schema_name = f"tenant_{tenant.slug}"
                print(f"Migrating schema: {schema_name}")

                with connectable.connect() as connection:
                    connection.execute(text("SET search_path = :schema, public"),
                                     {"schema": schema_name})
                    context.configure(
                        connection=connection,
                        target_metadata=target_metadata,
                        version_table='alembic_version',
                        version_table_schema=schema_name,
                        include_schemas=True
                    )

                    try:
                        with context.begin_transaction():
                            context.run_migrations()
                    except Exception as e:
                        print(f"ERROR migrating {schema_name}: {e}")
                        # Don't stop - continue to next tenant

        finally:
            db.close()

if context.is_offline_mode():
    raise NotImplementedError("Offline mode not supported for multi-tenant migrations")
else:
    run_migrations_online()
