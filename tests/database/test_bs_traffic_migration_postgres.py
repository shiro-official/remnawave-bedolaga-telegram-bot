"""Apply the actual revision to old-schema data in an isolated PostgreSQL schema."""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect, text

from tests.fixtures.postgres_db import postgres_engine


pytestmark = pytest.mark.postgres
MIGRATION = Path(__file__).resolve().parents[2] / 'migrations/alembic/versions/0132_bs_traffic_foundation.py'


@pytest.mark.asyncio
async def test_upgrade_preserves_old_paid_trial_and_expired_data(postgres_database):
    spec = importlib.util.spec_from_file_location('migration_0132', MIGRATION)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    schema = f'bs_migration_{uuid4().hex}'
    async with postgres_engine(postgres_database) as engine, engine.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
        await conn.execute(text(f'SET LOCAL search_path TO "{schema}"'))
        await conn.execute(text('CREATE TABLE users (id integer PRIMARY KEY, balance_kopeks bigint NOT NULL)'))
        await conn.execute(text('CREATE TABLE tariffs (id integer PRIMARY KEY, traffic_limit_gb integer NOT NULL)'))
        await conn.execute(
            text("""
            CREATE TABLE subscriptions (
                id integer PRIMARY KEY, user_id integer REFERENCES users(id),
                tariff_id integer REFERENCES tariffs(id), status varchar(20), is_trial boolean,
                end_date timestamptz, remnawave_id bigint, subscription_url text,
                traffic_limit_gb integer, traffic_used_gb double precision
            )
        """)
        )
        await conn.execute(text('INSERT INTO users VALUES (1, 12345)'))
        await conn.execute(text('INSERT INTO tariffs VALUES (1, 0)'))
        await conn.execute(
            text("""
            INSERT INTO subscriptions VALUES
              (1,1,1,'active',false,'2027-01-01',1000,'https://example.test/paid',0,250.5),
              (2,1,1,'trial',true,'2027-01-01',1001,'https://example.test/trial',50,25),
              (3,1,1,'expired',false,'2025-01-01',1002,'https://example.test/expired',0,75)
        """)
        )
        query = 'SELECT id,user_id,tariff_id,status,is_trial,end_date,remnawave_id,subscription_url,traffic_limit_gb,traffic_used_gb FROM subscriptions ORDER BY id'
        before = (await conn.execute(text(query))).all()

        def apply(sync_conn, direction):
            with Operations.context(MigrationContext.configure(sync_conn)):
                getattr(migration, direction)()

        await conn.run_sync(lambda connection: apply(connection, 'upgrade'))
        assert (await conn.execute(text(query))).all() == before
        assert (await conn.execute(text('SELECT balance_kopeks FROM users'))).scalar_one() == 12345
        assert (await conn.execute(text('SELECT traffic_mode FROM subscriptions'))).scalars().all() == ['shared'] * 3
        assert (
            await conn.execute(text('SELECT bs_traffic_enabled,bs_traffic_limit_gb,bs_squad_uuids FROM tariffs'))
        ).one() == (False, 0, [])
        assert (await conn.execute(text('SELECT count(*) FROM subscription_bs_accounts'))).scalar_one() == 0
        await conn.execute(
            text("""
            INSERT INTO subscription_bs_accounts
              (subscription_id,panel_username,provisioning_key,base_traffic_limit_gb)
            VALUES (1,'test_bs1','persisted-intent',100)
        """)
        )
        assert (
            await conn.execute(text('SELECT panel_status,migration_state FROM subscription_bs_accounts'))
        ).one() == ('DISABLED', 'pending')

        await conn.run_sync(lambda connection: apply(connection, 'downgrade'))
        assert (await conn.execute(text(query))).all() == before
        assert not await conn.run_sync(
            lambda connection: inspect(connection).has_table('subscription_bs_accounts', schema=schema)
        )
        await conn.run_sync(lambda connection: apply(connection, 'upgrade'))
        assert (await conn.execute(text(query))).all() == before
        await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
