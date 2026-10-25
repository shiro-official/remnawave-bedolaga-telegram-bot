"""The actual migration adds disabled storage without altering existing subscriptions."""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import text

from tests.fixtures.postgres_db import postgres_engine


pytestmark = pytest.mark.postgres
MIGRATION = Path(__file__).resolve().parents[2] / 'migrations/alembic/versions/0133_bs_public_links.py'


@pytest.mark.asyncio
async def test_public_link_revision_roundtrip_preserves_existing_data(postgres_database):
    spec = importlib.util.spec_from_file_location('migration_0133', MIGRATION)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    schema = f'public_link_migration_{uuid4().hex}'
    async with postgres_engine(postgres_database) as engine, engine.begin() as connection:
        await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        await connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))
        await connection.execute(
            text('CREATE TABLE subscriptions (id integer PRIMARY KEY, subscription_url text, balance bigint)')
        )
        await connection.execute(text("INSERT INTO subscriptions VALUES (1, 'https://example.test/existing', 12345)"))

        def apply(sync_connection, direction):
            with Operations.context(MigrationContext.configure(sync_connection)):
                getattr(migration, direction)()

        for direction in ('upgrade', 'downgrade', 'upgrade'):
            await connection.run_sync(lambda conn, direction=direction: apply(conn, direction))
            assert (await connection.execute(text('SELECT * FROM subscriptions'))).one() == (
                1,
                'https://example.test/existing',
                12345,
            )
            if direction == 'upgrade':
                assert await connection.scalar(text('SELECT count(*) FROM subscription_public_links')) == 0
        await connection.execute(
            text("""
            INSERT INTO subscription_public_links
                (subscription_id,token_hash,primary_id,primary_short_uuid,secondary_id,secondary_short_uuid)
            VALUES (1,repeat('a',64),1000,'primary',2000,'secondary')
        """)
        )
        assert (
            await connection.execute(text('SELECT enabled, rotation_pending FROM subscription_public_links'))
        ).one() == (False, False)
        await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
