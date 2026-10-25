"""Hashed public capabilities and durable paired-revoke intent; no rollout."""

import sqlalchemy as sa
from alembic import op


revision = '0133'
down_revision = '0132'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'subscription_public_links',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('subscription_id', sa.Integer(), sa.ForeignKey('subscriptions.id', ondelete='CASCADE'),
                  nullable=False, unique=True),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('primary_id', sa.BigInteger(), nullable=False),
        sa.Column('primary_short_uuid', sa.String(255), nullable=False),
        sa.Column('secondary_id', sa.BigInteger(), nullable=False),
        sa.Column('secondary_short_uuid', sa.String(255), nullable=False),
        sa.Column('rotation_pending', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('rotation_intent', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    # Removes capabilities/intents, never restores already rotated panel keys.
    op.drop_table('subscription_public_links')
