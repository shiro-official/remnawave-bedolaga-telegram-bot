"""Separate BS traffic configuration and a recoverable secondary identity.

This migration changes storage only. It does not call the panel, create users,
change balances or quotas, or convert existing subscriptions to split traffic.
"""

import sqlalchemy as sa
from alembic import op


revision = '0132'
down_revision = '0131'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('tariffs', sa.Column('bs_traffic_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('tariffs', sa.Column('bs_traffic_limit_gb', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('tariffs', sa.Column('bs_squad_uuids', sa.JSON(), nullable=False, server_default='[]'))
    op.add_column('subscriptions', sa.Column('traffic_mode', sa.String(16), nullable=False, server_default='shared'))
    op.create_table(
        'subscription_bs_accounts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column(
            'subscription_id',
            sa.Integer(),
            sa.ForeignKey('subscriptions.id', ondelete='CASCADE'),
            nullable=False,
            unique=True,
        ),
        sa.Column('panel_username', sa.String(36), nullable=False, unique=True),
        sa.Column('provisioning_key', sa.String(32), nullable=False, unique=True),
        sa.Column('remnawave_id', sa.BigInteger(), nullable=True, unique=True),
        sa.Column('remnawave_short_uuid', sa.String(255), nullable=True, unique=True),
        sa.Column('base_traffic_limit_gb', sa.Integer(), nullable=False),
        sa.Column('traffic_limit_override_gb', sa.Integer(), nullable=True),
        sa.Column('purchased_traffic_gb', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('traffic_used_bytes', sa.BigInteger(), nullable=False, server_default='0'),
        sa.Column('panel_status', sa.String(20), nullable=False, server_default='DISABLED'),
        sa.Column('migration_state', sa.String(16), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint('base_traffic_limit_gb > 0', name='ck_bs_account_base_limit'),
        sa.CheckConstraint(
            'traffic_limit_override_gb IS NULL OR traffic_limit_override_gb > 0', name='ck_bs_account_override_limit'
        ),
        sa.CheckConstraint('purchased_traffic_gb >= 0', name='ck_bs_account_purchased_traffic'),
        sa.CheckConstraint('traffic_used_bytes >= 0', name='ck_bs_account_used_traffic'),
        sa.CheckConstraint(
            "migration_state IN ('pending', 'prepared', 'active')", name='ck_bs_account_migration_state'
        ),
    )


def downgrade() -> None:
    # Application data-loss policy is handled by the explicit deployment/rollback plan.
    op.drop_table('subscription_bs_accounts')
    op.drop_column('subscriptions', 'traffic_mode')
    op.drop_column('tariffs', 'bs_squad_uuids')
    op.drop_column('tariffs', 'bs_traffic_limit_gb')
    op.drop_column('tariffs', 'bs_traffic_enabled')
