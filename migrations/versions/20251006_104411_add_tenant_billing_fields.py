"""add tenant billing fields

Revision ID: add_tenant_billing_fields
Revises:
Create Date: 2025-10-06
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_tenant_billing_fields'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('tenant') as batch:
        batch.add_column(sa.Column('pricing_rate_cents', sa.BigInteger(), nullable=False, server_default='0'))
        batch.add_column(sa.Column('outstanding_cents', sa.BigInteger(), nullable=False, server_default='0'))

def downgrade():
    with op.batch_alter_table('tenant') as batch:
        batch.drop_column('outstanding_cents')
        batch.drop_column('pricing_rate_cents')
