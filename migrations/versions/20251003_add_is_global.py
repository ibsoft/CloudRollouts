"""make apikey tenant_id nullable and add is_global

Revision ID: add_is_global_1759477018
Revises: add_last_ip_to_device
Create Date: 2025-10-03 07:36:58.438115
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_is_global_1759477018'
down_revision = 'add_last_ip_to_device'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('api_key') as batch_op:
        batch_op.alter_column('tenant_id', existing_type=sa.Integer(), nullable=True)
        batch_op.add_column(sa.Column('is_global', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.execute("UPDATE api_key SET is_global=0 WHERE is_global IS NULL")

def downgrade():
    with op.batch_alter_table('api_key') as batch_op:
        batch_op.drop_column('is_global')
        batch_op.alter_column('tenant_id', existing_type=sa.Integer(), nullable=False)
