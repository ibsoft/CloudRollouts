"""add rollout_id to device_installation

Revision ID: add_rollout_id_o9eh890w
Revises: 68a85c375b83
Create Date: 2025-09-30 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_rollout_id_o9eh890w"
down_revision = "68a85c375b83"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("device_installation") as batch_op:
        batch_op.add_column(sa.Column("rollout_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_device_installation_rollout", ["rollout_id"], unique=False)
        batch_op.create_foreign_key("fk_device_installation_rollout", "rollout", ["rollout_id"], ["id"])

def downgrade():
    with op.batch_alter_table("device_installation") as batch_op:
        batch_op.drop_constraint("fk_device_installation_rollout", type_="foreignkey")
        batch_op.drop_index("ix_device_installation_rollout")
        batch_op.drop_column("rollout_id")
