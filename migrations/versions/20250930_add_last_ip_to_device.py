"""add last_ip to device"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "add_last_ip_to_device"
down_revision = "add_rollout_id_o9eh890w"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("device") as batch:
        batch.add_column(sa.Column("last_ip", sa.String(length=45), nullable=True))

def downgrade():
    with op.batch_alter_table("device") as batch:
        batch.drop_column("last_ip")
