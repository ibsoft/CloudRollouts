"""merge billing with main history

Revision ID: 16524c92f487
Revises: add_is_global_1759477018, add_tenant_billing_fields
Create Date: 2025-10-06 13:53:08.605382

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '16524c92f487'
down_revision = ('add_is_global_1759477018', 'add_tenant_billing_fields')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
