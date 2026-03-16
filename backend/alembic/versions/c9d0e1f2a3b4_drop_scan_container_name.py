"""drop legacy scan.container_name

Revision ID: c9d0e1f2a3b4
Revises: b7c8d9e0f1a2
Create Date: 2026-03-16 14:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c9d0e1f2a3b4"
down_revision: str | Sequence[str] | None = "b7c8d9e0f1a2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan") as batch_op:
        batch_op.drop_column("container_name")


def downgrade() -> None:
    with op.batch_alter_table("scan") as batch_op:
        batch_op.add_column(sa.Column("container_name", sa.String(), nullable=True))
