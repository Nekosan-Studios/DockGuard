"""add pending_task_id to imageupdatecheck

Revision ID: f2a3b4c5d6e7
Revises: e5f6a7b8c9d0
Create Date: 2026-03-19 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f2a3b4c5d6e7"
down_revision: str | Sequence[str] | None = "e5f6a7b8c9d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("imageupdatecheck") as batch_op:
        batch_op.add_column(sa.Column("pending_task_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_imageupdatecheck_pending_task_id",
            "systemtask",
            ["pending_task_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("imageupdatecheck") as batch_op:
        batch_op.drop_constraint("fk_imageupdatecheck_pending_task_id", type_="foreignkey")
        batch_op.drop_column("pending_task_id")
