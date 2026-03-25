"""add source_task_id to scan

Revision ID: g3h4i5j6k7l8
Revises: f2a3b4c5d6e7
Create Date: 2026-03-24 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "g3h4i5j6k7l8"
down_revision: str | Sequence[str] | None = "f2a3b4c5d6e7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan") as batch_op:
        batch_op.add_column(sa.Column("source_task_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_scan_source_task_id",
            "systemtask",
            ["source_task_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("scan") as batch_op:
        batch_op.drop_constraint("fk_scan_source_task_id", type_="foreignkey")
        batch_op.drop_column("source_task_id")
