"""add is_update_check to scan and imageupdatecheck table

Revision ID: d4e5f6a7b8c9
Revises: c9d0e1f2a3b4
Create Date: 2026-03-17 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: str | Sequence[str] | None = "c9d0e1f2a3b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("scan") as batch_op:
        batch_op.add_column(
            sa.Column(
                "is_update_check",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )

    op.create_table(
        "imageupdatecheck",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("image_name", sa.String(), nullable=False),
        sa.Column("running_digest", sa.String(), nullable=False),
        sa.Column("registry_digest", sa.String(), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("update_scan_id", sa.Integer(), sa.ForeignKey("scan.id"), nullable=True),
        sa.Column("current_scan_id", sa.Integer(), sa.ForeignKey("scan.id"), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.UniqueConstraint("image_name", name="uq_imageupdatecheck_image_name"),
    )
    op.create_index("ix_imageupdatecheck_image_name", "imageupdatecheck", ["image_name"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_imageupdatecheck_image_name", table_name="imageupdatecheck")
    op.drop_table("imageupdatecheck")

    with op.batch_alter_table("scan") as batch_op:
        batch_op.drop_column("is_update_check")
