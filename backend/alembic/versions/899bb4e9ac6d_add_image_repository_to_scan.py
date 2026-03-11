"""add_image_repository_to_scan

Revision ID: 899bb4e9ac6d
Revises: 6cfd79ed8096
Create Date: 2026-02-24 10:28:56.409466

"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "899bb4e9ac6d"
down_revision: str | Sequence[str] | None = "6cfd79ed8096"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _parse_image_repository(image_ref: str) -> str:
    """Extract repository from image_ref by stripping the tag."""
    last_colon = image_ref.rfind(":")
    if last_colon == -1:
        return image_ref
    if "/" not in image_ref[last_colon + 1 :]:
        return image_ref[:last_colon]
    return image_ref


def upgrade() -> None:
    """Upgrade schema."""
    # Step 1: add as nullable so existing rows are not rejected
    op.add_column("scan", sa.Column("image_repository", sqlmodel.sql.sqltypes.AutoString(), nullable=True))

    # Step 2: backfill existing rows by stripping the tag from image_name
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, image_name FROM scan")).fetchall()
    for row_id, image_name in rows:
        repo = _parse_image_repository(image_name)
        bind.execute(
            sa.text("UPDATE scan SET image_repository = :repo WHERE id = :id"),
            {"repo": repo, "id": row_id},
        )

    # Step 3: make non-nullable now that all rows have a value
    with op.batch_alter_table("scan") as batch_op:
        batch_op.alter_column("image_repository", nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("scan") as batch_op:
        batch_op.drop_column("image_repository")
