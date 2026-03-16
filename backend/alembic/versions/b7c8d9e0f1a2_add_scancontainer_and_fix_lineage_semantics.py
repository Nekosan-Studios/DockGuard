"""add scancontainer and fix lineage semantics

Revision ID: b7c8d9e0f1a2
Revises: a0b1c2d3e4f5
Create Date: 2026-03-16 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b7c8d9e0f1a2"
down_revision: str | Sequence[str] | None = "a0b1c2d3e4f5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scancontainer",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("container_name", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "container_name", name="uq_scancontainer_scan_id_container_name"),
    )
    op.create_index(op.f("ix_scancontainer_container_name"), "scancontainer", ["container_name"], unique=False)
    op.create_index(op.f("ix_scancontainer_scan_id"), "scancontainer", ["scan_id"], unique=False)

    bind = op.get_bind()

    # Backfill historical single-container linkage where available.
    bind.execute(
        sa.text(
            """
            INSERT INTO scancontainer (scan_id, container_name)
            SELECT id, container_name
            FROM scan
            WHERE container_name IS NOT NULL AND TRIM(container_name) != ''
            """
        )
    )

    # Recompute first_seen_at with correct lineage semantics (image_name).
    bind.execute(
        sa.text(
            """
            UPDATE vulnerability
            SET first_seen_at = (
                SELECT MIN(s.scanned_at)
                FROM vulnerability v2
                JOIN scan s ON s.id = v2.scan_id
                WHERE v2.vuln_id = vulnerability.vuln_id
                  AND v2.package_name = vulnerability.package_name
                  AND v2.installed_version = vulnerability.installed_version
                  AND s.image_name = (
                      SELECT s0.image_name
                      FROM scan s0
                      WHERE s0.id = vulnerability.scan_id
                  )
            )
            """
        )
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_scancontainer_scan_id"), table_name="scancontainer")
    op.drop_index(op.f("ix_scancontainer_container_name"), table_name="scancontainer")
    op.drop_table("scancontainer")
