"""add performance indexes

Revision ID: a1b2c3d4e5f6
Revises: 6a033a2ce106
Create Date: 2026-03-04 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "6a033a2ce106"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add indexes on columns used in WHERE / ORDER BY clauses on hot paths."""
    op.create_index("ix_scan_image_name", "scan", ["image_name"])
    op.create_index("ix_scan_scanned_at", "scan", ["scanned_at"])
    op.create_index("ix_vulnerability_scan_id_severity", "vulnerability", ["scan_id", "severity"])
    op.create_index("ix_vulnerability_scan_id_is_kev", "vulnerability", ["scan_id", "is_kev"])


def downgrade() -> None:
    """Drop performance indexes."""
    op.drop_index("ix_vulnerability_scan_id_is_kev", table_name="vulnerability")
    op.drop_index("ix_vulnerability_scan_id_severity", table_name="vulnerability")
    op.drop_index("ix_scan_scanned_at", table_name="scan")
    op.drop_index("ix_scan_image_name", table_name="scan")
