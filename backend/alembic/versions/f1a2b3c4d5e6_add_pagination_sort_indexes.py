"""add pagination sort indexes

Revision ID: f1a2b3c4d5e6
Revises: a1b2c3d4e5f6
Create Date: 2026-03-05 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: str | Sequence[str] | None = "85896e7c6488"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add composite indexes to support server-side sort + pagination on vulnerability queries."""
    # Covers ORDER BY cvss_base_score + cursor range scans
    op.create_index(
        "ix_vulnerability_scan_id_cvss",
        "vulnerability",
        ["scan_id", "cvss_base_score", "id"],
    )
    # Covers ORDER BY epss_score + cursor range scans
    op.create_index(
        "ix_vulnerability_scan_id_epss",
        "vulnerability",
        ["scan_id", "epss_score", "id"],
    )
    # Covers ORDER BY first_seen_at (new-24h report) + cursor range scans
    op.create_index(
        "ix_vulnerability_scan_id_first_seen",
        "vulnerability",
        ["scan_id", "first_seen_at", "id"],
    )


def downgrade() -> None:
    """Drop pagination sort indexes."""
    op.drop_index("ix_vulnerability_scan_id_first_seen", table_name="vulnerability")
    op.drop_index("ix_vulnerability_scan_id_epss", table_name="vulnerability")
    op.drop_index("ix_vulnerability_scan_id_cvss", table_name="vulnerability")
