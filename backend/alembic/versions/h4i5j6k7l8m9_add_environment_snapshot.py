"""add environment snapshot table

Revision ID: h4i5j6k7l8m9
Revises: g3h4i5j6k7l8
Create Date: 2026-03-25 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "h4i5j6k7l8m9"
down_revision: str | Sequence[str] | None = "g3h4i5j6k7l8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "environmentsnapshot",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("container_count", sa.Integer(), nullable=False),
        sa.Column("urgent_count", sa.Integer(), nullable=False),
        sa.Column("kev_count", sa.Integer(), nullable=False),
        sa.Column("is_backfill", sa.Boolean(), nullable=False, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
    )

    bind = op.get_bind()

    # Backfill historical snapshots from existing scan data.
    #
    # Strategy: for each calendar day, identify the latest scan per image_name.
    # Days where fewer than 70% of the historical peak image count were scanned
    # are discarded — they represent partial/bad scan days (e.g. a Grype DB gap
    # that caused only a subset of containers to be rescanned).
    #
    # All available history is backfilled (no cutoff) so that future configurable
    # time-range views (60 days, 1 year, etc.) have data ready.

    # Temp table: latest scan ID per image per calendar day
    bind.execute(
        sa.text("""
            CREATE TEMP TABLE _day_image_scan AS
            SELECT
                date(scanned_at) AS day,
                image_name,
                MAX(id) AS scan_id,
                MAX(scanned_at) AS latest_scanned_at
            FROM scan
            WHERE is_update_check = 0 AND is_preview = 0
            GROUP BY date(scanned_at), image_name
        """)
    )

    # Temp table: per-day image count and latest timestamp
    bind.execute(
        sa.text("""
            CREATE TEMP TABLE _day_summary AS
            SELECT
                day,
                COUNT(*) AS image_count,
                MAX(latest_scanned_at) AS latest_ts
            FROM _day_image_scan
            GROUP BY day
        """)
    )

    # Insert one snapshot per qualifying day.
    # A day qualifies if its image_count >= 70% of the peak daily image count.
    # Uses LEFT JOIN so days with zero vulnerabilities are still captured.
    bind.execute(
        sa.text("""
            INSERT INTO environmentsnapshot
                (created_at, container_count, urgent_count, kev_count, is_backfill)
            SELECT
                ds.latest_ts,
                ds.image_count,
                COALESCE(SUM(CASE WHEN v.risk_score >= 80 THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN v.is_kev = 1 THEN 1 ELSE 0 END), 0),
                1
            FROM _day_summary ds
            JOIN _day_image_scan dis ON dis.day = ds.day
            LEFT JOIN vulnerability v ON v.scan_id = dis.scan_id
            WHERE ds.image_count >= (SELECT MAX(image_count) * 0.7 FROM _day_summary)
            GROUP BY ds.day, ds.latest_ts, ds.image_count
            ORDER BY ds.day ASC
        """)
    )

    bind.execute(sa.text("DROP TABLE _day_image_scan"))
    bind.execute(sa.text("DROP TABLE _day_summary"))


def downgrade() -> None:
    op.drop_table("environmentsnapshot")
