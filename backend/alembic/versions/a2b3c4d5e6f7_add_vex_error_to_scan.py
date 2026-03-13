"""add_vex_error_to_scan

Revision ID: a2b3c4d5e6f7
Revises: 6672a2a27dc7
Create Date: 2026-03-13 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
import sqlmodel
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a2b3c4d5e6f7"
down_revision: str | Sequence[str] | None = "96f220035707"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add vex_error column to scan table to store error details when VEX check fails."""
    op.add_column("scan", sa.Column("vex_error", sqlmodel.sql.sqltypes.AutoString(), nullable=True))


def downgrade() -> None:
    """Remove vex_error column from scan table."""
    op.drop_column("scan", "vex_error")
