"""add db_schema to app_state

Revision ID: fe90de88bb33
Revises: 7af8f5421cf2
Create Date: 2026-03-05 19:39:19.260940

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "fe90de88bb33"
down_revision: str | Sequence[str] | None = "7af8f5421cf2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("appstate", sa.Column("db_schema", sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("appstate", "db_schema")
