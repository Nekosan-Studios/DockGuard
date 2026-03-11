"""add grype_version and db_built to app_state

Revision ID: e2f3a4b5c6d7
Revises: d1e2f3a4b5c6
Create Date: 2026-03-04 13:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e2f3a4b5c6d7"
down_revision: str | Sequence[str] | None = "d1e2f3a4b5c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("appstate", sa.Column("grype_version", sa.Text(), nullable=True))
    op.add_column("appstate", sa.Column("db_built", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("appstate", "db_built")
    op.drop_column("appstate", "grype_version")
