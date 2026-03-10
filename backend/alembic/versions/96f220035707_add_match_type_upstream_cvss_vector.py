"""Add match_type, upstream_name, cvss_vector to Vulnerability

Revision ID: 96f220035707
Revises: 7af8f5421cf2
Create Date: 2026-03-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '96f220035707'
down_revision: Union[str, Sequence[str], None] = 'f821d6764dee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add match_type, upstream_name, and cvss_vector columns to vulnerability table."""
    op.add_column('vulnerability', sa.Column('match_type', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('vulnerability', sa.Column('upstream_name', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvss_vector', sqlmodel.sql.sqltypes.AutoString(), nullable=True))


def downgrade() -> None:
    """Remove match_type, upstream_name, and cvss_vector columns from vulnerability table."""
    op.drop_column('vulnerability', 'cvss_vector')
    op.drop_column('vulnerability', 'upstream_name')
    op.drop_column('vulnerability', 'match_type')
