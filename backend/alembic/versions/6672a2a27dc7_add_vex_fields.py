"""add_vex_fields

Revision ID: 6672a2a27dc7
Revises: fe90de88bb33
Create Date: 2026-03-07 12:09:03.759972

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '6672a2a27dc7'
down_revision: Union[str, Sequence[str], None] = 'fe90de88bb33'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add VEX fields to scan and vulnerability tables."""
    op.add_column('scan', sa.Column('vex_status', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('scan', sa.Column('vex_source', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('scan', sa.Column('vex_checked_at', sa.DateTime(), nullable=True))
    op.add_column('vulnerability', sa.Column('vex_status', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('vulnerability', sa.Column('vex_justification', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.add_column('vulnerability', sa.Column('vex_statement', sqlmodel.sql.sqltypes.AutoString(), nullable=True))


def downgrade() -> None:
    """Remove VEX fields from scan and vulnerability tables."""
    op.drop_column('vulnerability', 'vex_statement')
    op.drop_column('vulnerability', 'vex_justification')
    op.drop_column('vulnerability', 'vex_status')
    op.drop_column('scan', 'vex_checked_at')
    op.drop_column('scan', 'vex_source')
    op.drop_column('scan', 'vex_status')
