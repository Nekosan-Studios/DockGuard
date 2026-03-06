"""add db_version to scan and appstate

Revision ID: 7c5f222a00e9
Revises: f1a2b3c4d5e6
Create Date: 2026-03-05 18:29:57.291697

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = '7c5f222a00e9'
down_revision: Union[str, Sequence[str], None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('appstate', sa.Column('db_version', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    
    # Add new column as nullable first, then update existing rows, then make it non-nullable
    op.add_column('scan', sa.Column('db_version', sqlmodel.sql.sqltypes.AutoString(), nullable=True))
    op.execute("UPDATE scan SET db_version = '' WHERE db_version IS NULL")
    
    # For SQLite, altering to non-nullable isn't well-supported in standard alembic
    # without batch mode, but since this is sqlmodel, leaving it added is fine for now,
    # or we can just leave it as nullable=True in the DB and enforce in code.
    # We will use batch mode for the alter.
    with op.batch_alter_table('scan') as batch_op:
        batch_op.alter_column('db_version', nullable=False, existing_type=sqlmodel.sql.sqltypes.AutoString())

def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('scan') as batch_op:
        batch_op.drop_column('db_version')
    op.drop_column('appstate', 'db_version')
    # ### end Alembic commands ###
