"""add notification tables

Revision ID: a0b1c2d3e4f5
Revises: f1a2b3c4d5e6
Create Date: 2026-03-15 00:00:00.000000
"""

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision = "a0b1c2d3e4f5"
down_revision = "c6d7e8f9a0b1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notificationchannel",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("apprise_url", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("notify_urgent", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("notify_all_new", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("notify_digest", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("notify_kev", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("notify_eol", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("notify_scan_failure", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "notificationlog",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("channel_id", sa.Integer(), nullable=False),
        sa.Column("notification_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("body", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("error_message", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["channel_id"], ["notificationchannel.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("appstate") as batch_op:
        batch_op.add_column(sa.Column("last_digest_data", sqlmodel.sql.sqltypes.AutoString(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("appstate") as batch_op:
        batch_op.drop_column("last_digest_data")
    op.drop_table("notificationlog")
    op.drop_table("notificationchannel")
