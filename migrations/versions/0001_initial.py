"""Initial schema: users (with role) and scans.

Revision ID: 0001_initial
Revises:
Create Date: 2026-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=250)),
        sa.Column("email", sa.String(length=100), unique=True, nullable=False),
        sa.Column("password", sa.String(length=500)),
        sa.Column("security_question", sa.String(length=250)),
        sa.Column("security_answer", sa.String(length=250)),
        sa.Column("role", sa.String(length=20), nullable=False, server_default="user"),
        sa.Column("created_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_user_email", "user", ["email"], unique=True)

    op.create_table(
        "scan",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("target", sa.String(length=2048), nullable=False),
        sa.Column("scan_type", sa.String(length=20), server_default="Passive Scan"),
        sa.Column("status", sa.String(length=20), server_default="queued", nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_scan_user_id", "scan", ["user_id"])
    op.create_index("ix_scan_status", "scan", ["status"])


def downgrade() -> None:
    op.drop_index("ix_scan_status", table_name="scan")
    op.drop_index("ix_scan_user_id", table_name="scan")
    op.drop_table("scan")
    op.drop_index("ix_user_email", table_name="user")
    op.drop_table("user")
