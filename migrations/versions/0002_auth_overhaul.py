"""Auth overhaul: drop security question/answer, add SSO + phone fields.

Revision ID: 0002_auth_overhaul
Revises: 0001_initial
Create Date: 2026-01-02 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "0002_auth_overhaul"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("user", "security_question")
    op.drop_column("user", "security_answer")
    op.add_column("user", sa.Column("phone", sa.String(length=30), nullable=True))
    op.add_column(
        "user",
        sa.Column("auth_provider", sa.String(length=30), nullable=False, server_default="local"),
    )
    op.add_column("user", sa.Column("provider_sub", sa.String(length=255), nullable=True))
    op.add_column(
        "user",
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("user", sa.Column("picture", sa.String(length=500), nullable=True))


def downgrade() -> None:
    op.drop_column("user", "picture")
    op.drop_column("user", "email_verified")
    op.drop_column("user", "provider_sub")
    op.drop_column("user", "auth_provider")
    op.drop_column("user", "phone")
    op.add_column("user", sa.Column("security_answer", sa.String(length=250)))
    op.add_column("user", sa.Column("security_question", sa.String(length=250)))
