"""Added measurings

Revision ID: 75c60c8151d5
Revises: 8548c94241d9
Create Date: 2023-02-21 11:42:39.106843

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "75c60c8151d5"
down_revision = "8548c94241d9"
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "measurings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("statistics", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("build_task_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["build_task_id"],
            ["build_tasks.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column("build_tasks", sa.Column("started_at", sa.DateTime(), nullable=True))
    op.add_column("build_tasks", sa.Column("finished_at", sa.DateTime(), nullable=True))
    op.add_column("builds", sa.Column("finished_at", sa.DateTime(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("builds", "finished_at")
    op.drop_column("build_tasks", "finished_at")
    op.drop_column("build_tasks", "started_at")
    op.drop_table("measurings")
    # ### end Alembic commands ###
