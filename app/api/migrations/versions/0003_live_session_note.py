"""live session note

revision: 0003
revises: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('live_sessions', sa.Column('note', sa.String(length=200), nullable=False, server_default=''))
    op.alter_column('live_sessions', 'note', server_default=None)


def downgrade():
    op.drop_column('live_sessions', 'note')
