"""live sessions

revision: 0002
revises: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('live_sessions',
    sa.Column('analysis_id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('key_hash', sa.String(length=64), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_chunk_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('chunks', sa.Integer(), nullable=False),
    sa.Column('total_bytes', sa.Integer(), nullable=False),
    sa.Column('last_seq', sa.Integer(), nullable=False),
    sa.Column('creator_ip', sa.String(length=64), nullable=False),
    sa.Column('esp_header', sa.LargeBinary(), nullable=True),
    sa.Column('ike_header', sa.LargeBinary(), nullable=True),
    sa.ForeignKeyConstraint(['analysis_id'], ['analyses.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('analysis_id')
    )
    op.create_table('live_chunks',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('analysis_id', sa.String(length=36), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('esp_data', sa.LargeBinary(), nullable=False),
    sa.Column('ike_data', sa.LargeBinary(), nullable=True),
    sa.Column('packets', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['analysis_id'], ['analyses.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_live_chunks_analysis_id'), 'live_chunks', ['analysis_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_live_chunks_analysis_id'), table_name='live_chunks')
    op.drop_table('live_chunks')
    op.drop_table('live_sessions')
