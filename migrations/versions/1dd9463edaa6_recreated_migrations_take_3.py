"""Recreated migrations take 3

Revision ID: 1dd9463edaa6
Revises: 
Create Date: 2024-09-04 01:36:46.934221

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1dd9463edaa6'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('spread',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('odds_id', sa.String(length=50), nullable=False),
    sa.Column('update_time', sa.DateTime(), nullable=False),
    sa.Column('game_time', sa.DateTime(), nullable=False),
    sa.Column('home_team', sa.String(length=50), nullable=False),
    sa.Column('road_team', sa.String(length=50), nullable=False),
    sa.Column('home_team_spread', sa.Float(), nullable=False),
    sa.Column('road_team_spread', sa.Float(), nullable=False),
    sa.Column('week', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('odds_id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.Column('is_admin', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('weekly_result',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('week', sa.Integer(), nullable=True),
    sa.Column('team', sa.String(length=64), nullable=True),
    sa.Column('result', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('logs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('action_type', sa.String(length=50), nullable=True),
    sa.Column('description', sa.String(length=200), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('pick',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('week', sa.Integer(), nullable=True),
    sa.Column('team', sa.String(length=64), nullable=True),
    sa.Column('is_correct', sa.Boolean(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('pick')
    op.drop_table('logs')
    op.drop_table('weekly_result')
    op.drop_table('user')
    op.drop_table('spread')
    # ### end Alembic commands ###
