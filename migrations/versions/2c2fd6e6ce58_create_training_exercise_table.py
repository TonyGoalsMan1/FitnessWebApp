"""create training_exercise table

Revision ID: 2c2fd6e6ce58
Revises: 5eadc6bb2faa
Create Date: 2023-12-28 17:36:38.971728

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2c2fd6e6ce58'
down_revision = '5eadc6bb2faa'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('training_exercise',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('training_id', sa.Integer(), nullable=True),
    sa.Column('exercise_name', sa.String(length=100), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['training_id'], ['training.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('exercise_progress',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('exercise_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('progress', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['exercise_id'], ['training_exercise.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('exercise_progress')
    op.drop_table('training_exercise')
    # ### end Alembic commands ###
