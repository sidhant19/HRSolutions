"""new constraint lastlogin

Revision ID: 6326e73641da
Revises: ab9df6c1a05b
Create Date: 2023-08-11 13:08:30.105738

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6326e73641da'
down_revision = 'ab9df6c1a05b'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('last_login',
               existing_type=sa.DATETIME(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('last_login',
               existing_type=sa.DATETIME(),
               nullable=False)

    # ### end Alembic commands ###
