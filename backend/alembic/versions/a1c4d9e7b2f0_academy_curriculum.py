"""academy curriculum and learner progress

Revision ID: a1c4d9e7b2f0
Revises: 1cb5bb2c7c3f
Create Date: 2026-10-20 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1c4d9e7b2f0'
down_revision: Union[str, None] = '1cb5bb2c7c3f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'academy_lessons',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('slug', sa.String(length=120), nullable=False),
        sa.Column('division', sa.String(length=20), nullable=False),
        sa.Column('category', sa.String(length=60), nullable=False),
        sa.Column('difficulty', sa.String(length=20), nullable=False),
        sa.Column('order_index', sa.Integer(), nullable=False),
        sa.Column('title_ar', sa.String(length=240), nullable=False),
        sa.Column('title_en', sa.String(length=240), nullable=False),
        sa.Column('summary_ar', sa.Text(), nullable=False),
        sa.Column('summary_en', sa.Text(), nullable=False),
        sa.Column('description_ar', sa.Text(), nullable=False),
        sa.Column('description_en', sa.Text(), nullable=False),
        sa.Column('objectives', sa.JSON(), nullable=False),
        sa.Column('prerequisites', sa.JSON(), nullable=False),
        sa.Column('related', sa.JSON(), nullable=False),
        sa.Column('video_url', sa.String(length=500), nullable=False),
        sa.Column('video_status', sa.String(length=30), nullable=False),
        sa.Column('resource_url', sa.String(length=500), nullable=False),
        sa.Column('resource_label_ar', sa.String(length=200), nullable=False),
        sa.Column('resource_label_en', sa.String(length=200), nullable=False),
        sa.Column('duration_minutes', sa.Integer(), nullable=False),
        sa.Column('exercise_ar', sa.Text(), nullable=False),
        sa.Column('exercise_en', sa.Text(), nullable=False),
        sa.Column('quiz', sa.JSON(), nullable=False),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('is_published', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_academy_lessons')),
    )
    with op.batch_alter_table('academy_lessons', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_academy_lessons_slug'), ['slug'], unique=True)
        batch_op.create_index(batch_op.f('ix_academy_lessons_division'), ['division'], unique=False)
        batch_op.create_index(batch_op.f('ix_academy_lessons_category'), ['category'], unique=False)
        batch_op.create_index(batch_op.f('ix_academy_lessons_difficulty'), ['difficulty'], unique=False)
        batch_op.create_index(batch_op.f('ix_academy_lessons_is_published'), ['is_published'], unique=False)
        batch_op.create_index('ix_academy_lessons_division_order', ['division', 'order_index'], unique=False)
        batch_op.create_index('ix_academy_lessons_division_category', ['division', 'category'], unique=False)

    op.create_table(
        'academy_lesson_progress',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('lesson_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('progress_percent', sa.Integer(), nullable=False),
        sa.Column('quiz_score', sa.Integer(), nullable=True),
        sa.Column('quiz_answers', sa.JSON(), nullable=False),
        sa.Column('quiz_attempts', sa.Integer(), nullable=False),
        sa.Column('bookmarked', sa.Boolean(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['lesson_id'], ['academy_lessons.id'], name=op.f('fk_academy_lesson_progress_lesson_id_academy_lessons'), ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_academy_lesson_progress_user_id_users'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_academy_lesson_progress')),
        sa.UniqueConstraint('user_id', 'lesson_id', name='uq_lesson_progress_user_lesson'),
    )
    with op.batch_alter_table('academy_lesson_progress', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_academy_lesson_progress_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_academy_lesson_progress_lesson_id'), ['lesson_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_academy_lesson_progress_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_academy_lesson_progress_bookmarked'), ['bookmarked'], unique=False)
        batch_op.create_index('ix_academy_progress_user_status', ['user_id', 'status'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('academy_lesson_progress', schema=None) as batch_op:
        batch_op.drop_index('ix_academy_progress_user_status')
        batch_op.drop_index(batch_op.f('ix_academy_lesson_progress_bookmarked'))
        batch_op.drop_index(batch_op.f('ix_academy_lesson_progress_status'))
        batch_op.drop_index(batch_op.f('ix_academy_lesson_progress_lesson_id'))
        batch_op.drop_index(batch_op.f('ix_academy_lesson_progress_user_id'))
    op.drop_table('academy_lesson_progress')

    with op.batch_alter_table('academy_lessons', schema=None) as batch_op:
        batch_op.drop_index('ix_academy_lessons_division_category')
        batch_op.drop_index('ix_academy_lessons_division_order')
        batch_op.drop_index(batch_op.f('ix_academy_lessons_is_published'))
        batch_op.drop_index(batch_op.f('ix_academy_lessons_difficulty'))
        batch_op.drop_index(batch_op.f('ix_academy_lessons_category'))
        batch_op.drop_index(batch_op.f('ix_academy_lessons_division'))
        batch_op.drop_index(batch_op.f('ix_academy_lessons_slug'))
    op.drop_table('academy_lessons')