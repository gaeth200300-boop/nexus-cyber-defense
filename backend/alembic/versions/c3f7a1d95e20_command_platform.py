"""command platform: detection rules, cases, custody, posture, purple team

Revision ID: c3f7a1d95e20
Revises: a1c4d9e7b2f0
Create Date: 2026-10-20 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c3f7a1d95e20'
down_revision: Union[str, None] = 'a1c4d9e7b2f0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'sigma_rules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=True),
        sa.Column('name', sa.String(length=160), nullable=False),
        sa.Column('title', sa.String(length=240), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('author', sa.String(length=120), nullable=False),
        sa.Column('license', sa.String(length=60), nullable=False),
        sa.Column('level', sa.String(length=20), nullable=False),
        sa.Column('logsource', sa.JSON(), nullable=False),
        sa.Column('detection', sa.JSON(), nullable=False),
        sa.Column('fields', sa.JSON(), nullable=False),
        sa.Column('falsepositives', sa.JSON(), nullable=False),
        sa.Column('references', sa.JSON(), nullable=False),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('techniques', sa.JSON(), nullable=False),
        sa.Column('lessons', sa.JSON(), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=False),
        sa.Column('validation', sa.JSON(), nullable=False),
        sa.Column('last_validated_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_sigma_rules_project_id_projects'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_sigma_rules')),
        sa.UniqueConstraint('project_id', 'name', name='uq_sigma_rule_project_name'),
    )
    with op.batch_alter_table('sigma_rules', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_sigma_rules_project_id'), ['project_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_sigma_rules_name'), ['name'], unique=False)
        batch_op.create_index(batch_op.f('ix_sigma_rules_status'), ['status'], unique=False)
        batch_op.create_index('ix_sigma_rules_project_status', ['project_id', 'status'], unique=False)

    op.create_table(
        'case_files',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('reference', sa.String(length=40), nullable=False),
        sa.Column('title', sa.String(length=240), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('classification', sa.String(length=60), nullable=False),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('assignee_id', sa.String(length=36), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=False),
        sa.Column('opened_at', sa.DateTime(), nullable=False),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_case_files_project_id_projects'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_case_files')),
    )
    with op.batch_alter_table('case_files', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_case_files_project_id'), ['project_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_case_files_reference'), ['reference'], unique=False)
        batch_op.create_index(batch_op.f('ix_case_files_status'), ['status'], unique=False)
        batch_op.create_index('ix_case_files_project_status', ['project_id', 'status'], unique=False)

    op.create_table(
        'case_hypotheses',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=False),
        sa.Column('statement', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('confidence', sa.String(length=20), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('created_by', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['case_files.id'], name=op.f('fk_case_hypotheses_case_id_case_files'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_case_hypotheses')),
    )
    with op.batch_alter_table('case_hypotheses', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_case_hypotheses_case_id'), ['case_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_case_hypotheses_status'), ['status'], unique=False)
        batch_op.create_index('ix_case_hypotheses_case', ['case_id'], unique=False)

    op.create_table(
        'case_annotations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('entity_type', sa.String(length=40), nullable=False),
        sa.Column('entity_id', sa.String(length=36), nullable=False),
        sa.Column('author_id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['case_files.id'], name=op.f('fk_case_annotations_case_id_case_files'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_case_annotations')),
    )
    with op.batch_alter_table('case_annotations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_case_annotations_case_id'), ['case_id'], unique=False)
        batch_op.create_index('ix_case_annotations_case', ['case_id'], unique=False)

    op.create_table(
        'case_tasks',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=240), nullable=False),
        sa.Column('detail', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('assignee_id', sa.String(length=36), nullable=False),
        sa.Column('due_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['case_files.id'], name=op.f('fk_case_tasks_case_id_case_files'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_case_tasks')),
    )
    with op.batch_alter_table('case_tasks', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_case_tasks_case_id'), ['case_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_case_tasks_status'), ['status'], unique=False)
        batch_op.create_index('ix_case_tasks_case_status', ['case_id', 'status'], unique=False)

    op.create_table(
        'custody_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('evidence_id', sa.String(length=36), nullable=True),
        sa.Column('action', sa.String(length=30), nullable=False),
        sa.Column('actor_user_id', sa.String(length=36), nullable=False),
        sa.Column('actor_label', sa.String(length=160), nullable=False),
        sa.Column('location', sa.String(length=160), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
        sa.Column('sha256_at_action', sa.String(length=64), nullable=False),
        sa.Column('source_path', sa.String(length=300), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_custody_events_project_id_projects'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_custody_events')),
    )
    with op.batch_alter_table('custody_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_custody_events_project_id'), ['project_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_custody_events_evidence_id'), ['evidence_id'], unique=False)
        batch_op.create_index('ix_custody_events_evidence', ['evidence_id'], unique=False)

    op.create_table(
        'posture_snapshots',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('grade', sa.String(length=6), nullable=False),
        sa.Column('factors', sa.JSON(), nullable=False),
        sa.Column('missing_information', sa.JSON(), nullable=False),
        sa.Column('coverage', sa.JSON(), nullable=False),
        sa.Column('computed_by', sa.String(length=36), nullable=False),
        sa.Column('computed_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_posture_snapshots_project_id_projects'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_posture_snapshots')),
    )
    with op.batch_alter_table('posture_snapshots', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_posture_snapshots_project_id'), ['project_id'], unique=False)
        batch_op.create_index('ix_posture_snapshots_project_time', ['project_id', 'computed_at'], unique=False)

    op.create_table(
        'purple_simulations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('scenario_key', sa.String(length=80), nullable=False),
        sa.Column('scenario_title', sa.String(length=240), nullable=False),
        sa.Column('division', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('expected_telemetry', sa.JSON(), nullable=False),
        sa.Column('observed_telemetry', sa.JSON(), nullable=False),
        sa.Column('detections', sa.JSON(), nullable=False),
        sa.Column('missed', sa.JSON(), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], name=op.f('fk_purple_simulations_project_id_projects'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_purple_simulations')),
    )
    with op.batch_alter_table('purple_simulations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_purple_simulations_project_id'), ['project_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_purple_simulations_scenario_key'), ['scenario_key'], unique=False)
        batch_op.create_index(batch_op.f('ix_purple_simulations_status'), ['status'], unique=False)
        batch_op.create_index('ix_purple_simulations_project', ['project_id'], unique=False)

    op.create_table(
        'lesson_certificates',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('division', sa.String(length=20), nullable=False),
        sa.Column('display_name', sa.String(length=160), nullable=False),
        sa.Column('lessons_completed', sa.Integer(), nullable=False),
        sa.Column('average_quiz', sa.Float(), nullable=False),
        sa.Column('serial', sa.String(length=40), nullable=False),
        sa.Column('issued_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_lesson_certificates_user_id_users'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_lesson_certificates')),
    )
    with op.batch_alter_table('lesson_certificates', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_lesson_certificates_user_id'), ['user_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_lesson_certificates_division'), ['division'], unique=False)
        batch_op.create_index('ix_lesson_certificates_user_division', ['user_id', 'division'], unique=True)

    op.create_table(
        'user_preferences',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('theme', sa.String(length=20), nullable=False),
        sa.Column('locale', sa.String(length=10), nullable=False),
        sa.Column('dashboard_days', sa.Integer(), nullable=False),
        sa.Column('sidebar_collapsed', sa.Boolean(), nullable=False),
        sa.Column('saved_searches', sa.JSON(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_user_preferences_user_id_users'), ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_user_preferences')),
        sa.UniqueConstraint('user_id', name='uq_user_preferences_user'),
    )
    with op.batch_alter_table('user_preferences', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_preferences_user_id'), ['user_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('user_preferences', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_preferences_user_id'))
    op.drop_table('user_preferences')

    with op.batch_alter_table('lesson_certificates', schema=None) as batch_op:
        batch_op.drop_index('ix_lesson_certificates_user_division')
        batch_op.drop_index(batch_op.f('ix_lesson_certificates_division'))
        batch_op.drop_index(batch_op.f('ix_lesson_certificates_user_id'))
    op.drop_table('lesson_certificates')

    with op.batch_alter_table('purple_simulations', schema=None) as batch_op:
        batch_op.drop_index('ix_purple_simulations_project')
        batch_op.drop_index(batch_op.f('ix_purple_simulations_status'))
        batch_op.drop_index(batch_op.f('ix_purple_simulations_scenario_key'))
        batch_op.drop_index(batch_op.f('ix_purple_simulations_project_id'))
    op.drop_table('purple_simulations')

    with op.batch_alter_table('posture_snapshots', schema=None) as batch_op:
        batch_op.drop_index('ix_posture_snapshots_project_time')
        batch_op.drop_index(batch_op.f('ix_posture_snapshots_project_id'))
    op.drop_table('posture_snapshots')

    with op.batch_alter_table('custody_events', schema=None) as batch_op:
        batch_op.drop_index('ix_custody_events_evidence')
        batch_op.drop_index(batch_op.f('ix_custody_events_evidence_id'))
        batch_op.drop_index(batch_op.f('ix_custody_events_project_id'))
    op.drop_table('custody_events')

    with op.batch_alter_table('case_tasks', schema=None) as batch_op:
        batch_op.drop_index('ix_case_tasks_case_status')
        batch_op.drop_index(batch_op.f('ix_case_tasks_status'))
        batch_op.drop_index(batch_op.f('ix_case_tasks_case_id'))
    op.drop_table('case_tasks')

    with op.batch_alter_table('case_annotations', schema=None) as batch_op:
        batch_op.drop_index('ix_case_annotations_case')
        batch_op.drop_index(batch_op.f('ix_case_annotations_case_id'))
    op.drop_table('case_annotations')

    with op.batch_alter_table('case_hypotheses', schema=None) as batch_op:
        batch_op.drop_index('ix_case_hypotheses_case')
        batch_op.drop_index(batch_op.f('ix_case_hypotheses_status'))
        batch_op.drop_index(batch_op.f('ix_case_hypotheses_case_id'))
    op.drop_table('case_hypotheses')

    with op.batch_alter_table('case_files', schema=None) as batch_op:
        batch_op.drop_index('ix_case_files_project_status')
        batch_op.drop_index(batch_op.f('ix_case_files_status'))
        batch_op.drop_index(batch_op.f('ix_case_files_reference'))
        batch_op.drop_index(batch_op.f('ix_case_files_project_id'))
    op.drop_table('case_files')

    with op.batch_alter_table('sigma_rules', schema=None) as batch_op:
        batch_op.drop_index('ix_sigma_rules_project_status')
        batch_op.drop_index(batch_op.f('ix_sigma_rules_status'))
        batch_op.drop_index(batch_op.f('ix_sigma_rules_name'))
        batch_op.drop_index(batch_op.f('ix_sigma_rules_project_id'))
    op.drop_table('sigma_rules')
