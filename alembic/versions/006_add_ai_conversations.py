"""Add AI conversations tables

Revision ID: 006
Revises: 005
Create Date: 2026-02-03

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade():
    # Create ai_conversations table
    op.create_table(
        'ai_conversations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('conversation_id', sa.String(length=100), nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('repository_id', sa.Integer(), nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=True),
        sa.Column('focus', sa.String(length=100), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True, default=True),
        sa.Column('message_count', sa.Integer(), nullable=True, default=0),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.Column('last_message_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(
        'ix_ai_conversations_conversation_id',
        'ai_conversations',
        ['conversation_id'],
        unique=True
    )
    op.create_index(
        'ix_ai_conversations_project_id',
        'ai_conversations',
        ['project_id']
    )
    op.create_index(
        'ix_ai_conversations_repository_id',
        'ai_conversations',
        ['repository_id']
    )

    # Create ai_messages table
    op.create_table(
        'ai_messages',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('message_id', sa.String(length=100), nullable=False),
        sa.Column('conversation_id', sa.Integer(), nullable=False),
        sa.Column('role', sa.Enum('USER', 'ASSISTANT', 'SYSTEM', name='messagerole'), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('thinking', sa.Text(), nullable=True),
        sa.Column('needs_clarification', sa.Boolean(), nullable=True, default=False),
        sa.Column('clarification_question', sa.Text(), nullable=True),
        sa.Column('context_used', sa.JSON(), nullable=True),
        sa.Column('tokens_used', sa.Integer(), nullable=True),
        sa.Column('confidence_score', sa.Integer(), nullable=True),
        sa.Column('web_search_performed', sa.Boolean(), nullable=True, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['conversation_id'], ['ai_conversations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(
        'ix_ai_messages_message_id',
        'ai_messages',
        ['message_id'],
        unique=True
    )
    op.create_index(
        'ix_ai_messages_conversation_id',
        'ai_messages',
        ['conversation_id']
    )

    # Create ai_citations table
    op.create_table(
        'ai_citations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('citation_id', sa.String(length=100), nullable=False),
        sa.Column('message_id', sa.Integer(), nullable=False),
        sa.Column('type', sa.Enum('REPOSITORY', 'SCAN_RESULT', 'VULNERABILITY', 'WEB', 'DOCUMENTATION', name='citationtype'), nullable=False),
        sa.Column('source', sa.String(length=500), nullable=False),
        sa.Column('reference', sa.String(length=1000), nullable=False),
        sa.Column('excerpt', sa.Text(), nullable=True),
        sa.Column('url', sa.String(length=2000), nullable=True),
        sa.Column('relevance_score', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['message_id'], ['ai_messages.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(
        'ix_ai_citations_citation_id',
        'ai_citations',
        ['citation_id'],
        unique=True
    )
    op.create_index(
        'ix_ai_citations_message_id',
        'ai_citations',
        ['message_id']
    )


def downgrade():
    op.drop_index('ix_ai_citations_message_id', table_name='ai_citations')
    op.drop_index('ix_ai_citations_citation_id', table_name='ai_citations')
    op.drop_table('ai_citations')

    op.drop_index('ix_ai_messages_conversation_id', table_name='ai_messages')
    op.drop_index('ix_ai_messages_message_id', table_name='ai_messages')
    op.drop_table('ai_messages')

    op.drop_index('ix_ai_conversations_repository_id', table_name='ai_conversations')
    op.drop_index('ix_ai_conversations_project_id', table_name='ai_conversations')
    op.drop_index('ix_ai_conversations_conversation_id', table_name='ai_conversations')
    op.drop_table('ai_conversations')

    # Drop enums
    sa.Enum(name='citationtype').drop(op.get_bind(), checkfirst=False)
    sa.Enum(name='messagerole').drop(op.get_bind(), checkfirst=False)
