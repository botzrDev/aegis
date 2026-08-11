-- AEG-32 / AILAB-122 — governance slice 4: pgvector learning fabric (D24).
--
-- Only learning patterns are durable. The ingest buffer, drift findings, and
-- the policy-pack registry stay in-process on GovernanceState (D21–D23).
--
-- Columns hold audit outcome fields only: no raw prompt/input/output text, no
-- agent or project identity. `embedding` is a deterministic, versioned
-- encoding (aegis_governance.learning.FEATURE_SCHEMA_VERSION), never a live
-- LLM embedding.
--
-- The audit_schema_version CHECK moved 1 -> 2 in AILAB-624. This file only
-- governs a *fresh* database: CREATE TABLE IF NOT EXISTS is a no-op against an
-- existing one, so 002 carries the same change to databases already created.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS learning_patterns (
    pattern_id UUID PRIMARY KEY,
    call_id TEXT NOT NULL UNIQUE,
    tool_id TEXT NOT NULL,
    audit_schema_version INTEGER NOT NULL
        CONSTRAINT learning_patterns_audit_schema_version_check
        CHECK (audit_schema_version = 2),
    feature_schema_version INTEGER NOT NULL,
    embedding vector(16) NOT NULL,
    content JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS learning_patterns_tool_id_idx
    ON learning_patterns (tool_id);

CREATE INDEX IF NOT EXISTS learning_patterns_embedding_hnsw_idx
    ON learning_patterns USING hnsw (embedding vector_cosine_ops);
