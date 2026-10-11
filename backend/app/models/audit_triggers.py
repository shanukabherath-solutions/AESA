"""DB-level append-only enforcement for audit_logs (defence in depth on top of the hash chain)."""
from __future__ import annotations

from sqlalchemy import DDL, Table, event

SQLITE_TRIGGERS = [
    """CREATE TRIGGER IF NOT EXISTS audit_logs_no_update BEFORE UPDATE ON audit_logs
       BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END""",
    """CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete BEFORE DELETE ON audit_logs
       BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END""",
]

POSTGRES_STATEMENTS = [
    """CREATE OR REPLACE FUNCTION audit_logs_immutable() RETURNS trigger AS $$
       BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END; $$ LANGUAGE plpgsql""",
    """CREATE TRIGGER audit_logs_no_change BEFORE UPDATE OR DELETE ON audit_logs
       FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable()""",
]


def install(table: Table) -> None:
    for stmt in SQLITE_TRIGGERS:
        event.listen(table, "after_create", DDL(stmt).execute_if(dialect="sqlite"))
    for stmt in POSTGRES_STATEMENTS:
        event.listen(table, "after_create", DDL(stmt).execute_if(dialect="postgresql"))
