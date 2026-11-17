"""Documents and the outbox, in the product's Postgres.

A document's row holds its tenant, type, status, who uploaded it, its name (cleaned), format, size,
SHA-256, the scan's verdict, the fields read from it and any review. The file itself is in object
storage, keyed by the document's id: never its name.

Status: awaiting_upload -> uploaded -> (rejected | needs_review | extracted) -> reviewed;
failed when checks can't run after several tries.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from .relay_types import Outgoing, Queued

STATUSES = ("awaiting_upload", "uploaded", "rejected", "needs_review", "extracted", "reviewed", "failed")


@dataclass(frozen=True)
class Document:
    id: str
    tenant: str
    type: str
    status: str
    uploaded_by: str
    filename: str
    declared_format: str
    size: int
    created_at: datetime
    sha256: str = ""
    format: str = ""
    problem: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    reviewed_by: str = ""
    attempts: int = 0

    @property
    def key(self) -> str:
        return f"{self.tenant}/{self.id}"


def now() -> datetime:
    return datetime.now(UTC)


def new_id() -> str:
    return f"doc_{uuid.uuid4().hex}"


class Store(Protocol):
    def create(self, doc: Document) -> None: ...
    def get(self, doc_id: str, tenants: frozenset[str] | None) -> Document | None: ...
    def update(self, doc: Document, events: list[Outgoing] | None = None, *, expect: str = "") -> bool: ...
    def due(self, limit: int) -> list[Document]: ...
    def queue(self, tenants: frozenset[str], limit: int) -> list[Document]: ...
    def expired(self, retention: dict[str, int], limit: int) -> list[Document]: ...
    def forget(self, doc: Document) -> None: ...
    def claim(self, limit: int = 100) -> list[Queued]: ...
    def published(self, ids: list[int]) -> None: ...


class MemoryStore:
    def __init__(self) -> None:
        self.docs: dict[str, Document] = {}
        self.outbox: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def create(self, doc: Document) -> None:
        with self.lock:
            self.docs[doc.id] = doc

    def get(self, doc_id: str, tenants: frozenset[str] | None) -> Document | None:
        d = self.docs.get(doc_id)
        return d if d and (tenants is None or d.tenant in tenants) else None

    def update(self, doc: Document, events: list[Outgoing] | None = None, *, expect: str = "") -> bool:
        with self.lock:
            cur = self.docs.get(doc.id)
            if cur is None or (expect and cur.status != expect):
                return False
            self.docs[doc.id] = doc
            for e in events or []:
                self.outbox.append(
                    {
                        "id": len(self.outbox) + 1,
                        "topic": e.topic,
                        "key": e.key,
                        "value": e.value,
                        "headers": e.headers,
                        "sent": False,
                    }
                )
            return True

    def due(self, limit: int) -> list[Document]:
        return [d for d in self.docs.values() if d.status == "uploaded"][:limit]

    def queue(self, tenants: frozenset[str], limit: int) -> list[Document]:
        rows = [d for d in self.docs.values() if d.status == "needs_review" and d.tenant in tenants]
        return sorted(rows, key=lambda d: d.created_at)[:limit]

    def expired(self, retention: dict[str, int], limit: int) -> list[Document]:
        t = now()
        return [
            d
            for d in self.docs.values()
            if d.type in retention and d.created_at < t - timedelta(days=retention[d.type])
        ][:limit]

    def forget(self, doc: Document) -> None:
        self.docs.pop(doc.id, None)

    def claim(self, limit: int = 100) -> list[Queued]:
        return [
            Queued(r["id"], r["topic"], r["key"], r["value"], r["headers"])
            for r in self.outbox
            if not r["sent"]
        ][:limit]

    def published(self, ids: list[int]) -> None:
        for r in self.outbox:
            if r["id"] in ids:
                r["sent"] = True


SCHEMA = """
create table if not exists intake_documents (
  id text primary key,
  tenant text not null,
  type text not null,
  status text not null,
  uploaded_by text not null,
  filename text not null,
  declared_format text not null,
  size bigint not null,
  created_at timestamptz not null default now(),
  sha256 text not null default '',
  format text not null default '',
  problem text not null default '',
  fields jsonb not null default '{}',
  reviewed_by text not null default '',
  attempts int not null default 0
);
create index if not exists intake_documents_due on intake_documents (created_at) where status = 'uploaded';
create index if not exists intake_documents_review on intake_documents (tenant, created_at)
  where status = 'needs_review';
create table if not exists intake_outbox (
  id bigserial primary key,
  topic text not null,
  key text not null,
  value jsonb not null,
  headers jsonb not null default '{}',
  created_at timestamptz not null default now(),
  sent_at timestamptz
);
create index if not exists intake_outbox_unsent on intake_outbox (id) where sent_at is null;
"""
COLUMNS = (
    "id",
    "tenant",
    "type",
    "status",
    "uploaded_by",
    "filename",
    "declared_format",
    "size",
    "created_at",
    "sha256",
    "format",
    "problem",
    "fields",
    "reviewed_by",
    "attempts",
)
# Every statement is a literal: nothing is ever formatted into SQL.
SELECT = (
    "select id, tenant, type, status, uploaded_by, filename, declared_format, size, created_at, sha256,"
    " format, problem, fields, reviewed_by, attempts from intake_documents"
)
INSERT = (
    "insert into intake_documents (id, tenant, type, status, uploaded_by, filename, declared_format, size,"
    " created_at, sha256, format, problem, fields, reviewed_by, attempts)"
    " values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
UPDATE = (
    "update intake_documents set type = %s, status = %s, uploaded_by = %s, filename = %s,"
    " declared_format = %s, size = %s, sha256 = %s, format = %s, problem = %s, fields = %s,"
    " reviewed_by = %s, attempts = %s"
    " where id = %s and (%s = '' or status = %s)"
)
UPDATED = (
    "type",
    "status",
    "uploaded_by",
    "filename",
    "declared_format",
    "size",
    "sha256",
    "format",
    "problem",
    "fields",
    "reviewed_by",
    "attempts",
)
BY_ID = SELECT + " where id = %s"
BY_ID_IN = SELECT + " where id = %s and tenant = any(%s)"
DUE = SELECT + " where status = 'uploaded' order by created_at limit %s"
QUEUE = SELECT + " where status = 'needs_review' and tenant = any(%s) order by created_at limit %s"
EXPIRED = SELECT + " where type = %s and created_at < now() - make_interval(days => %s) limit %s"


def _row(r: Any) -> Document:
    return Document(**dict(zip(COLUMNS, r, strict=True)))


def _values(doc: Document, columns: tuple[str, ...]) -> list[Any]:
    return [json.dumps(doc.fields) if c == "fields" else getattr(doc, c) for c in columns]


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        from psycopg_pool import ConnectionPool

        self.pool = ConnectionPool(dsn, min_size=1, max_size=5, open=True, kwargs={"autocommit": True})
        with self.pool.connection() as conn:
            conn.execute(SCHEMA)

    def create(self, doc: Document) -> None:
        with self.pool.connection() as conn:
            conn.execute(INSERT, _values(doc, COLUMNS))

    def get(self, doc_id: str, tenants: frozenset[str] | None) -> Document | None:
        with self.pool.connection() as conn:
            r = (
                conn.execute(BY_ID, (doc_id,))
                if tenants is None
                else conn.execute(BY_ID_IN, (doc_id, sorted(tenants)))
            ).fetchone()
        return _row(r) if r else None

    def update(self, doc: Document, events: list[Outgoing] | None = None, *, expect: str = "") -> bool:
        with self.pool.connection() as conn, conn.transaction():
            cur = conn.execute(UPDATE, [*_values(doc, UPDATED), doc.id, expect, expect])
            if not cur.rowcount:
                return False
            for e in events or []:
                conn.execute(
                    "insert into intake_outbox (topic, key, value, headers) values (%s, %s, %s, %s)",
                    (e.topic, e.key, json.dumps(e.value), json.dumps(e.headers)),
                )
            return True

    def due(self, limit: int) -> list[Document]:
        with self.pool.connection() as conn:
            return [_row(r) for r in conn.execute(DUE, (limit,)).fetchall()]

    def queue(self, tenants: frozenset[str], limit: int) -> list[Document]:
        with self.pool.connection() as conn:
            return [_row(r) for r in conn.execute(QUEUE, (sorted(tenants), limit)).fetchall()]

    def expired(self, retention: dict[str, int], limit: int) -> list[Document]:
        out: list[Document] = []
        with self.pool.connection() as conn:
            for t, days in sorted(retention.items()):
                out += [_row(r) for r in conn.execute(EXPIRED, (t, days, limit)).fetchall()]
        return out[:limit]

    def forget(self, doc: Document) -> None:
        with self.pool.connection() as conn:
            conn.execute("delete from intake_documents where id = %s", (doc.id,))

    def claim(self, limit: int = 100) -> list[Queued]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                "select id, topic, key, value, headers from intake_outbox where sent_at is null"
                " order by id limit %s",
                (limit,),
            ).fetchall()
        return [Queued(int(r[0]), r[1], r[2], r[3], r[4]) for r in rows]

    def published(self, ids: list[int]) -> None:
        if ids:
            with self.pool.connection() as conn:
                conn.execute("update intake_outbox set sent_at = now() where id = any(%s)", (ids,))


__all__ = ["STATUSES", "Document", "MemoryStore", "PostgresStore", "Store", "new_id", "now", "replace"]
