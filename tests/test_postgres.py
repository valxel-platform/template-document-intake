"""The Postgres store against a real database (VALXEL_TEST_DATABASE_URL); skipped without one."""

from __future__ import annotations

import os
from dataclasses import replace
from datetime import timedelta

import pytest

from intake.relay_types import Outgoing
from intake.store import Document, PostgresStore, new_id, now

URL = os.environ.get("VALXEL_TEST_DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not URL, reason="needs VALXEL_TEST_DATABASE_URL")


@pytest.fixture
def pg():
    store = PostgresStore(URL)
    with store.pool.connection() as conn:
        conn.execute("truncate intake_documents, intake_outbox")
    yield store
    store.pool.close()


def doc(tenant="north", status="awaiting_upload") -> Document:
    return Document(
        id=new_id(),
        tenant=tenant,
        type="lab-report",
        status=status,
        uploaded_by="nurse-7",
        filename="r.pdf",
        declared_format="pdf",
        size=10,
        created_at=now(),
    )


def test_documents_by_tenant_status_moves_and_the_outbox(pg):
    d = doc()
    pg.create(d)
    assert pg.get(d.id, frozenset({"north"})) == d
    assert pg.get(d.id, frozenset({"south"})) is None and pg.get(d.id, None) == d
    assert pg.update(replace(d, status="uploaded"), expect="awaiting_upload")
    assert not pg.update(replace(d, status="uploaded"), expect="awaiting_upload")  # someone moved it already
    assert [x.id for x in pg.due(10)] == [d.id]
    ev = Outgoing("emr.lab-report-extracted.v1", d.id, {"id": "e"}, {"valxel-dataset": "x"})
    done = replace(d, status="needs_review", fields={"patient_ref": {"value": "P", "confidence": 0.5}})
    assert pg.update(done, [ev], expect="uploaded")
    assert pg.get(d.id, None).fields["patient_ref"]["confidence"] == 0.5
    assert [x.id for x in pg.queue(frozenset({"north"}), 10)] == [d.id] and pg.queue(
        frozenset({"south"}), 10
    ) == []
    [q] = pg.claim()
    pg.published([q.id])
    assert pg.claim() == []
    with pg.pool.connection() as conn:
        conn.execute("update intake_documents set created_at = now() - interval '40 days'")
    assert [x.id for x in pg.expired({"lab-report": 30}, 10)] == [d.id]
    pg.forget(d)
    assert pg.get(d.id, None) is None and timedelta(days=1)
