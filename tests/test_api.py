from __future__ import annotations

import pytest

from intake.app import build, clean_name
from intake.extraction import FixedExtractor

from .conftest import GOOD, auth, make_env


def test_declaring_needs_the_upload_scope_and_one_organization(env):
    assert env.client.post("/documents", json={}).status_code == 401
    assert env.declare("reader").status_code == 403
    assert env.declare("no-org").status_code == 403
    assert env.declare("two-orgs").status_code == 422
    assert (
        env.client.post("/documents", json={"type": "lab-report"}, headers=auth("bogus")).status_code == 401
    )


def test_declaring_checks_type_format_and_size_and_hands_back_a_narrow_upload(env):
    assert env.declare(type="selfie").status_code == 422
    assert env.declare(format="tiff").status_code == 422
    assert env.declare(size=11 * 1024 * 1024).status_code == 413
    r = env.declare(filename='../../etc/pass\x00wd".pdf')
    assert r.status_code == 201
    fields = r.json()["upload"]["fields"]
    assert fields["key"] == f"north-clinic/{r.json()['id']}" and fields["Content-Type"] == "application/pdf"
    assert fields["x-max-bytes"] == str(10 * 1024 * 1024) and fields["x-ttl"] == "300"
    assert env.store.docs[r.json()["id"]].filename == "pass_wd_.pdf"
    assert env.sink.events[-1]["data"]["action"] == "document.declared"


def test_names_are_display_only():
    assert clean_name("C:\\Users\\a\\scan 1.PDF") == "scan 1.PDF"
    assert clean_name("...") == "document" and len(clean_name("a" * 300)) == 120


def test_a_clean_document_is_checked_extracted_and_published(env):
    doc_id = env.upload()
    env.process()
    doc = env.store.docs[doc_id]
    assert doc.status == "extracted" and doc.format == "pdf" and len(doc.sha256) == 64
    assert env.storage.quarantine == {} and doc.key in env.storage.clean
    [q] = env.store.claim()
    assert q.topic == "emr.lab-report-extracted.v1" and q.key == doc_id
    assert q.value["data"] == {
        "document_id": doc_id,
        "tenant": "north-clinic",
        "type": "lab-report",
        "patient_ref": "P-1001",
        "collected_on": "2026-11-02",
        "test_code": "2345-7",
    }
    actions = [e["data"]["action"] for e in env.sink.events]
    assert actions == ["document.declared", "document.scanned", "document.extracted"]
    assert "P-1001" not in str(env.sink.events)  # ids and codes only
    shown = env.client.get(f"/documents/{doc_id}", headers=auth("reader")).json()
    assert shown["status"] == "extracted" and shown["fields"]["patient_ref"]["value"] == "P-1001"
    assert env.sink.events[-1]["data"]["action"] == "document.read"


def test_other_tenants_and_other_people_get_404(env):
    doc_id = env.upload()
    assert env.client.get(f"/documents/{doc_id}", headers=auth("south")).status_code == 404
    assert env.client.get(f"/documents/{doc_id}/download", headers=auth("south")).status_code == 404
    other = env.declare().json()["id"]
    assert (
        env.client.post(f"/documents/{other}/uploaded", headers=auth("reviewer")).status_code == 403
    )  # no scope
    env.store.docs[other] = env.store.docs[other].__class__(
        **{**env.store.docs[other].__dict__, "uploaded_by": "x"}
    )
    assert env.client.post(f"/documents/{other}/uploaded", headers=auth("uploader")).status_code == 404


def test_downloads_only_after_the_checks_and_are_audited(env):
    doc_id = env.upload()
    assert env.client.get(f"/documents/{doc_id}/download", headers=auth("reader")).status_code == 409
    env.process()
    r = env.client.get(f"/documents/{doc_id}/download", headers=auth("reader"))
    assert r.status_code == 200 and r.json()["expires_in"] == 60 and "ttl=60" in r.json()["url"]
    assert env.sink.events[-1]["data"]["action"] == "document.downloaded"


@pytest.mark.parametrize(
    "data,declared,why",
    [
        (b"\x89PNG\r\n\x1a\n...", "pdf", "format"),
        (b"MZ\x90\x00 an executable", "pdf", "format"),
        (b"%PDF-1.4 X5O!P%@AP EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "pdf", "malware"),
    ],
)
def test_wrong_or_infected_files_are_rejected_and_deleted(env, caplog, data, declared, why):
    doc_id = env.upload(data, format=declared)
    env.process()
    doc = env.store.docs[doc_id]
    assert doc.status == "rejected" and doc.problem.startswith(why)
    assert env.storage.quarantine == {} and env.storage.clean == {} and env.store.claim() == []
    assert env.client.get(f"/documents/{doc_id}", headers=auth("reader")).json()["problem"] == why
    if why == "malware":
        assert "intake.malware_found" in caplog.text
        assert any(e["data"]["details"].get("signature") == "Eicar-Test-Signature" for e in env.sink.events)


def test_unsure_fields_wait_for_someone_else_to_review(settings):
    env = make_env(settings, extractor=FixedExtractor({**GOOD, "patient_ref": ("P-10O1", 0.6)}))
    doc_id = env.upload()
    env.process()
    assert env.store.docs[doc_id].status == "needs_review" and env.store.claim() == []
    assert env.client.get("/reviews", headers=auth("reader")).status_code == 403
    assert env.client.get("/reviews", headers=auth("south")).json() == {"documents": []}
    [queued] = env.client.get("/reviews", headers=auth("reviewer")).json()["documents"]
    assert queued["id"] == doc_id and queued["problem"] == "review"
    fix = {"fields": {"patient_ref": "P-1001"}}
    assert (
        env.client.post(
            f"/documents/{doc_id}/review", json={"fields": {"nope": "1"}}, headers=auth("reviewer")
        ).status_code
        == 422
    )
    r = env.client.post(f"/documents/{doc_id}/review", json=fix, headers=auth("reviewer"))
    assert r.status_code == 200 and r.json()["status"] == "reviewed"
    assert env.store.docs[doc_id].reviewed_by == "clerk-2"
    [q] = env.store.claim()
    assert q.value["data"]["patient_ref"] == "P-1001"
    assert (
        env.client.post(f"/documents/{doc_id}/review", json=fix, headers=auth("reviewer")).status_code == 409
    )


def test_the_uploader_never_reviews_their_own_document(settings):
    env = make_env(settings, extractor=FixedExtractor({**GOOD, "collected_on": (None, 0.0)}))
    env.store  # noqa: B018
    doc_id = env.upload(token="south")
    env.process()
    r = env.client.post(
        f"/documents/{doc_id}/review", json={"fields": {"collected_on": "2026-11-02"}}, headers=auth("south")
    )
    assert r.status_code == 403


def test_a_review_that_breaks_the_contract_isnt_published(settings):
    env = make_env(settings, extractor=FixedExtractor({**GOOD, "collected_on": ("Nov 2", 0.5)}))
    doc_id = env.upload()
    env.process()
    r = env.client.post(
        f"/documents/{doc_id}/review",
        json={"fields": {"collected_on": "2 Nov 2026"}},
        headers=auth("reviewer"),
    )
    assert r.status_code == 422 and "collected_on" in r.json()["detail"]
    assert env.store.docs[doc_id].status == "needs_review" and env.store.claim() == []
    missing = env.client.post(
        f"/documents/{doc_id}/review", json={"fields": {"patient_ref": None}}, headers=auth("reviewer")
    )
    assert missing.status_code == 422 and "Required" in missing.json()["detail"]


def test_no_audit_record_means_no_answer(env):
    doc_id = env.upload()
    env.sink.fail = True
    assert env.client.get(f"/documents/{doc_id}", headers=auth("reader")).status_code == 503


def test_deployed_environments_refuse_development_parts(settings):
    prod = settings.model_copy(update={"environment": "production"})
    with pytest.raises(RuntimeError, match="INTAKE_STORAGE=s3, INTAKE_SCANNER=clamd"):
        build(prod)
    bad = settings.model_copy(update={"contracts_dir": "/nonexistent"})
    with pytest.raises(RuntimeError, match="no contract for lab-report-extracted"):
        build(bad)


def test_health_and_metrics(env):
    assert env.client.get("/healthz").json() == {"status": "ok"}
    assert env.client.get("/readyz").status_code == 200
    assert "valxel_events" in env.client.get("/metrics").text
    assert env.client.get("/docs").status_code == 404


def test_the_worker_processes_uploads_and_readyz_names_a_stopped_one(env, caplog):
    from intake.app import start_workers
    from intake.pipeline import Worker

    doc_id = env.upload()
    w = Worker(env.rt.pipeline, idle_s=0.01)
    w.start()
    import time

    for _ in range(200):
        if env.store.docs[doc_id].status == "extracted":
            break
        time.sleep(0.01)
    w.stop.set()
    w.join(2)
    assert env.store.docs[doc_id].status == "extracted"
    env.rt.threads.append(w)
    assert env.client.get("/readyz").json() == {"status": "not ready", "stopped": ["intake-pipeline"]}
    env.rt.threads.clear()
    start_workers(env.rt)
    assert [t.name for t in env.rt.threads] == ["intake-pipeline"] and "outbox" in caplog.text
    env.rt.threads[0].stop.set()


def test_the_worker_waits_while_the_audit_trail_is_down(env, caplog):
    from intake.pipeline import Worker

    doc_id = env.upload()
    env.sink.fail = True
    w = Worker(env.rt.pipeline, idle_s=0.01)
    w.start()
    import time

    time.sleep(0.2)
    w.stop.set()
    w.join(2)
    assert env.store.docs[doc_id].status == "uploaded" and "audit unavailable" in caplog.text


def test_uploaded_twice_is_harmless_and_a_failed_document_shows_why(env):
    doc_id = env.upload()
    again = env.client.post(f"/documents/{doc_id}/uploaded", headers=auth("uploader"))
    assert again.status_code == 202 and again.json()["status"] == "uploaded"
    d = env.store.docs[doc_id]
    env.store.docs[doc_id] = d.__class__(**{**d.__dict__, "status": "failed", "problem": "scan: down"})
    assert env.client.get(f"/documents/{doc_id}", headers=auth("reader")).json()["problem"] == "scan"


def test_the_example_feature_is_behind_its_flag(env):
    """The pattern every feature follows: its new behaviour reads its flag, and off is today's."""
    from openfeature.provider.in_memory_provider import InMemoryFlag, InMemoryProvider

    from intake import flags
    from intake.app import example_flag
    from intake.settings import Settings

    assert example_flag(Settings(product="emr")) == "emr.example.document-age"
    doc_id = env.upload()
    assert "age_seconds" not in env.client.get(f"/documents/{doc_id}", headers=auth("reader")).json()
    on = InMemoryFlag("on", {"on": True, "off": False})
    flags.use_provider(InMemoryProvider({"example.example.document-age": on, "emr.example.document-age": on}))
    try:
        shown = env.client.get(f"/documents/{doc_id}", headers=auth("reader")).json()
        assert shown["age_seconds"] >= 0
    finally:
        flags.use_provider(InMemoryProvider({}))
