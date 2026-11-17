"""The pieces: format sniffing, the scanner, extraction, storage, the policy file and the pipeline's edges."""

from __future__ import annotations

import json
import socket
import struct
import threading
from datetime import timedelta

import httpx
import pytest

from intake.checks import ClamdScanner, ScanError, Verdict, parse_reply, sniff
from intake.config import ConfigError, load, parse
from intake.extraction import ExtractionUnavailable, GatewayExtractor, tidy
from intake.pipeline import MAX_ATTEMPTS
from intake.storage import S3Storage

from .conftest import PDF, ROOT, make_env


def test_formats_are_read_from_content():
    assert [
        sniff(h)
        for h in (
            b"%PDF-1.7",
            b"\x89PNG\r\n\x1a\nxx",
            b"\xff\xd8\xff\xe0",
            b"II*\x00",
            b"MM\x00*",
            b"PK\x03\x04",
            b"",
        )
    ] == ["pdf", "png", "jpeg", "tiff", "tiff", None, None]


def test_clamd_replies():
    assert parse_reply("stream: OK") == Verdict(True)
    assert parse_reply("stream: Eicar-Signature FOUND") == Verdict(False, "Eicar-Signature")
    with pytest.raises(ScanError):
        parse_reply("INSTREAM size limit exceeded. ERROR")


def fake_clamd(answer: bytes) -> tuple[int, list[bytes]]:
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got: list[bytes] = []

    def serve() -> None:
        conn, _ = srv.accept()
        with conn:
            assert conn.recv(10) == b"zINSTREAM\0"
            while True:
                (n,) = struct.unpack(">I", conn.recv(4))
                if not n:
                    break
                buf = b""
                while len(buf) < n:
                    buf += conn.recv(n - len(buf))
                got.append(buf)
            conn.sendall(answer)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], got


def test_the_clamd_scanner_streams_and_reads_the_verdict():
    port, got = fake_clamd(b"stream: OK\0")
    assert ClamdScanner("127.0.0.1", port).scan(b"x" * 70000) == Verdict(True)
    assert sum(len(c) for c in got) == 70000 and len(got) == 2
    with pytest.raises(ScanError, match="can't be reached"):
        ClamdScanner("127.0.0.1", 9, timeout_s=1).scan(b"x")


def test_gateway_extraction_and_what_it_trusts(env):
    doc = env.rt.cfg.documents["lab-report"]
    seen = []

    def gateway(request):
        seen.append(request)
        content = json.dumps(
            {
                "patient_ref": {"value": "P-1", "confidence": 2},
                "evil": {"value": "x"},
                "collected_on": {"value": "", "confidence": "high"},
            }
        )
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    ex = GatewayExtractor(
        base_url="https://gw.test",
        api_key="k",
        model="doc-model",
        component="c",
        client=httpx.Client(transport=httpx.MockTransport(gateway)),
    )
    reads = ex.extract(PDF, "pdf", doc)
    assert set(reads) == {"patient_ref", "collected_on", "test_code"}
    assert (reads["patient_ref"].value, reads["patient_ref"].confidence) == ("P-1", 1.0)
    assert (reads["collected_on"].value, reads["collected_on"].confidence) == (None, 0.0)
    body = json.loads(seen[0].content)
    assert body["model"] == "doc-model" and body["temperature"] == 0
    assert seen[0].headers["x-valxel-purpose"] == "document-extraction"
    for answer, says in ((httpx.Response(429), "429"), (httpx.Response(200, json={"choices": []}), "JSON")):
        bad = GatewayExtractor(
            base_url="https://gw.test",
            api_key="k",
            model="m",
            component="c",
            client=httpx.Client(transport=httpx.MockTransport(lambda r, a=answer: a)),
        )
        with pytest.raises(ExtractionUnavailable, match=says):
            bad.extract(PDF, "pdf", doc)
    with pytest.raises(RuntimeError, match="INTAKE_GATEWAY_URL"):
        GatewayExtractor(base_url="", api_key="", model="", component="c")
    assert tidy("not a dict", doc)["patient_ref"].value is None


class FakeS3:
    class exceptions:
        class NoSuchKey(Exception):
            pass

    def __init__(self):
        self.calls = []

    def generate_presigned_post(self, **kw):
        self.calls.append(("post", kw))
        return {"url": "https://q.s3", "fields": {"key": kw["Key"], "policy": "p"}}

    def generate_presigned_url(self, op, **kw):
        self.calls.append((op, kw))
        return "https://c.s3/x"

    def get_object(self, **kw):
        if kw["Key"] == "gone":
            raise self.exceptions.NoSuchKey()
        self.calls.append(("get", kw))
        return {"Body": type("B", (), {"read": lambda self: b"data"})()}

    def put_object(self, **kw):
        self.calls.append(("put", kw))

    def delete_object(self, **kw):
        self.calls.append(("delete", kw))


def test_s3_uploads_are_narrow_files_are_encrypted_and_downloads_short():
    s3 = FakeS3()
    st = S3Storage(quarantine="q", clean="c", kms_key_id="kms-1", client=s3)
    up = st.presign_upload("t/doc_1", "application/pdf", 1000, 300)
    _, kw = s3.calls[0]
    assert kw["Bucket"] == "q" and kw["ExpiresIn"] == 300
    assert ["content-length-range", 1, 1000] in kw["Conditions"] and {
        "Content-Type": "application/pdf"
    } in kw["Conditions"]
    assert up.url == "https://q.s3"
    assert st.read_quarantine("t/doc_1", 10) == b"data" and s3.calls[-1][1]["Range"] == "bytes=0-10"
    st.promote("t/doc_1", b"d", "application/pdf")
    assert s3.calls[-1][1]["ServerSideEncryption"] == "aws:kms" and s3.calls[-1][1]["SSEKMSKeyId"] == "kms-1"
    st.presign_download("t/doc_1", "a.pdf", 60)
    assert (
        s3.calls[-1][1]["ExpiresIn"] == 60
        and 'filename="a.pdf"' in s3.calls[-1][1]["Params"]["ResponseContentDisposition"]
    )
    st.drop_quarantine("k")
    st.delete_clean("k")
    from intake.storage import Missing

    with pytest.raises(Missing):
        st.read_quarantine("gone", 1)
    with pytest.raises(RuntimeError, match="must differ"):
        S3Storage(quarantine="b", clean="b", kms_key_id="k", client=s3)
    with pytest.raises(RuntimeError, match="KMS"):
        S3Storage(quarantine="b", clean="c", kms_key_id="", client=s3)


def test_the_policy_file_refuses_vague_or_unsafe_types(tmp_path):
    cfg = load(str(ROOT / "intake.yaml"))
    assert cfg.documents["lab-report"].formats == ("pdf", "png", "jpeg")
    with pytest.raises(ConfigError) as err:
        parse(
            {
                "name": "x",
                "data_class": "phi",
                "documents": [
                    {
                        "type": "a",
                        "formats": ["exe"],
                        "max_mb": 500,
                        "dataset": "Bad",
                        "fields": [{"name": "X", "min_confidence": 0.1}],
                    },
                    {"type": "a", "formats": ["pdf"], "retention_days": 1, "dataset": "d"},
                ],
            }
        )
    text = str(err.value)
    for says in (
        "formats",
        "max_mb",
        "retention_days",
        "dataset",
        "isn't a name",
        "min_confidence",
        "unique type",
        "name the fields",
    ):
        assert says in text, says
    with pytest.raises(ConfigError, match="at least one"):
        parse({"name": "x", "data_class": "general"})
    (tmp_path / "a.yaml").write_text("- 1")
    with pytest.raises(ConfigError, match="mapping"):
        load(str(tmp_path / "a.yaml"))
    (tmp_path / "a.yaml").write_text("a: [")
    with pytest.raises(ConfigError, match="YAML"):
        load(str(tmp_path / "a.yaml"))


class Broken:
    def scan(self, data):
        raise ScanError("the malware scanner can't be reached (ConnectionRefusedError)")


def test_a_scan_that_cant_run_retries_then_fails_never_passes(settings, caplog):
    env = make_env(settings, scanner=Broken())
    doc_id = env.upload()
    for _ in range(MAX_ATTEMPTS):
        env.process()
    doc = env.store.docs[doc_id]
    assert doc.status == "failed" and doc.attempts == MAX_ATTEMPTS
    assert env.storage.clean == {} and "intake.document_failed" in caplog.text


def test_missing_and_oversized_uploads_are_rejected(settings):
    env = make_env(settings)
    r = env.declare()
    doc_id = r.json()["id"]
    env.client.post(f"/documents/{doc_id}/uploaded", headers={"Authorization": "Bearer uploader"})
    env.process()
    assert env.store.docs[doc_id].problem.startswith("missing")
    big = env.upload(b"%PDF-" + b"x" * (10 * 1024 * 1024))
    env.process()
    assert env.store.docs[big].problem.startswith("size")


def test_documents_past_retention_are_purged_and_audited(env):
    doc_id = env.upload()
    env.process()
    old = env.store.docs[doc_id]
    env.store.docs[doc_id] = old.__class__(
        **{**old.__dict__, "created_at": old.created_at - timedelta(days=2556)}
    )
    assert env.rt.pipeline.purge() == 1
    assert doc_id not in env.store.docs and env.storage.clean == {}
    assert env.sink.events[-1]["data"]["action"] == "document.purged"
