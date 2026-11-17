from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from intake.app import Runtime, build, create_app
from intake.audit import Auditor, MemorySink
from intake.checks import NoScanner
from intake.extraction import FixedExtractor
from intake.settings import Settings
from intake.storage import MemoryStorage
from intake.store import MemoryStore

ROOT = Path(__file__).resolve().parent.parent
NORTH, SOUTH = {"organization": {"north-clinic": {}}}, {"organization": ["south-clinic"]}
# token -> claims. Synthetic people only.
TOKENS: dict[str, dict[str, Any]] = {
    "uploader": {"sub": "nurse-7", "azp": "emr-bff", "scope": "documents:write documents:read", **NORTH},
    "reviewer": {"sub": "clerk-2", "azp": "emr-bff", "scope": "documents:read documents:review", **NORTH},
    "south": {
        "sub": "nurse-9",
        "azp": "emr-bff",
        "scope": "documents:write documents:read documents:review",
        **SOUTH,
    },
    "reader": {"sub": "doc-3", "azp": "emr-bff", "scope": "documents:read", **NORTH},
    "no-org": {"sub": "x", "azp": "emr-bff", "scope": "documents:write"},
    "two-orgs": {"sub": "y", "azp": "emr-bff", "scope": "documents:write", "organization": ["a", "b"]},
}
GOOD = {"patient_ref": ("P-1001", 0.97), "collected_on": ("2026-11-02", 0.95), "test_code": ("2345-7", 0.9)}
PDF = b"%PDF-1.7\n% synthetic lab report\n"


class FakeVerifier:
    def verify(self, token: str) -> dict[str, Any] | None:
        return TOKENS.get(token)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class Env:
    def __init__(self, rt: Runtime, client: TestClient, sink: MemorySink) -> None:
        self.rt, self.client, self.sink = rt, client, sink
        self.store: MemoryStore = rt.store  # type: ignore[assignment]
        self.storage: MemoryStorage = rt.storage  # type: ignore[assignment]

    def declare(self, token: str = "uploader", **over: Any) -> Any:  # noqa: S107 - a test token name
        body = {"type": "lab-report", "filename": "report.pdf", "format": "pdf", "size": 1000, **over}
        return self.client.post("/documents", json=body, headers=auth(token))

    def upload(self, data: bytes = PDF, token: str = "uploader", **over: Any) -> str:  # noqa: S107
        r = self.declare(token, **over)
        assert r.status_code == 201, r.text
        doc_id = r.json()["id"]
        self.storage.put_quarantine(r.json()["upload"]["fields"]["key"], data)
        assert self.client.post(f"/documents/{doc_id}/uploaded", headers=auth(token)).status_code == 202
        return str(doc_id)

    def process(self) -> None:
        for d in self.store.due(100):
            self.rt.pipeline.process(d)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        config_path=str(ROOT / "intake.yaml"),
        contracts_dir=str(ROOT / "contracts"),
        product="emr",
        audit_sink="memory",
        rate_burst=100,
        rate_per_minute=6000,
    )


def make_env(settings: Settings, *, scanner: Any = None, extractor: Any = None) -> Env:
    sink = MemorySink()
    auditor = Auditor(sink, service="document-intake", product="emr", environment="test", data_class="phi")
    rt = build(
        settings,
        verifier=FakeVerifier(),
        store=MemoryStore(),
        storage=MemoryStorage(),
        scanner=scanner or NoScanner(),
        extractor=extractor or FixedExtractor(GOOD),
        auditor=auditor,
    )
    return Env(rt, TestClient(create_app(settings, runtime=rt, workers=False)), sink)


@pytest.fixture
def env(settings: Settings) -> Env:
    return make_env(settings)
