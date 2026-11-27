"""The document intake API. People reach it through the product's BFF, which passes their token on.

  POST /documents                 (upload scope) declare a document: type, name, format, size. The
                                  answer is its id and a presigned POST to quarantine (5 minutes,
                                  that key, that Content-Type, at most the type's size).
  POST /documents/{id}/uploaded   (upload scope, the uploader only) the browser's upload is done:
                                  the pipeline takes it from here.
  GET  /documents/{id}            (read scope) status and, once checked, the fields read.
  GET  /documents/{id}/download   (read scope) a one-minute link, only for a checked file.
  GET  /reviews                   (review scope) documents waiting for a person, oldest first.
  POST /documents/{id}/review     (review scope) confirm or correct the fields; then they're published.

A caller sees only their tenants' documents (another tenant's answers 404). Every read of a document
or its file, and every review, is audited by id. /healthz and /readyz are in-cluster only; /metrics
is on the management port (management.py).
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass, replace
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest
from pydantic import BaseModel, Field

from . import cohorts, errors, events, flags, management, telemetry
from .audit import Actor, Auditor, AuditUnavailable, make_sink, require_encryption
from .auth import Caller, JwtVerifier, RateLimiter, Verifier, authenticate
from .checks import ClamdScanner, NoScanner
from .component import COMPONENT
from .config import Config, load
from .contracts import Contracts, summary_line
from .extraction import Extractor, FixedExtractor, GatewayExtractor
from .pipeline import Pipeline, Worker
from .settings import Settings
from .storage import MemoryStorage, S3Storage, Storage
from .store import Document, MemoryStore, PostgresStore, Store, new_id, now

log = logging.getLogger("intake")
DEPLOYED = ("staging", "production")
_UNSAFE = re.compile(r"[^A-Za-z0-9._ -]+")


def clean_name(name: str) -> str:
    """A display name only (files are stored by id): no paths, controls or quotes, at most 120 chars."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    return (_UNSAFE.sub("_", base).strip(" .") or "document")[:120]


class Declare(BaseModel):
    type: str = Field(max_length=63)
    filename: str = Field(min_length=1, max_length=255)
    format: str = Field(max_length=10)
    size: int = Field(gt=0)


class Review(BaseModel):
    fields: dict[str, str | None]


@dataclass
class Runtime:
    settings: Settings
    cfg: Config
    store: Store
    storage: Storage
    pipeline: Pipeline
    auditor: Auditor
    verifier: Verifier
    threads: list[Any]


def build(
    settings: Settings,
    *,
    verifier: Verifier | None = None,
    store: Store | None = None,
    storage: Storage | None = None,
    scanner: Any = None,
    extractor: Extractor | None = None,
    auditor: Auditor | None = None,
) -> Runtime:
    cfg = load(settings.config_path)
    deployed = settings.environment in DEPLOYED
    if deployed:
        missing = [
            n
            for n, ok in (
                ("INTAKE_STORAGE=s3", settings.storage == "s3"),
                ("INTAKE_SCANNER=clamd", settings.scanner == "clamd"),
                ("INTAKE_DATABASE_URL", bool(settings.database_url)),
                ("INTAKE_KAFKA_BOOTSTRAP", bool(settings.kafka_bootstrap)),
            )
            if not ok
        ]
        if missing:
            raise RuntimeError(
                "document intake can't start: staging and production need " + ", ".join(missing)
            )
    if settings.kafka_bootstrap:
        require_encryption(settings.kafka_config, cfg.data_class, "events")
    contracts = Contracts.load(settings.contracts_dir)
    absent = sorted(
        {d.dataset for d in cfg.documents.values()} - {c.dataset for c in contracts.by_topic.values()}
    )
    if absent:
        raise RuntimeError(f"document intake can't start: no contract for {', '.join(absent)} in contracts/")
    if auditor is None:
        required = (
            settings.audit_required if settings.audit_required is not None else cfg.data_class != "general"
        )
        auditor = Auditor(
            make_sink(
                settings.audit_sink,
                bootstrap=settings.audit_kafka_bootstrap,
                topic=settings.audit_topic,
                config=settings.audit_kafka_config,
                data_class=cfg.data_class,
            ),
            service=COMPONENT,
            product=settings.product,
            environment=settings.environment,
            data_class=cfg.data_class,
            required=required,
        )
    store = store or (PostgresStore(settings.database_url) if settings.database_url else MemoryStore())
    if storage is None:
        storage = (
            S3Storage(
                quarantine=settings.quarantine_bucket,
                clean=settings.clean_bucket,
                kms_key_id=settings.kms_key_id,
            )
            if settings.storage == "s3"
            else MemoryStorage()
        )
    if scanner is None:
        scanner = (
            ClamdScanner(settings.clamd_host, settings.clamd_port)
            if settings.scanner == "clamd"
            else NoScanner()
        )
    if extractor is None:
        extractor = (
            GatewayExtractor(
                base_url=settings.gateway_url,
                api_key=settings.gateway_key,
                model=settings.extraction_model,
                component=COMPONENT,
            )
            if settings.gateway_url
            else FixedExtractor()
        )
    verifier = verifier or JwtVerifier(
        issuer=settings.oidc_issuer, jwks_url=settings.oidc_jwks_url, audience=settings.audience
    )
    pipeline = Pipeline(
        cfg,
        store,
        storage,
        scanner,
        extractor,
        contracts,
        auditor,
        source=f"{settings.product}/{COMPONENT}",
        component=COMPONENT,
    )
    return Runtime(settings, cfg, store, storage, pipeline, auditor, verifier, [])


def example_flag(settings: Settings) -> str:
    """The example feature's flag. It shows the pattern every feature follows: the tool gives the
    feature a flag in the product's Flipt (on in dev and staging, off in production until it's
    released) and the new behaviour reads it. Replace it with your first feature's own."""
    return f"{settings.product or 'example'}.example.document-age"


def create_app(
    settings: Settings | None = None, *, runtime: Runtime | None = None, workers: bool = True
) -> Any:
    settings = settings or Settings()
    rt = runtime or build(settings)
    limiter = RateLimiter(settings.rate_per_minute, settings.rate_burst)
    app = FastAPI(title=COMPONENT, docs_url=None, redoc_url=None, openapi_url=None)
    telemetry.setup(COMPONENT, app=app)
    errors.start_errors()
    flags.configure(settings)
    events.register(REGISTRY)

    def need(scope: str) -> Any:
        """A dependency: runs before the body is read, so unauthenticated callers learn nothing."""

        def check(request: Request) -> Caller:
            caller = authenticate(request, rt.verifier, settings.tenant_claim, limiter)
            caller.require(scope)
            return caller

        return Depends(check)

    upload, read, reviewing = (
        need(settings.upload_scope),
        need(settings.read_scope),
        need(settings.review_scope),
    )

    def audit(action: str, caller: Caller, doc: Document, outcome: str = "success", **details: Any) -> None:
        actor = Actor(
            id=caller.subject or caller.client,
            type="user" if caller.subject != caller.client else "service",
            client=caller.client,
        )
        try:
            rt.auditor.record(
                action,
                actor=actor,
                resource=("document", [doc.id]),
                outcome=outcome,  # type: ignore[arg-type]
                details={"tenant": doc.tenant, "type": doc.type, **details},
            )
        except AuditUnavailable as exc:
            raise HTTPException(
                503, "This couldn't be recorded in the audit trail; try again shortly."
            ) from exc

    def mine(caller: Caller, doc_id: str) -> Document:
        doc = rt.store.get(doc_id, caller.tenants)
        if doc is None:
            raise HTTPException(404, "No such document.")
        return doc

    def view(doc: Document) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": doc.id,
            "type": doc.type,
            "status": doc.status,
            "filename": doc.filename,
            "created_at": doc.created_at.isoformat(),
        }
        if doc.status in ("needs_review", "extracted", "reviewed"):
            out["fields"] = doc.fields
        if doc.status in ("rejected", "needs_review", "failed"):
            out["problem"] = doc.problem.split(":", 1)[0]
        return out

    @app.post("/documents", status_code=201)
    def declare(body: Declare, caller: Caller = upload) -> dict[str, Any]:
        dtype = rt.cfg.documents.get(body.type)
        if dtype is None:
            raise HTTPException(
                422, f"Unknown document type; use one of {', '.join(sorted(rt.cfg.documents))}."
            )
        fmt = body.format.lower()
        if fmt not in dtype.formats:
            raise HTTPException(422, f"A {dtype.type} must be one of {', '.join(dtype.formats)}.")
        if body.size > dtype.max_mb * 1024 * 1024:
            raise HTTPException(413, f"A {dtype.type} is at most {dtype.max_mb} MB.")
        if len(caller.tenants) != 1:
            raise HTTPException(422, "Your token names several organizations: upload through one of them.")
        doc = Document(
            id=new_id(),
            tenant=next(iter(caller.tenants)),
            type=dtype.type,
            status="awaiting_upload",
            uploaded_by=caller.subject,
            filename=clean_name(body.filename),
            declared_format=fmt,
            size=body.size,
            created_at=now(),
        )
        audit("document.declared", caller, doc, format=fmt, size=body.size)
        rt.store.create(doc)
        from .checks import MIME

        upload = rt.storage.presign_upload(
            doc.key, MIME[fmt], dtype.max_mb * 1024 * 1024, settings.upload_url_ttl_s
        )
        return {"id": doc.id, "upload": {"url": upload.url, "fields": upload.fields}}

    @app.post("/documents/{doc_id}/uploaded", status_code=202)
    def uploaded(doc_id: str, caller: Caller = upload) -> dict[str, Any]:
        doc = mine(caller, doc_id)
        if doc.uploaded_by != caller.subject:
            raise HTTPException(404, "No such document.")
        if doc.status != "awaiting_upload":
            return view(doc)
        moved = replace(doc, status="uploaded")
        rt.store.update(moved, expect="awaiting_upload")
        events.record("intake.document_received", type=doc.type)
        return view(moved)

    @app.get("/documents/{doc_id}")
    def show(doc_id: str, caller: Caller = read) -> dict[str, Any]:
        doc = mine(caller, doc_id)
        audit("document.read", caller, doc)
        out = view(doc)
        # The template's example feature, behind its flag: off, the response is today's.
        if flags.enabled(example_flag(settings), user=caller.subject or caller.client):
            out["age_seconds"] = int((now() - doc.created_at).total_seconds())
        return out

    @app.get("/documents/{doc_id}/download")
    def download(doc_id: str, caller: Caller = read) -> dict[str, Any]:
        doc = mine(caller, doc_id)
        if doc.status not in ("needs_review", "extracted", "reviewed"):
            raise HTTPException(409, "The file hasn't passed its checks.")
        audit("document.downloaded", caller, doc)
        return {
            "url": rt.storage.presign_download(doc.key, doc.filename, settings.download_url_ttl_s),
            "expires_in": settings.download_url_ttl_s,
        }

    @app.get("/reviews")
    def reviews(caller: Caller = reviewing) -> dict[str, Any]:
        return {"documents": [view(d) for d in rt.store.queue(caller.tenants, 50)]}

    @app.post("/documents/{doc_id}/review")
    def review(doc_id: str, body: Review, caller: Caller = reviewing) -> dict[str, Any]:
        doc = mine(caller, doc_id)
        if doc.status != "needs_review":
            raise HTTPException(409, "This document isn't waiting for review.")
        if doc.uploaded_by == caller.subject:
            raise HTTPException(403, "Someone other than the uploader reviews a document.")
        dtype = rt.cfg.documents[doc.type]
        names = {f.name for f in dtype.fields}
        unknown = sorted(set(body.fields) - names)
        if unknown:
            raise HTTPException(422, f"Unknown fields: {', '.join(unknown)}.")
        missing = [
            f.name
            for f in dtype.fields
            if f.required
            and not (
                body.fields.get(f.name)
                or (f.name not in body.fields and doc.fields.get(f.name, {}).get("value"))
            )
        ]
        if missing:
            raise HTTPException(422, f"Required fields are missing: {', '.join(missing)}.")
        fields = {
            **doc.fields,
            **{
                k: {"value": (v or None) and str(v)[:500], "confidence": 1.0, "by": "review"}
                for k, v in body.fields.items()
            },
        }
        audit("document.reviewed", caller, doc, changed=len(body.fields))
        done = rt.pipeline.publish(
            replace(doc, fields=fields), "reviewed", expect="needs_review", by=caller.subject
        )
        if done.status != "reviewed":
            raise HTTPException(
                422, f"The fields don't match the agreed contract ({done.problem.split(': ', 1)[-1]})."
            )
        return view(done)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> Response:
        dead = [t.name for t in rt.threads if not t.is_alive()]
        return JSONResponse(
            {"status": "not ready", "stopped": dead} if dead else {"status": "ready"},
            status_code=503 if dead else 200,
        )

    app.add_middleware(cohorts.CohortMiddleware)
    app.add_middleware(errors.TraceResponseMiddleware)
    app.state.runtime = rt
    if workers:
        start_workers(rt)
    return app


def start_workers(rt: Runtime) -> None:
    worker = Worker(rt.pipeline)
    worker.start()
    rt.threads.append(worker)
    s = rt.settings
    if s.kafka_bootstrap:
        from .relay import Relay, kafka_producer

        relay = Relay(
            rt.store,
            rt.pipeline.contracts,
            kafka_producer({"bootstrap.servers": s.kafka_bootstrap, **s.kafka_config}),
        )
        relay.start()
        rt.threads.append(relay)
    else:
        log.warning("no Kafka configured: events stay in the outbox")

    def report() -> None:
        while True:
            threading.Event().wait(60)
            line = summary_line()
            if line:
                log.info(line)

    threading.Thread(target=report, name="datasets", daemon=True).start()
    cohorts.start_reporting()
    events.start_reporting()


def metrics_body() -> tuple[bytes, str]:
    """What the management port serves (management.py): every metric, the product events counter
    (valxel_events_total) among them."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def main() -> None:
    import uvicorn

    settings = Settings()
    telemetry.setup_logging(COMPONENT)
    # /metrics on the management port (MANAGEMENT_PORT, 8081), apart from the API, as in the Java
    # templates: the mesh lets the data plane's metrics collector reach that port only.
    management.serve(metrics_body, host="0.0.0.0")  # noqa: S104  NOSONAR: inside the container; the collector scrapes it from another pod
    uvicorn.run(create_app(settings), host="0.0.0.0", port=settings.port, log_config=None)  # noqa: S104
