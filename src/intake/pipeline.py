"""What happens to an uploaded document, in order. Nothing reads a file before its checks pass.

  1. size      read at most the type's limit (+1 byte): larger is rejected.
  2. format    by content (checks.sniff): must be one the type allows and the one declared.
  3. malware   the platform's ClamAV: infected is rejected and the file deleted at once; a scan
               that can't run leaves the document uploaded, to try again (never "clean").
  4. promote   the file goes to the clean bucket, encrypted with the product's KMS key; quarantine's
               copy is deleted.
  5. extract   through the LLM gateway; each field below its min_confidence, or a required field
               not found, sends the document to review. Otherwise it's extracted and its fields are
               published under the type's dataset contract.

Every step that decides is audited (document.scanned, document.rejected, document.extracted) with
the document's id and codes only, never a field's value. Product events count received, rejected,
needs_review and extracted.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from dataclasses import replace
from typing import Any

from opentelemetry import trace

from . import cohorts, events
from .audit import Actor, Auditor, AuditUnavailable
from .checks import ScanError, sniff
from .config import Config, DocType
from .contracts import ContractError, Contracts, count
from .extraction import ExtractionUnavailable, Extractor, Read
from .relay_types import Outgoing
from .storage import Missing, Storage
from .store import Document, Store, now

log = logging.getLogger("intake.pipeline")
tracer = trace.get_tracer("intake")
MAX_ATTEMPTS = 5


class Pipeline:
    def __init__(
        self,
        cfg: Config,
        store: Store,
        storage: Storage,
        scanner: Any,
        extractor: Extractor,
        contracts: Contracts,
        auditor: Auditor,
        *,
        source: str,
        component: str,
    ) -> None:
        self.cfg, self.store, self.storage, self.scanner = cfg, store, storage, scanner
        self.extractor, self.contracts, self.auditor, self.source = extractor, contracts, auditor, source
        self.actor = Actor(id=component, type="service")

    def _audit(
        self, action: str, doc: Document, outcome: str = "success", reason: str = "", **details: Any
    ) -> None:
        self.auditor.record(
            action,
            actor=self.actor,
            resource=("document", [doc.id]),
            outcome=outcome,  # type: ignore[arg-type]
            reason=reason,
            details={"tenant": doc.tenant, "type": doc.type, **details},
        )

    def event(self, doc: Document, dataset: str, data: dict[str, Any]) -> Outgoing:
        contract = self.contracts.for_dataset(dataset)
        if contract is None:
            raise ContractError(dataset, "", "no contract: add the dataset to the design")
        checked = contract.check_whole(data)
        value = {
            "specversion": "1.0",
            "id": str(uuid.uuid4()),
            "source": self.source,
            "type": dataset,
            "time": now().isoformat(),
            "datacontenttype": "application/json",
            "dataschema": f"{dataset}@{contract.version}",
            "subject": doc.id,
            "data": checked,
        }
        return Outgoing(
            contract.topic, doc.id, value, {"valxel-dataset": dataset, "valxel-tenant": doc.tenant}
        )

    def reject(self, doc: Document, why: str) -> Document:
        done = replace(doc, status="rejected", problem=why)
        self._audit("document.rejected", done, "failure", why)
        if self.store.update(done, expect=doc.status):
            events.record("intake.document_rejected", type=doc.type, reason=why.split(":", 1)[0])
            log.warning(
                "intake.document_rejected id=%s type=%s reason=%s", doc.id, doc.type, why.split(":", 1)[0]
            )
        return done

    def process(self, doc: Document) -> Document:
        """One uploaded document through the checks. Returns its new state."""
        dtype = self.cfg.documents[doc.type]
        with (
            tracer.start_as_current_span("intake.process", attributes={"intake.type": doc.type}),
            cohorts.item(),
        ):
            try:
                data = self.storage.read_quarantine(doc.key, dtype.max_mb * 1024 * 1024)
            except Missing:
                return self.reject(doc, "missing: nothing was uploaded")
            if len(data) > dtype.max_mb * 1024 * 1024:
                self.storage.drop_quarantine(doc.key)
                return self.reject(doc, f"size: larger than {dtype.max_mb} MB")
            fmt = sniff(data[:16])
            if fmt is None or fmt not in dtype.formats or fmt != doc.declared_format:
                self.storage.drop_quarantine(doc.key)
                return self.reject(
                    doc, f"format: the content isn't one of {', '.join(dtype.formats)} as declared"
                )
            try:
                verdict = self.scanner.scan(data)
            except ScanError as exc:
                return self._retry(doc, str(exc))
            if not verdict.clean:
                self.storage.drop_quarantine(doc.key)
                log.error("intake.malware_found id=%s type=%s signature=%s", doc.id, doc.type, verdict.threat)
                self._audit("document.scanned", doc, "failure", "malware", signature=verdict.threat)
                return self.reject(doc, f"malware: {verdict.threat}")
            digest = hashlib.sha256(data).hexdigest()
            self.storage.promote(doc.key, data, f"application/{fmt}" if fmt == "pdf" else f"image/{fmt}")
            self.storage.drop_quarantine(doc.key)
            checked = replace(doc, sha256=digest, format=fmt, size=len(data))
            self._audit("document.scanned", checked, sha256=digest)
            try:
                reads = self.extractor.extract(data, fmt, dtype)
            except ExtractionUnavailable as exc:
                return self._retry(checked, str(exc))
            return self._extracted(checked, dtype, reads)

    def _extracted(self, doc: Document, dtype: DocType, reads: dict[str, Read]) -> Document:
        unsure = [
            f.name
            for f in dtype.fields
            if reads[f.name].confidence < f.min_confidence or (f.required and reads[f.name].value is None)
        ]
        fields = {k: {"value": r.value, "confidence": round(r.confidence, 3)} for k, r in reads.items()}
        if unsure:
            done = replace(doc, status="needs_review", fields=fields, problem="review: " + ", ".join(unsure))
            self._audit("document.extracted", done, unsure=len(unsure))
            self.store.update(done, expect=doc.status)
            events.record("intake.document_needs_review", type=doc.type)
            return done
        return self.publish(replace(doc, fields=fields), "extracted", expect=doc.status)

    def publish(self, doc: Document, status: str, *, expect: str, by: str = "") -> Document:
        """Publish the document's fields under its type's dataset; stays put if they break the contract."""
        dtype = self.cfg.documents[doc.type]
        data = {
            "document_id": doc.id,
            "tenant": doc.tenant,
            "type": doc.type,
            **{k: v["value"] for k, v in doc.fields.items()},
        }
        try:
            out = self.event(doc, dtype.dataset, data)
        except ContractError as exc:
            count(exc.dataset, "refused")
            held = replace(doc, status="needs_review", problem=f"contract: {exc.field}")
            log.error("intake.contract_refused id=%s dataset=%s field=%s", doc.id, exc.dataset, exc.field)
            self.store.update(held, expect=expect)
            return held
        done = replace(doc, status=status, problem="", reviewed_by=by or doc.reviewed_by)
        if status == "extracted":
            self._audit("document.extracted", done)
        if self.store.update(done, [out], expect=expect):
            events.record(f"intake.document_{status}", type=doc.type)
        return done

    def _retry(self, doc: Document, why: str) -> Document:
        tried = replace(doc, attempts=doc.attempts + 1, problem=why)
        if tried.attempts >= MAX_ATTEMPTS:
            failed = replace(tried, status="failed")
            log.error("intake.document_failed id=%s type=%s attempts=%s", doc.id, doc.type, tried.attempts)
            self.store.update(failed, expect=doc.status)
            return failed
        log.warning("intake.check_unavailable id=%s attempt=%s: %s", doc.id, tried.attempts, why)
        self.store.update(tried, expect=doc.status)
        return tried

    def purge(self) -> int:
        """Documents past their type's retention: the file and the row go (audited)."""
        retention = {t: d.retention_days for t, d in self.cfg.documents.items()}
        gone = 0
        for doc in self.store.expired(retention, 500):
            self.storage.delete_clean(doc.key)
            self.storage.drop_quarantine(doc.key)
            self._audit("document.purged", doc, reason="retention")
            self.store.forget(doc)
            gone += 1
        return gone


class Worker(threading.Thread):
    def __init__(self, pipeline: Pipeline, *, idle_s: float = 2.0) -> None:
        super().__init__(daemon=True, name="intake-pipeline")
        self.pipeline, self.idle_s = pipeline, idle_s
        self.stop = threading.Event()
        self.last_purge = 0.0

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                due = self.pipeline.store.due(10)
                for doc in due:
                    self.pipeline.process(doc)
                if time.monotonic() - self.last_purge > 3600:
                    self.last_purge = time.monotonic()
                    self.pipeline.purge()
                if not due:
                    self.stop.wait(self.idle_s)
            except AuditUnavailable:
                log.error("intake: audit unavailable; documents wait")
                self.stop.wait(10)
            except Exception:
                log.exception("intake: the pipeline failed; retrying")
                self.stop.wait(10)
