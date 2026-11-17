"""Reading fields from a document, always through the product's LLM gateway (which decides which
models the data class allows: PHI only under a BAA or to the self-hosted model).

The gateway is expected to serve the OpenAI-style chat route (POST /v1/chat/completions) with the
document as a data URL. The model answers JSON: each field's value and its confidence (0-1), or
null when the field isn't there. Nothing the model says is trusted beyond that shape: unknown
fields are dropped, and values are strings of bounded length.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .checks import MIME
from .config import DocType


@dataclass(frozen=True)
class Read:
    value: str | None
    confidence: float


class ExtractionUnavailable(RuntimeError):
    """The gateway refused or failed: the message never includes what was sent."""


class Extractor(Protocol):
    def extract(self, data: bytes, fmt: str, doc: DocType) -> dict[str, Read]: ...


def tidy(raw: Any, doc: DocType) -> dict[str, Read]:
    out: dict[str, Read] = {}
    rows = raw if isinstance(raw, dict) else {}
    for f in doc.fields:
        row = rows.get(f.name)
        if not isinstance(row, dict):
            out[f.name] = Read(None, 0.0)
            continue
        value = row.get("value")
        try:
            conf = min(1.0, max(0.0, float(row.get("confidence", 0.0))))
        except (TypeError, ValueError):
            conf = 0.0
        out[f.name] = Read(None if value in (None, "") else str(value)[:500], conf)
    return out


class GatewayExtractor:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        component: str,
        client: httpx.Client | None = None,
        timeout_s: float = 120.0,
    ) -> None:
        if not (base_url and api_key and model):
            raise RuntimeError(
                "Extraction needs INTAKE_GATEWAY_URL, INTAKE_GATEWAY_KEY and INTAKE_EXTRACTION_MODEL"
            )
        self.url, self.model = base_url.rstrip("/") + "/v1/chat/completions", model
        self.client = client or httpx.Client(timeout=timeout_s, follow_redirects=False)
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "x-valxel-component": component,
            "x-valxel-purpose": "document-extraction",
        }

    def extract(self, data: bytes, fmt: str, doc: DocType) -> dict[str, Read]:
        names = ", ".join(f.name for f in doc.fields)
        prompt = (
            f"This is a {doc.type}. Read these fields: {names}. Answer only JSON: an object whose keys are "
            'those names and whose values are {"value": <string or null>, "confidence": <0 to 1>}. Use '
            "null when a field isn't on the document; never guess."
        )
        url = f"data:{MIME[fmt]};base64,{base64.b64encode(data).decode()}"
        body = {
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": url}},
                    ],
                }
            ],
        }
        try:
            resp = self.client.post(self.url, json=body, headers=self.headers)
        except httpx.HTTPError as exc:
            raise ExtractionUnavailable(f"the LLM gateway can't be reached ({type(exc).__name__})") from exc
        if resp.status_code >= 400:
            raise ExtractionUnavailable(f"the LLM gateway answered {resp.status_code}")
        try:
            content = resp.json()["choices"][0]["message"]["content"]
            return tidy(json.loads(content), doc)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ExtractionUnavailable("the model's answer wasn't the JSON asked for") from exc


class FixedExtractor:
    """Tests and local runs: the same answer for every document."""

    def __init__(self, answers: dict[str, tuple[str | None, float]] | None = None) -> None:
        self.answers = answers or {}

    def extract(self, data: bytes, fmt: str, doc: DocType) -> dict[str, Read]:
        return tidy({k: {"value": v, "confidence": c} for k, (v, c) in self.answers.items()}, doc)
