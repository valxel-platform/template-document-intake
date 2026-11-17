"""intake.yaml: which documents the product takes, what's read from them and how long they're kept.

People approve it at G4 with the design's Documents section.

    name: template-document-intake
    data_class: phi
    documents:
      - type: lab-report
        formats: [pdf, png, jpeg]
        max_mb: 10
        retention_days: 2555          # 7 years
        dataset: lab-report-extracted # the contract the extracted fields are published under
        fields:
          - { name: patient_ref, required: true, min_confidence: 0.9 }
          - { name: collected_on, required: true, min_confidence: 0.8 }
          - { name: test_code, min_confidence: 0.8 }

A field read with less than its min_confidence, or a required field not found, sends the document to
the review queue: a person with the review scope confirms or corrects it before it's published.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

FORMATS = ("pdf", "png", "jpeg", "tiff")
DATA_CLASSES = ("general", "payments", "phi")
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_FIELD = re.compile(r"^[a-z][a-z0-9_]{0,62}$")


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Field:
    name: str
    required: bool = False
    min_confidence: float = 0.8


@dataclass(frozen=True)
class DocType:
    type: str
    formats: tuple[str, ...]
    max_mb: int
    retention_days: int
    dataset: str
    fields: tuple[Field, ...]


@dataclass(frozen=True)
class Config:
    name: str
    data_class: str
    documents: dict[str, DocType]


def parse(raw: dict[str, Any]) -> Config:
    problems: list[str] = []
    name, data_class = str(raw.get("name") or ""), str(raw.get("data_class") or "")
    if not _NAME.match(name):
        problems.append("name must be the component's name")
    if data_class not in DATA_CLASSES:
        problems.append(f"data_class must be one of {', '.join(DATA_CLASSES)}")
    docs: dict[str, DocType] = {}
    for i, d in enumerate(raw.get("documents") or []):
        where = f"documents[{i}]"
        t = str(d.get("type") or "")
        if not _NAME.match(t) or t in docs:
            problems.append(f"{where}: a unique type is required (lowercase, dashes)")
        formats = tuple(str(f).lower() for f in d.get("formats") or [])
        if not formats or any(f not in FORMATS for f in formats):
            problems.append(
                f"{where}: formats are some of {', '.join(FORMATS)} (checked by content, not name)"
            )
        max_mb, keep = int(d.get("max_mb", 10)), int(d.get("retention_days", 0))
        if not 1 <= max_mb <= 50:
            problems.append(f"{where}: max_mb must be 1-50")
        if keep < 1:
            problems.append(f"{where}: retention_days is required: how long documents of this type are kept")
        dataset = str(d.get("dataset") or "")
        if not _NAME.match(dataset):
            problems.append(f"{where}: dataset names the contract its extracted fields are published under")
        fields = []
        for f in d.get("fields") or []:
            fname, conf = str(f.get("name") or ""), float(f.get("min_confidence", 0.8))
            if not _FIELD.match(fname):
                problems.append(f"{where}: field {fname!r} isn't a name (lowercase, underscores)")
            if not 0.5 <= conf <= 1.0:
                problems.append(f"{where}: {fname}: min_confidence must be 0.5-1.0")
            fields.append(Field(fname, bool(f.get("required", False)), conf))
        if not fields:
            problems.append(f"{where}: name the fields read from it")
        docs[t] = DocType(t, formats, max_mb, keep, dataset, tuple(fields))
    if not docs:
        problems.append("name at least one document type")
    if problems:
        raise ConfigError("intake.yaml: " + "; ".join(problems))
    return Config(name, data_class, docs)


def load(path: str) -> Config:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"intake.yaml isn't YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("intake.yaml must be a mapping")
    return parse(raw)
