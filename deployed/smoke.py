"""Checks a deployed document intake and writes JUnit for the post-deploy report.

Always: it's up, and it refuses calls without a token (before reading any body). With SMOKE_TOKEN
(documents:read and an organization, nothing else): a document that doesn't exist answers 404,
never an error or another tenant's data, and the review queue refuses a token without the review
scope. Writes nothing, so it is safe in production.
"""

from __future__ import annotations

import argparse
import os
import secrets
import time
from collections.abc import Callable
from pathlib import Path
from xml.etree import ElementTree as ET

import httpx


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--junit", default="reports/deployed-smoke.xml")
    args = ap.parse_args(argv)
    base = args.base_url.rstrip("/")
    checks: dict[str, Callable[[], bool]] = {
        "healthz": lambda: httpx.get(f"{base}/healthz", timeout=10).status_code == 200,
        "declaring needs a token": lambda: (
            httpx.post(f"{base}/documents", json={}, timeout=10).status_code == 401
        ),
        "reading needs a token": lambda: httpx.get(f"{base}/documents/doc_x", timeout=10).status_code == 401,
    }
    token = os.environ.get("SMOKE_TOKEN", "")
    if token:
        h = {"Authorization": f"Bearer {token}"}
        unknown = f"doc_{secrets.token_hex(16)}"
        checks["an unknown document is 404"] = lambda: (
            httpx.get(f"{base}/documents/{unknown}", headers=h, timeout=10).status_code == 404
        )
        checks["reviews need the review scope"] = lambda: (
            httpx.get(f"{base}/reviews", headers=h, timeout=10).status_code == 403
        )
    suite = ET.Element("testsuite", name="smoke")
    failed = 0
    for name, check in checks.items():
        t0 = time.monotonic()
        try:
            ok = check()
        except Exception:  # noqa: BLE001  (an unreachable service is a failed check)
            ok = False
        tc = ET.SubElement(
            suite, "testcase", classname="smoke", name=name, time=f"{time.monotonic() - t0:.3f}"
        )
        if not ok:
            failed += 1
            ET.SubElement(tc, "failure", message=f"{name} failed at {base}")
        print(f"{'pass' if ok else 'FAIL'}  {name}")
    suite.set("tests", str(len(checks)))
    suite.set("failures", str(failed))
    Path(args.junit).parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(suite).write(args.junit, encoding="utf-8", xml_declaration=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
