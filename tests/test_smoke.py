from __future__ import annotations

from xml.etree import ElementTree as ET

import httpx

from deployed import smoke


def run(tmp_path, monkeypatch, get, post, token=""):
    monkeypatch.setenv("SMOKE_TOKEN", token)
    monkeypatch.setattr(httpx, "get", lambda url, **kw: httpx.Response(get(url, kw)))
    monkeypatch.setattr(httpx, "post", lambda url, **kw: httpx.Response(post(url, kw)))
    out = tmp_path / "s.xml"
    code = smoke.main(["--base-url", "https://intake.test/", "--junit", str(out)])
    return code, ET.fromstring(out.read_text())  # noqa: S314 - our own file


def secure_get(url, kw):
    if url.endswith("/healthz"):
        return 200
    if "headers" not in kw:
        return 401
    return 403 if url.endswith("/reviews") else 404


def test_a_locked_down_service_passes(tmp_path, monkeypatch):
    code, suite = run(tmp_path, monkeypatch, secure_get, lambda u, kw: 401, token="t")
    assert code == 0 and suite.get("tests") == "5"


def test_an_open_queue_or_an_anonymous_read_fails(tmp_path, monkeypatch):
    code, _ = run(tmp_path, monkeypatch, lambda u, kw: 200, lambda u, kw: 401, token="t")
    assert code == 1
    code, suite = run(tmp_path, monkeypatch, secure_get, lambda u, kw: 422)
    assert code == 1 and suite.get("failures") == "1"
