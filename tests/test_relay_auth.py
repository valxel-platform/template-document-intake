from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from intake.auth import JwtVerifier, tenants
from intake.contracts import summary_line
from intake.relay import Relay

from .fakes import Producer


def test_the_relay_publishes_what_the_broker_acknowledges(env):
    doc_id = env.upload()
    env.process()
    summary_line()
    with pytest.raises(RuntimeError, match="acknowledged"):
        Relay(env.store, env.rt.pipeline.contracts, Producer(fail=True)).step()
    producer = Producer()
    assert Relay(env.store, env.rt.pipeline.contracts, producer).step() == 1
    assert (
        producer.sent[0]["key"] == doc_id.encode()
        and producer.sent[0]["headers"]["valxel-tenant"] == b"north-clinic"
    )
    assert (
        env.store.claim() == []
        and summary_line() == 'valxel.datasets {"lab-report-extracted":{"published":1}}'
    )


def test_tokens_are_checked_for_signature_issuer_and_audience(monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    class Jwks:
        def __init__(self, url, cache_keys):
            pass

        def get_signing_key_from_jwt(self, token):
            return type("K", (), {"key": key.public_key()})()

    monkeypatch.setattr(jwt, "PyJWKClient", Jwks)
    v = JwtVerifier(issuer="https://idp.test", jwks_url="https://idp.test/certs", audience="document-intake")
    claims = {
        "iss": "https://idp.test",
        "aud": "document-intake",
        "sub": "nurse-7",
        "exp": int(time.time()) + 60,
    }
    assert v.verify(jwt.encode(claims, key, algorithm="RS256"))["sub"] == "nurse-7"
    assert v.verify(jwt.encode({**claims, "aud": "other"}, key, algorithm="RS256")) is None
    assert v.verify(jwt.encode({**claims, "exp": 1}, key, algorithm="RS256")) is None
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(
        v.jwks, "get_signing_key_from_jwt", lambda t: type("K", (), {"key": other.public_key()})()
    )
    assert v.verify(jwt.encode(claims, key, algorithm="RS256")) is None
    with pytest.raises(RuntimeError, match="OIDC"):
        JwtVerifier(issuer="", jwks_url="", audience="x")


def test_tenants_from_the_token():
    assert tenants({"organization": {"a": {}, "b": {}}}, "organization") == frozenset({"a", "b"})
    assert (
        tenants({"organization": "a"}, "organization") == frozenset({"a"})
        and tenants({}, "organization") == frozenset()
    )
