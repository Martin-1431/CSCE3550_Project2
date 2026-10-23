"""
Test suite for app.py (the JWKS server).

Run with:
    pytest --cov=app --cov-report=term-missing
"""

import base64
import datetime

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

import app as server


@pytest.fixture
def client():
    """A Flask test client for the server."""
    server.app.config["TESTING"] = True
    with server.app.test_client() as c:
        yield c


def _public_key_from_jwk(jwk):
    """Rebuild an RSA public key object from a JWK dict (for verifying)."""

    def b64url_to_int(value):
        padded = value + "=" * (-len(value) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), byteorder="big")

    n = b64url_to_int(jwk["n"])
    e = b64url_to_int(jwk["e"])
    return RSAPublicNumbers(e, n).public_key()


# ---------------------------------------------------------------------------
# Key generation / helper tests
# ---------------------------------------------------------------------------
def test_generate_key_creates_valid_key():
    kid = server.generate_key(expired=False)
    assert kid in server.KEYS
    data = server.KEYS[kid]
    assert isinstance(data["private_key"], rsa.RSAPrivateKey)
    assert data["expiry"] > datetime.datetime.now(datetime.timezone.utc)


def test_generate_key_creates_expired_key():
    kid = server.generate_key(expired=True)
    assert kid in server.KEYS
    assert server.KEYS[kid]["expiry"] < datetime.datetime.now(datetime.timezone.utc)


def test_b64url_uint_roundtrip():
    value = 65537
    encoded = server._b64url_uint(value)
    padded = encoded + "=" * (-len(encoded) % 4)
    decoded = int.from_bytes(base64.urlsafe_b64decode(padded), byteorder="big")
    assert decoded == value


def test_b64url_uint_no_padding_characters():
    encoded = server._b64url_uint(65537)
    assert "=" not in encoded


def test_unexpired_kids_excludes_expired():
    kids = server.unexpired_kids()
    assert server.VALID_KID in kids
    assert server.EXPIRED_KID not in kids


# ---------------------------------------------------------------------------
# /.well-known/jwks.json tests
# ---------------------------------------------------------------------------
def test_jwks_returns_200(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200


def test_jwks_only_contains_unexpired_keys(client):
    resp = client.get("/.well-known/jwks.json")
    body = resp.get_json()
    kids_in_response = [k["kid"] for k in body["keys"]]

    assert server.VALID_KID in kids_in_response
    assert server.EXPIRED_KID not in kids_in_response


def test_jwks_key_shape(client):
    resp = client.get("/.well-known/jwks.json")
    body = resp.get_json()
    valid_key = next(k for k in body["keys"] if k["kid"] == server.VALID_KID)

    assert valid_key["kty"] == "RSA"
    assert valid_key["use"] == "sig"
    assert valid_key["alg"] == "RS256"
    assert "n" in valid_key
    assert "e" in valid_key


# ---------------------------------------------------------------------------
# /auth tests
# ---------------------------------------------------------------------------
def test_auth_no_body_succeeds(client):
    """The blackbox test client POSTs with no body -- must still work."""
    resp = client.post("/auth")
    assert resp.status_code == 200
    assert resp.data  # non-empty token string


def test_auth_returns_valid_verifiable_jwt(client):
    resp = client.post("/auth")
    token = resp.data.decode("utf-8")

    header = jwt.get_unverified_header(token)
    assert header["kid"] == server.VALID_KID

    # Fetch matching public key from JWKS and verify signature/claims.
    jwks_body = client.get("/.well-known/jwks.json").get_json()
    jwk = next(k for k in jwks_body["keys"] if k["kid"] == header["kid"])
    public_key = _public_key_from_jwk(jwk)

    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user"


def test_auth_expired_query_param_uses_expired_key(client):
    resp = client.post("/auth?expired")
    token = resp.data.decode("utf-8")

    header = jwt.get_unverified_header(token)
    assert header["kid"] == server.EXPIRED_KID

    # The expired key must NOT appear in JWKS.
    jwks_body = client.get("/.well-known/jwks.json").get_json()
    kids = [k["kid"] for k in jwks_body["keys"]]
    assert server.EXPIRED_KID not in kids


def test_auth_expired_token_fails_verification(client):
    resp = client.post("/auth?expired")
    token = resp.data.decode("utf-8")

    public_key = server.KEYS[server.EXPIRED_KID]["public_key"]
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])


def test_auth_get_not_allowed(client):
    resp = client.get("/auth")
    assert resp.status_code == 405


def test_jwks_post_not_allowed(client):
    resp = client.post("/.well-known/jwks.json")
    assert resp.status_code == 405
