"""Tests for the SQLite-backed JWKS server."""

import base64
import datetime
import sqlite3
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

import app as server


@pytest.fixture
def client(tmp_path):
    """Use an isolated SQLite file for every test."""
    server.app.config["TESTING"] = True
    server.app.config["DATABASE_PATH"] = str(tmp_path / server.DATABASE_FILENAME)
    server.initialize_database()
    with server.app.test_client() as test_client:
        yield test_client


def _public_key_from_jwk(jwk):
    """Rebuild an RSA public key from the modulus and exponent in a JWK."""

    def b64url_to_int(value):
        padded = value + "=" * (-len(value) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), byteorder="big")

    return RSAPublicNumbers(
        b64url_to_int(jwk["e"]), b64url_to_int(jwk["n"])
    ).public_key()


def _database_rows():
    with sqlite3.connect(server.app.config["DATABASE_PATH"]) as connection:
        return connection.execute(
            "SELECT kid, key, exp FROM keys ORDER BY kid"
        ).fetchall()


def test_startup_creates_schema_and_seeds_both_expiry_types(client):
    rows = _database_rows()
    assert len(rows) >= 2
    assert all(isinstance(row[1], bytes) for row in rows)
    assert any(row[2] > int(time.time()) for row in rows)
    assert any(row[2] <= int(time.time()) for row in rows)

    with sqlite3.connect(server.app.config["DATABASE_PATH"]) as connection:
        columns = connection.execute("PRAGMA table_info(keys)").fetchall()
    assert [(column[1], column[2]) for column in columns] == [
        ("kid", "INTEGER"),
        ("key", "BLOB"),
        ("exp", "INTEGER"),
    ]
    assert columns[0][5] == 1
    assert columns[1][3] == columns[2][3] == 1


def test_initialize_database_preserves_existing_keys(client):
    original_ids = [row[0] for row in _database_rows()]
    server.initialize_database()
    assert [row[0] for row in _database_rows()] == original_ids


@pytest.mark.parametrize("expired", [False, True])
def test_generate_key_persists_serialized_key_and_expected_expiry(client, expired):
    kid = server.generate_key(expired=expired)
    row = next(row for row in _database_rows() if row[0] == kid)
    private_key = server._load_private_key(row[1])

    assert isinstance(private_key, rsa.RSAPrivateKey)
    if expired:
        assert row[2] < int(time.time())
    else:
        assert row[2] > int(time.time())


def test_b64url_uint_roundtrip_and_no_padding():
    value = 65537
    encoded = server._b64url_uint(value)
    padded = encoded + "=" * (-len(encoded) % 4)
    assert int.from_bytes(base64.urlsafe_b64decode(padded), "big") == value
    assert "=" not in encoded
    assert server._b64url_uint(0) == "AA"


def test_jwks_only_returns_unexpired_persisted_keys(client):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    body = response.get_json()
    rows = _database_rows()
    valid_ids = {str(row[0]) for row in rows if row[2] > int(time.time())}
    expired_ids = {str(row[0]) for row in rows if row[2] <= int(time.time())}
    published = {item["kid"]: item for item in body["keys"]}

    assert valid_ids.issubset(published)
    assert expired_ids.isdisjoint(published)
    assert all(
        (item["kty"], item["use"], item["alg"]) == ("RSA", "sig", "RS256")
        and item["n"]
        and item["e"]
        for item in published.values()
    )


def test_jwks_public_key_matches_serialized_private_key(client):
    jwks = client.get("/.well-known/jwks.json").get_json()["keys"]
    row = next(row for row in _database_rows() if row[2] > int(time.time()))
    jwk = next(item for item in jwks if item["kid"] == str(row[0]))
    private_key = server._load_private_key(row[1])

    assert _public_key_from_jwk(jwk).public_numbers() == (
        private_key.public_key().public_numbers()
    )


def test_auth_issues_jwt_verified_by_published_key(client):
    response = client.post(
        "/auth",
        json={"username": "userABC", "password": "password123"},
        headers={"Authorization": "Basic dXNlcjpwYXNz"},
    )
    assert response.status_code == 200
    token = response.data.decode("utf-8")
    header = jwt.get_unverified_header(token)

    jwks = client.get("/.well-known/jwks.json").get_json()["keys"]
    jwk = next(item for item in jwks if item["kid"] == header["kid"])
    claims = jwt.decode(token, _public_key_from_jwk(jwk), algorithms=["RS256"])
    assert claims["sub"] == "fake-user"
    assert header["kid"] in {item["kid"] for item in jwks}


def test_auth_uses_expired_database_key_and_expired_claim(client):
    response = client.post("/auth?expired")
    assert response.status_code == 200
    token = response.data.decode("utf-8")
    header = jwt.get_unverified_header(token)
    row = next(row for row in _database_rows() if str(row[0]) == header["kid"])

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            server._load_private_key(row[1]).public_key(),
            algorithms=["RS256"],
        )
    published_ids = {
        item["kid"]
        for item in client.get("/.well-known/jwks.json").get_json()["keys"]
    }
    assert header["kid"] not in published_ids


def test_auth_generates_a_fresh_key_if_all_valid_keys_expired(client):
    with sqlite3.connect(server.app.config["DATABASE_PATH"]) as connection:
        connection.execute("UPDATE keys SET exp = ?", (int(time.time()) - 10,))

    response = client.post("/auth")
    assert response.status_code == 200
    claims = jwt.decode(
        response.data.decode("utf-8"),
        options={"verify_signature": False, "verify_exp": False},
        algorithms=["RS256"],
    )
    assert claims["exp"] > int(time.time())
    assert any(row[2] > int(time.time()) for row in _database_rows())


def test_auth_expired_query_presence_selects_expired_key(client):
    response = client.post("/auth?expired=false")
    header = jwt.get_unverified_header(response.data.decode("utf-8"))
    row = next(row for row in _database_rows() if str(row[0]) == header["kid"])
    assert row[2] <= int(time.time())


def test_auth_get_not_allowed(client):
    assert client.get("/auth").status_code == 405


def test_jwks_post_not_allowed(client):
    assert client.post("/.well-known/jwks.json").status_code == 405


def test_expiry_timestamps_are_utc_epoch_seconds(client):
    valid_row = next(row for row in _database_rows() if row[2] > int(time.time()))
    expiry = datetime.datetime.fromtimestamp(
        valid_row[2], tz=datetime.timezone.utc
    )
    assert expiry.tzinfo is datetime.timezone.utc
