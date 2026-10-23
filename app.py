"""
SQLite-backed JWKS server for the educational authentication project.

Run with ``python app.py``. The server listens on http://localhost:8080
and creates ``totally_not_my_privateKeys.db`` in the current directory.
"""

import base64
import datetime
import os
import sqlite3
import time
from contextlib import contextmanager

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

DATABASE_FILENAME = "totally_not_my_privateKeys.db"
app.config["DATABASE_PATH"] = os.path.join(os.getcwd(), DATABASE_FILENAME)

VALID_KEY_LIFETIME = datetime.timedelta(hours=1)
EXPIRED_KEY_AGE = datetime.timedelta(minutes=5)


@contextmanager
def _database_connection():
    """Yield a row-enabled SQLite connection and always close it."""
    connection = sqlite3.connect(app.config["DATABASE_PATH"])
    connection.row_factory = sqlite3.Row
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _serialize_private_key(private_key):
    """Serialize an RSA private key to unencrypted PKCS8 PEM bytes."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _insert_key(connection, expiry):
    """Generate and insert a private key, returning its integer database ID."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cursor = connection.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (_serialize_private_key(private_key), expiry),
    )
    return cursor.lastrowid


def initialize_database():
    """Create the required schema and seed a valid and an expired key."""
    now = int(time.time())
    with _database_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )

        valid_key = connection.execute(
            "SELECT 1 FROM keys WHERE exp > ? LIMIT 1", (now,)
        ).fetchone()
        if valid_key is None:
            valid_expiry = now + int(VALID_KEY_LIFETIME.total_seconds())
            _insert_key(connection, valid_expiry)

        expired_key = connection.execute(
            "SELECT 1 FROM keys WHERE exp <= ? LIMIT 1", (now,)
        ).fetchone()
        if expired_key is None:
            expired_expiry = now - int(EXPIRED_KEY_AGE.total_seconds())
            _insert_key(connection, expired_expiry)


def generate_key(expired=False):
    """Generate, persist, and return a key ID; used for rotation and tests."""
    now = int(time.time())
    lifetime = EXPIRED_KEY_AGE if expired else VALID_KEY_LIFETIME
    expiry = now - int(lifetime.total_seconds()) if expired else (
        now + int(lifetime.total_seconds())
    )
    with _database_connection() as connection:
        return _insert_key(connection, expiry)


def _b64url_uint(value):
    """Base64url-encode an unsigned integer without padding (RFC 7518)."""
    byte_length = (value.bit_length() + 7) // 8 or 1
    value_bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")


def _find_key(expired):
    """Read a suitable private key row using a parameterized expiry query."""
    now = int(time.time())
    with _database_connection() as connection:
        if expired:
            row = connection.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? "
                "ORDER BY exp DESC LIMIT 1",
                (now,),
            ).fetchone()
        else:
            row = connection.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? "
                "ORDER BY exp DESC LIMIT 1",
                (now,),
            ).fetchone()

    if row is None and not expired:
        generate_key()
        return _find_key(expired=False)
    return row


def _load_private_key(serialized_key):
    """Deserialize a private key previously stored in the database."""
    return serialization.load_pem_private_key(serialized_key, password=None)


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return public JWK values for all keys that have not expired."""
    now = int(time.time())
    with _database_connection() as connection:
        rows = connection.execute(
            "SELECT kid, key FROM keys WHERE exp > ? ORDER BY kid", (now,)
        ).fetchall()

    keys = []
    for row in rows:
        private_key = _load_private_key(row["key"])
        public_numbers = private_key.public_key().public_numbers()
        keys.append(
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": str(row["kid"]),
                "n": _b64url_uint(public_numbers.n),
                "e": _b64url_uint(public_numbers.e),
            }
        )
    return jsonify({"keys": keys})


@app.route("/auth", methods=["POST"])
def auth():
    """Mock authentication and issue a JWT using a key read from SQLite."""
    use_expired = "expired" in request.args
    row = _find_key(expired=use_expired)
    if row is None:
        raise RuntimeError("No expired signing key is available in the database.")

    private_key = _load_private_key(row["key"])
    now = int(time.time())
    if use_expired:
        issued_at = min(now - 3600, row["exp"] - 1)
        expires_at = row["exp"]
    else:
        issued_at = now
        expires_at = row["exp"]

    token = jwt.encode(
        {"sub": "fake-user", "iat": issued_at, "exp": expires_at},
        private_key,
        algorithm="RS256",
        headers={"kid": str(row["kid"])},
    )
    return Response(token, mimetype="text/plain")


initialize_database()


if __name__ == "__main__":  # pragma: no cover
    app.run(host="0.0.0.0", port=8080)
