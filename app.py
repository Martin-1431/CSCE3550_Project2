"""
JWKS Server (educational project)
==================================

A minimal RESTful server that demonstrates the core JOSE / JWT / JWKS
concepts:

  * RSA key pairs are generated at startup, each with a unique Key ID
    (``kid``) and an expiry timestamp.
  * ``GET /.well-known/jwks.json`` publishes the *public* half of every
    key that has **not** expired, in standard JWKS format.
  * ``POST /auth`` mocks a login and returns a JWT signed with the
    current valid key. If the request includes an ``expired`` query
    parameter (e.g. ``POST /auth?expired``), the server instead signs
    the JWT with an already-expired key and gives it an expired
    ``exp`` claim, so client code can test rejection of stale tokens.

This is intentionally simple: keys live in memory (no database/HSM),
and there is no real credential verification -- any POST to ``/auth``
"succeeds", per the assignment's scope.

Run it:
    python app.py

The server listens on http://localhost:8080
"""

import base64
import datetime
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, Response, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory key store.
#
# Structure:  KEYS[kid] = {
#                 "private_key": <RSAPrivateKey>,
#                 "public_key":  <RSAPublicKey>,
#                 "expiry":      <datetime, timezone-aware, UTC>,
#             }
# ---------------------------------------------------------------------------
KEYS = {}

VALID_KEY_LIFETIME = datetime.timedelta(hours=1)
EXPIRED_KEY_AGE = datetime.timedelta(minutes=5)  # how far in the past


def _b64url_uint(value: int) -> str:
    """Base64url-encode (no padding) an unsigned integer.

    This is the encoding JWK uses for RSA modulus (``n``) and exponent
    (``e``) values, per RFC 7518 section 6.3.
    """
    byte_length = (value.bit_length() + 7) // 8 or 1
    value_bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("ascii")


def generate_key(expired: bool = False) -> str:
    """Generate a new RSA keypair, store it, and return its ``kid``.

    Args:
        expired: If True, the key's expiry timestamp is set in the
            past. Such keys are excluded from the JWKS endpoint, but
            can still be used to sign a deliberately-expired JWT for
            testing purposes.

    Returns:
        The newly generated key's ``kid`` (a UUID4 string).
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = str(uuid.uuid4())

    now = datetime.datetime.now(datetime.timezone.utc)
    expiry = now - EXPIRED_KEY_AGE if expired else now + VALID_KEY_LIFETIME

    KEYS[kid] = {
        "private_key": private_key,
        "public_key": private_key.public_key(),
        "expiry": expiry,
    }
    return kid


def unexpired_kids():
    """Return the list of kids whose key has not yet expired."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return [kid for kid, data in KEYS.items() if data["expiry"] > now]


# Seed the store with one valid key and one already-expired key so the
# server is immediately usable (and testable) as soon as it starts.
VALID_KID = generate_key(expired=False)
EXPIRED_KID = generate_key(expired=True)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Serve a JSON Web Key Set containing only unexpired public keys."""
    keys = []
    for kid in unexpired_kids():
        public_numbers = KEYS[kid]["public_key"].public_numbers()
        keys.append(
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _b64url_uint(public_numbers.n),
                "e": _b64url_uint(public_numbers.e),
            }
        )
    return jsonify({"keys": keys})


@app.route("/auth", methods=["POST"])
def auth():
    """Mock authentication endpoint -- issues a signed JWT.

    No credentials are actually checked; any POST succeeds. This
    endpoint exists to demonstrate JWT issuance/expiry, not real auth.

    Query params:
        expired: if present (e.g. ``/auth?expired``), the JWT is
            signed using the expired keypair and given an expired
            ``exp`` claim.
    """
    use_expired = "expired" in request.args
    kid = EXPIRED_KID if use_expired else VALID_KID
    private_key = KEYS[kid]["private_key"]

    now = datetime.datetime.now(datetime.timezone.utc)
    if use_expired:
        issued_at = now - datetime.timedelta(hours=1)
        expires_at = now - datetime.timedelta(minutes=5)
    else:
        issued_at = now
        expires_at = now + datetime.timedelta(hours=1)

    payload = {
        "sub": "fake-user",
        "iat": issued_at,
        "exp": expires_at,
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})

    # Blackbox test clients for this assignment typically expect the raw
    # JWT string as the response body, so we return plain text rather
    # than wrapping it in JSON.
    return Response(token, mimetype="text/plain")


if __name__ == "__main__":  # pragma: no cover
    app.run(host="0.0.0.0", port=8080)
