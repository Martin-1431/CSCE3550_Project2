# JWKS Server (educational project)

A tiny RESTful server, in Python + Flask, that shows how JWKS-based JWT
verification works:

- Generates RSA key pairs, each with a unique `kid` and an expiry.
- `GET /.well-known/jwks.json` — publishes only the **unexpired** public keys.
- `POST /auth` — mocks a login and returns a JWT signed with the current
  valid key (`kid` is in the JWT header).
- `POST /auth?expired` — returns a JWT signed with an **expired** key and an
  expired `exp` claim, so you can test that expired tokens/keys are rejected.

No real authentication happens — any POST to `/auth` succeeds. This is by
design for the assignment; a real system would verify credentials, use a
proper key-management/HSM setup, and rotate keys.

## Requirements

- Python 3.9+

## Quick start

```bash
# 1. Get the code, then from the project folder:
pip install -r requirements.txt

# 2. Run the server
python app.py
```

The server listens on **http://localhost:8080**.

Try it out (in another terminal):

```bash
# Public keys (JWKS)
curl.exe http://localhost:8080/.well-known/jwks.json

# Get a valid JWT
curl.exe -X POST http://localhost:8080/auth

# Get an expired JWT (signed with an expired key)
curl.exe -X POST "http://localhost:8080/auth?expired"
```

On Windows PowerShell, use `curl.exe` as shown above because `curl` is an
alias for PowerShell's `Invoke-WebRequest`, which does not support curl's
`-X` option. The native PowerShell equivalent for the POST request is:

```powershell
Invoke-WebRequest -Method POST -Uri "http://localhost:8080/auth?expired"
```

The `/auth` response body is the raw JWT string (plain text), which is what
common blackbox test clients for this assignment expect.

## Project layout

```
jwks_server/
├── app.py            # the server: key generation + the two endpoints
├── test_app.py        # pytest suite (unit + integration tests)
├── requirements.txt    # pinned dependencies
├── pytest.ini         # runs coverage automatically, fails if under 80%
└── .flake8            # lint configuration
```

Everything lives in `app.py` on purpose — the assignment is small, so one
well-commented, well-organized file is easier to read than several thin
modules. Functions are separated by concern (key generation, encoding
helpers, routes) and documented with docstrings.

## Running the tests

```bash
pytest
```

This runs the full suite and prints a coverage report (configured in
`pytest.ini` to fail if coverage drops below 80%; the suite currently hits
100%). Run `pytest -v` for per-test output.

## Linting

```bash
flake8 app.py test_app.py
```

## How the key/expiry logic works

- At startup, the server generates two RSA key pairs:
  - one **valid** key (`kid` = `VALID_KID`), expiring 1 hour from now
  - one **expired** key (`kid` = `EXPIRED_KID`), whose expiry is already
    5 minutes in the past
- `GET /.well-known/jwks.json` filters `KEYS` down to only entries whose
  expiry is still in the future, and returns their public components
  (`n`, `e`) alongside `kid`, `kty`, `alg`, and `use` — standard JWK fields.
- `POST /auth` picks the valid key by default. If the query string contains
  `expired` (e.g. `/auth?expired`, with or without a value), it instead
  signs with the expired key and sets `iat`/`exp` in the past, so the
  resulting JWT is both signed by a "retired" key and already expired.
- Every issued JWT carries its signing key's `kid` in the JWT header, so a
  verifier can look up the matching key in the JWKS response by `kid`.

## Notes / limitations (by design, for a class project)

- Keys are stored in memory only — they reset each time the server restarts.
- No real authentication/credential checking on `/auth`.
- Only two keys are ever generated (one valid, one expired); the server
  isn't meant to run indefinitely or rotate keys.
