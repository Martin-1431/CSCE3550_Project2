# SQLite-backed JWKS Server

A Python/Flask server that demonstrates JWKS-based JWT verification with
SQLite-backed RSA private-key storage.

- `GET /.well-known/jwks.json` publishes only unexpired public keys.
- `POST /auth` returns a JWT signed with a valid private key.
- `POST /auth?expired` returns a JWT signed with an expired private key and
  an expired `exp` claim.

Authentication is intentionally mocked: every POST to `/auth` succeeds,
including requests with the assignment's JSON username/password payload or
HTTP Basic authentication.

## Requirements and startup

- Python 3.9+
- Install dependencies with `pip install -r requirements.txt`.
- Start with `python app.py`.

The server listens on `http://localhost:8080`. It creates
`totally_not_my_privateKeys.db` in the current working directory at startup.
The `keys` table uses the required schema:

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
```

The application ensures the database contains at least one unexpired and one
expired key. Existing keys persist across restarts; if all valid keys expire,
a replacement is generated before the next normal JWT is signed.

## Try the endpoints

```powershell
# Public keys
curl.exe http://localhost:8080/.well-known/jwks.json

# Valid JWT
curl.exe -X POST http://localhost:8080/auth

# Expired JWT
curl.exe -X POST "http://localhost:8080/auth?expired"
```

The `/auth` response is the raw JWT as plain text, as expected by the project
blackbox test client.

## SQLite security and key format

Python's standard-library `sqlite3` module opens the database. SQL values,
including expiry timestamps, are bound through `?` placeholders, and the
expiry comparison is selected from fixed query strings rather than request
input. Private keys are serialized as unencrypted PKCS8 PEM bytes in the
`key` BLOB column and deserialized only when needed for signing or JWKS
generation. The JWT header's string `kid` corresponds to the database's
integer primary key.

Private keys are not encrypted at rest. This storage approach is only for the
class assignment; production systems should use protected key management and
real credential validation.

## Tests and lint

Run the test suite with coverage (the configured minimum is 80%):

```powershell
python -m pytest
```

Run lint checks with:

```powershell
python -m flake8 app.py test_app.py
```

Tests use a separate temporary database and cover persistence, expiry
selection, endpoint behavior, JWKS/public-key consistency, and JWT signatures.

## Submission evidence

- `gradebot_project2.png` shows the Project 2 Gradebot rubric output.
- `test_coverage.png` shows the passing pytest run and measured coverage.
