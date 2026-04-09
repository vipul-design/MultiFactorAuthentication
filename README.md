# Multi-Factor Authentication (MFA) Module

A plug-and-play MFA module for **FastAPI** projects. Handles TOTP setup, login verification, recovery codes, and brute-force protection — all ready to integrate.

**Stack:** Python · FastAPI · SQLAlchemy (async) · Redis · pyotp

---

## What This Module Does

- Generates a TOTP secret + QR code URI for authenticator apps (Google Authenticator, Authy, etc.)
- Verifies the first TOTP code to confirm setup
- Generates one-time recovery codes (for when the authenticator app is unavailable)
- Verifies TOTP or recovery codes at login
- Rate-limits failed attempts using Redis (5 attempts → 10 min lockout)
- Disables MFA on demand with TOTP confirmation

---

## Files

| File | Purpose |
|------|---------|
| `schemas.py` | Request/response data shapes (Pydantic models) |
| `service.py` | All MFA business logic |
| `helper.py` | Redis-backed rate limiting for failed attempts |
| `router.py` | FastAPI route definitions (HTTP endpoints) |

---

## Installation

```bash
pip install pyotp bcrypt redis fastapi sqlalchemy python-jose
```

---

## Database Setup

### 1. Add to your existing `User` model

```python
totp_secret: str | None   # Stores TOTP secret (None when MFA not enrolled)
mfa_enabled: bool         # True once MFA is confirmed and active
```

### 2. Create a new `RecoveryCode` model

```python
class RecoveryCode(Base):
    __tablename__ = "recovery_codes"

    id: int            # primary key
    user_id: UUID      # foreign key → User.id
    hashed_code: str   # SHA-256 hash of the code (never store plaintext)
    used: bool         # True after the code has been consumed
```

> **Run your migrations after adding these.**

---

## Config Settings

Add these to your settings / `.env` file:

| Setting | Example | Description |
|---------|---------|-------------|
| `TOTP_ISSUER` | `"MyApp"` | Name shown in the authenticator app |
| `RECOVERY_CODE_COUNT` | `10` | Number of recovery codes to generate |
| `RedisHost` | `"localhost"` | Redis hostname |
| `RedisPort` | `6379` | Redis port |
| `RedisDB` | `0` | Redis database index |
| `RedisUsername` | `""` | Redis username (empty if none) |
| `RedisPassword` | `""` | Redis password (empty if none) |
| `SECRET_KEY` | `"your-secret"` | JWT signing key (you likely have this already) |
| `ALGORITHM` | `"HS256"` | JWT algorithm |
| `RECOVERY_CODE_COUNT` | `10` | How many recovery codes to generate |

---

## Integration Steps

### Step 1 — Place the files

```
app/
  api/
    auth/
      mfa/
        __init__.py
        schemas.py
        service.py
        helper.py
        router.py
  db/
    models/
      user.py           ← add totp_secret + mfa_enabled
      recovery_code.py  ← new model
```

### Step 2 — Register the router

```python
from app.api.auth.mfa.router import mfa_router

app.include_router(mfa_router, prefix="/auth")
# Endpoints will be available at /auth/mfa/*
```

### Step 3 — Update your login endpoint

When a user logs in with password, check if MFA is enabled. If yes, return a short-lived **pre-auth token** instead of a full access token:

```python
if user.mfa_enabled:
    pre_auth_token = create_access_token(
        data={"sub": str(user.id), "scope": "mfa_pending"},
        expires_delta=timedelta(minutes=5)
    )
    return {"pre_auth_token": pre_auth_token, "mfa_required": True}

# else return full token as usual
```

The client then sends this pre-auth token to `POST /auth/mfa/verify-login`.

### Step 4 — Provide these dependencies

The module expects these two in `app/common/dependencies.py`:

```python
get_current_user   # Returns authenticated User from a full-access JWT
get_async_db       # Returns an async SQLAlchemy session
```

---

## API Endpoints

All endpoints are under `/auth/mfa/` (based on the prefix above).

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/mfa/status` | Full JWT | Check if MFA is enabled and TOTP is enrolled |
| `POST` | `/mfa/enroll` | Full JWT | Generate TOTP secret + QR URI (step 1 of setup) |
| `POST` | `/mfa/confirm` | Full JWT | Verify first TOTP code, enable MFA, get recovery codes |
| `POST` | `/mfa/verify-login` | Pre-auth JWT | Step 2 of login — verify TOTP or recovery code |
| `POST` | `/mfa/disable` | Full JWT | Disable MFA (requires valid TOTP code) |

---

## Request & Response Examples

### `GET /mfa/status`
```json
{
  "mfa_enabled": true,
  "totp_enrolled": true
}
```

### `POST /mfa/enroll`
No request body needed.
```json
{
  "secret": "BASE32SECRETHERE",
  "otpauth_uri": "otpauth://totp/MyApp:user@email.com?secret=BASE32...&issuer=MyApp"
}
```
> Render `otpauth_uri` as a QR code on the frontend. User scans it with their authenticator app.

### `POST /mfa/confirm`
```json
// Request
{ "totp_code": "123456" }

// Response — show these to the user ONCE, they are never shown again
{
  "recovery_codes": ["abc123xyz", "def456uvw", "..."],
  "message": "Save these recovery codes in a safe place. Each code can only be used once..."
}
```

### `POST /mfa/verify-login`
Send the **pre-auth token** as Bearer. Provide one of:
```json
{ "totp_code": "123456" }
// OR
{ "recovery_code": "abc123xyz" }
```
Success response:
```json
{
  "data": { "access_token": "<full_jwt>" },
  "message": "MFA verified successfully"
}
```

### `POST /mfa/disable`
```json
// Request
{ "totp_code": "123456" }

// Response
{ "data": {}, "message": "MFA Disabled successfully" }
```

---

## User Flows

### MFA Setup
1. User calls `POST /mfa/enroll` → gets `otpauth_uri`
2. Frontend renders it as a QR code → user scans with authenticator app
3. User enters the 6-digit code → frontend calls `POST /mfa/confirm`
4. On success, MFA is enabled and recovery codes are returned
5. Show recovery codes to user **once** — store them safely

### Login with MFA
1. User submits email + password to your login endpoint
2. If `mfa_enabled = true`, return a pre-auth token (`scope: mfa_pending`)
3. Frontend prompts for TOTP code → sends to `POST /mfa/verify-login` with pre-auth token
4. On success, full access token is returned → login complete

---

## Rate Limiting

Protects against brute-force attacks on TOTP and recovery codes.

| Setting | Value |
|---------|-------|
| Max failed attempts | 5 |
| Lockout duration | 10 minutes |
| Redis key (attempts) | `totp_attempts:{user_id}` |
| Redis key (lockout) | `totp_lockout:{user_id}` |

On each failed attempt the counter increments. At 5 failures, a lockout key is set in Redis and all requests return HTTP 429 until the lockout expires. On success, all counters are cleared.

---

## Recovery Codes

- 10 codes generated by default (set `RECOVERY_CODE_COUNT` to change)
- Each code is a random URL-safe string
- Stored as **SHA-256 hashes** — never in plaintext
- Each code can only be used **once** (marked `used = True` after consumption)
- If all codes are used, user gets an error and must contact support
- All codes are deleted when MFA is disabled
- New codes overwrite old ones when `/mfa/confirm` is called again

---

## Security Details

| What | How it's handled |
|------|-----------------|
| TOTP clock drift | `valid_window=1` — accepts codes ±30 seconds to handle slight clock differences |
| Brute force | Redis rate limit — 5 attempts then 10 min lockout |
| Recovery code storage | SHA-256 hashed before storing in DB |
| Timing attacks | `hmac.compare_digest` used for recovery code comparison |
| Token scope | Pre-auth token has `scope: mfa_pending` — `/verify-login` rejects any other scope |

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `"MFA enrollment not started. Call /mfa/enroll first."` | Called `/confirm` without `/enroll` | Always call `/enroll` first |
| `"This endpoint requires a pre-auth token from /auth/login."` | Sent full JWT to `/verify-login` | Use the pre-auth token from your login endpoint |
| `"Invalid or expired pre-auth token."` | Token expired or malformed | Re-do login to get a fresh pre-auth token |
| HTTP 429 Too Many Requests | Too many failed attempts | Wait 10 min or manually clear Redis keys for that user |
| `"MFA is not enabled on this account."` | Called `/disable` when MFA was never set up | Check `/mfa/status` before calling `/disable` |
| `"All recovery codes have been used."` | User exhausted all recovery codes | Admin must manually reset MFA for that user |

---

## Integration Checklist

- [ ] Install dependencies: `pyotp bcrypt redis fastapi sqlalchemy python-jose`
- [ ] Add `totp_secret` and `mfa_enabled` to User model
- [ ] Create `RecoveryCode` model and run migrations
- [ ] Add `TOTP_ISSUER`, `RECOVERY_CODE_COUNT`, and Redis settings to config
- [ ] Copy all 4 module files into `app/api/auth/mfa/`
- [ ] Register `mfa_router` in your main FastAPI app
- [ ] Update login endpoint to return pre-auth token when `mfa_enabled` is True
- [ ] Confirm `get_current_user` and `get_async_db` dependencies exist
- [ ] Test full flow: enroll → confirm → logout → login → verify-login
- [ ] Verify recovery codes work and get marked as used after consumption
