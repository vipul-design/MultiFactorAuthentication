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

Add these 2 fields to your existing `User` model (copy-paste as-is):

```python
# MFA fields - nullable for existing users until they enroll
totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
mfa_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
# End of MFA fields
```

| Field | Type | Purpose |
|-------|------|---------|
| `totp_secret` | `str \| None` | Stores the TOTP secret key. `None` until user enrolls. |
| `mfa_enabled` | `bool` | `True` only after user completes `/mfa/confirm`. |

### 1. Add to your existing `Tenant` model
Add these 1 field to your existing `Tenant` model (copy-paste as-is):

```python
# MFA field - nullable for existing users until they enroll
mfa_skiped: Mapped[bool] = mapped_column(default=False, nullable=False)  # allows skipping MFA prompt
# End of MFA fields
```
| Field | Type | Purpose |
|-------|------|---------|
| `mfa_skiped` | `bool` | `True` if the user chose to skip MFA setup (optional feature). |

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

This is the most important integration step. You need to touch **two places** in your existing login code: the service (business logic) and the router (HTTP response).

---

#### 3a — In your login **service** (where you build the response dict)

Add `mfa_enabled` and `mfa_skiped` to your normal login response:

```python
# Add selecloadin tenant in user table qury to fetch tenant field mfa skipped
query = await db.execute(
        select(User).options(selectinload(User.role),selectinload(User.tenant)).where(User.email == email, User.is_deleted == False)
    )
# Normal login response — add these two fields


response = {
    "access_token": access_token,
    "refresh_token": refresh_token,
    "token_type": "bearer",
    "user_with_tenant_exists": user_with_tenant_exists,
    "tenant_exists": tenant_exists,
    "tenant_email": tenant_email if tenant_email else None,
    "requested": has_access_request,
    "mfa_enabled": False,                                   # ← ADD THIS
    "mfa_skiped": getattr(user.tenant, 'mfa_skiped', False),       # ← ADD THIS
}
```

Then, **before building the normal response**, check if MFA is enabled. If it is, return a completely different response — a pre-auth token instead of a full access token:

```python
if getattr(user, 'mfa_enabled', False):
    pre_auth_token = create_access_token(
        data={"sub": str(user.id), "scope": "mfa_pending"},
        expires_delta=timedelta(minutes=5)
    )
    return {
        "mfa_enabled": True,
        "pre_auth_token": pre_auth_token,       # ← short-lived token, NOT the full access token
        "message": "MFA verification required.",
        "user_with_tenant_exists": user_with_tenant_exists,
        "tenant_exists": tenant_exists,
        "tenant_email": tenant_email if tenant_email else None,
        "requested": has_access_request,
    }

# Otherwise fall through and return the normal response dict above
```

> **Key difference:** When MFA is enabled, you return `pre_auth_token` only — no `access_token`, no `refresh_token`. The full tokens are only issued after `/mfa/verify-login` succeeds.

---

#### 3b — In your login **router** (where you return the HTTP response)

Check the service response and handle the MFA case before building the normal token response:

```python
# Handle MFA redirect — send pre_auth_token instead of full token
if response_data.get("mfa_enabled"):
    return success_response(
        message=response_data["message"],
        data={
            "mfa_enabled": True,
            "pre_auth_token": response_data["pre_auth_token"],
            "user_with_tenant_exists": response_data["user_with_tenant_exists"],
            "tenant_exists": response_data["tenant_exists"],
            "tenant_email": response_data["tenant_email"],
            "requested": response_data["requested"],
        },
    )

# Normal login — build full token response
token_data_kwargs = dict(
    user_with_tenant_exists=response_data["user_with_tenant_exists"],
    tenant_exists=response_data["tenant_exists"],
    tenant_email=response_data["tenant_email"],
    access_token=response_data["access_token"],
    token_type="bearer",
    expires_in=3600,
    requested=response_data["requested"],
    mfa_enabled=response_data["mfa_enabled"],       # ← always include
    mfa_skiped=response_data["mfa_skiped"],         # ← always include
)
if response_data.get("next"):
    token_data_kwargs["next"] = response_data["next"]

token_data = TokenData(**token_data_kwargs)
return success_response(
    message="Login successful. Use access_token in Authorization header.",
    data=token_data,
)
```

> Make sure your `TokenData` schema includes `mfa_enabled` and `mfa_skiped` fields so the response serializes correctly.

The client then uses the `pre_auth_token` as a Bearer token when calling `POST /auth/mfa/verify-login`.

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
- [ ] Add `totp_secret`, `mfa_enabled`, and `mfa_skiped` to User model
- [ ] Create `RecoveryCode` model and run migrations
- [ ] Add `TOTP_ISSUER`, `RECOVERY_CODE_COUNT`, and Redis settings to config
- [ ] Copy all 4 module files into `app/api/auth/mfa/`
- [ ] Register `mfa_router` in your main FastAPI app
- [ ] Update login **service**: add `mfa_enabled` + `mfa_skiped` to normal response; return pre-auth token early if `mfa_enabled` is True
- [ ] Update login **router**: handle `mfa_enabled` case (return `pre_auth_token`); pass `mfa_enabled` + `mfa_skiped` in normal `TokenData`
- [ ] Add `mfa_enabled` and `mfa_skiped` fields to your `TokenData` schema
- [ ] Confirm `get_current_user` and `get_async_db` dependencies exist
- [ ] Test full flow: enroll → confirm → logout → login → verify-login
- [ ] Verify recovery codes work and get marked as used after consumption
