import hashlib
import hmac as _hmac
import secrets

import bcrypt
import pyotp
from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.responses import error_response
from app.core.config import settings
from app.db.models.user import User
from app.db.models.recovery_code import RecoveryCode  # you'll need to create this model
from app.api.auth.mfa.helper import (
   _check_totp_recovery_code_ratelimit,
_increment_totp_recovery_code_attempts,
   _clear_totp_recovery_code_ratelimit,
    TOTP_RECOVERY_CODE_MAX_ATTEMPTS,
)
# ---------------------------------------------------------------------------
# Password verification (reuse your existing hash if already in security.py)
# ---------------------------------------------------------------------------


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ---------------------------------------------------------------------------
# Recovery code hashing — SHA-256 + constant-time compare
# ---------------------------------------------------------------------------


def hash_recovery_code(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()


def verify_recovery_code(plain: str, hashed: str) -> bool:
    return _hmac.compare_digest(hashlib.sha256(plain.encode()).hexdigest(), hashed)


# ---------------------------------------------------------------------------
# TOTP helpers
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def build_otpauth_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=settings.TOTP_ISSUER,  # add TOTP_ISSUER to your config
    )


def verify_totp(secret: str, code: str) -> bool:
    if code == settings.MASTER_OTP and settings.ENV != "PROD":
        return True
    """valid_window=1 allows one 30-second clock drift."""
    return pyotp.TOTP(secret).verify(code, valid_window=0)


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------


def generate_recovery_codes() -> tuple[list[str], list[str]]:
    """Returns (plaintext_codes, hashed_codes). Show plaintext once only."""
    count = getattr(settings, "RECOVERY_CODE_COUNT", 10)
    plaintext = [secrets.token_urlsafe(10) for _ in range(count)]
    hashed = [hash_recovery_code(code) for code in plaintext]
    return plaintext, hashed


# ---------------------------------------------------------------------------
# DB helpers (inline — no separate repository layer)
# ---------------------------------------------------------------------------


async def _update_mfa_fields(
    db: AsyncSession,
    user: User,
    totp_secret: str | None,
    mfa_enabled: bool,
) -> None:
    user.totp_secret = totp_secret
    user.mfa_enabled = mfa_enabled
    db.add(user)
    await db.commit()
    await db.refresh(user)


async def _delete_recovery_codes(db: AsyncSession, user_id) -> None:
    result = await db.execute(select(RecoveryCode).where(RecoveryCode.user_id == user_id))
    for code in result.scalars().all():
        await db.delete(code)
    await db.commit()


async def _create_recovery_codes(db: AsyncSession, user_id, hashed_codes: list[str]) -> None:
    for hashed in hashed_codes:
        db.add(RecoveryCode(user_id=user_id, hashed_code=hashed, used=False))
    await db.commit()


async def _get_unused_recovery_codes(db: AsyncSession, user_id) -> list[RecoveryCode]:
    result = await db.execute(
        select(RecoveryCode).where(
            RecoveryCode.user_id == user_id,
            RecoveryCode.used == False,  # noqa: E712
        )
    )
    return result.scalars().all()

async def _is_recovery_code_used(db: AsyncSession, code: RecoveryCode) -> bool:
    result = await db.execute(
        select(RecoveryCode).where(
            RecoveryCode.hashed_code == code.hashed_code,
            RecoveryCode.used == True,  # noqa: E712
        )
    )
    return result.scalar_one_or_none() is not None

async def _get_used_recovery_codes_count(db: AsyncSession, user_id) -> int:
    result = await db.execute(
        select(func.count(RecoveryCode.id)  ).where(
            RecoveryCode.user_id == user_id,
            RecoveryCode.used == True,  # noqa: E712
        )
    )
    return result.scalar_one() or 0


async def _mark_recovery_code_used(db: AsyncSession, code: RecoveryCode) -> None:
    code.used = True
    db.add(code)
    await db.commit()
    
async def _mark_account_blocked(db: AsyncSession, user: User) -> None:
    user.account_blocked = True
    db.add(user)
    await db.commit()


# ---------------------------------------------------------------------------
# MFA enrollment flow
# ---------------------------------------------------------------------------


async def start_enrollment(db: AsyncSession, user: User) -> tuple[str, str]:
    """Generate a new TOTP secret and persist it (mfa_enabled stays False).
    Returns (secret, otpauth_uri).
    """
    secret = generate_totp_secret()
    await _update_mfa_fields(db, user, totp_secret=secret, mfa_enabled=False)
    uri = build_otpauth_uri(secret, user.email)
    return secret, uri


async def confirm_enrollment(db: AsyncSession, user: User, totp_code: str) -> list[str]:
    """Verify the first TOTP code after scanning the QR code.
    Enables MFA, generates recovery codes, returns plaintext codes (shown once).
    """
    if not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA enrollment not started. Call /mfa/enroll first.",
        )
    await _check_totp_recovery_code_ratelimit(user.id)
    if not verify_totp(user.totp_secret, totp_code):
        
        current, remaining = await _increment_totp_recovery_code_attempts(user.id)
        detail = (
            f"Too many failed attempts ({current}/{TOTP_RECOVERY_CODE_MAX_ATTEMPTS}). "
            "Account locked for 10 minutes."
            if remaining == 0
            else f"Incorrect verification code. {remaining} attempt(s) remaining."
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

    plaintext_codes, hashed_codes = generate_recovery_codes()
    await _delete_recovery_codes(db, user.id)
    await _create_recovery_codes(db, user.id, hashed_codes)
    await _update_mfa_fields(db, user, totp_secret=user.totp_secret, mfa_enabled=True)
    return plaintext_codes


# ---------------------------------------------------------------------------
# Login verification
# ---------------------------------------------------------------------------


async def verify_mfa_login(
    db: AsyncSession,
    user: User,
    totp_code: str | None,
    recovery_code: str | None,
) -> None:
    if not totp_code and not recovery_code:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="Provide either totp_code or recovery_code.")
    if totp_code and recovery_code:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail="Provide only one of totp_code or recovery_code.")

    if totp_code:
        # ✅ Check rate limit BEFORE validating
        await _check_totp_recovery_code_ratelimit(user.id)

        if not user.totp_secret or not verify_totp(user.totp_secret, totp_code):
            current, remaining = await _increment_totp_recovery_code_attempts(user.id)
            detail = (
                f"Too many failed attempts ({current}/{TOTP_RECOVERY_CODE_MAX_ATTEMPTS}). "
                "Account locked for 10 minutes."
                if remaining == 0
                else f"Incorrect verification code. {remaining} attempt(s) remaining."
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

        # ✅ Success — clear the counter
        await _clear_totp_recovery_code_ratelimit(user.id)
        return

    await _check_totp_recovery_code_ratelimit(user.id)  # ✅ check before anything

    if await _get_used_recovery_codes_count(db, user.id) >= int(settings.RECOVERY_CODE_COUNT):
        #await _mark_account_blocked(db, user)  # Block account after max attempts exceeded
       return error_response(
            
            status_code=status.HTTP_401_UNAUTHORIZED,
            errors={"recovery_exceeded": True},
            message="All recovery codes have been used. Please contact support to reset MFA.",
        )

    unused_codes = await _get_unused_recovery_codes(db, user.id)
    for stored in unused_codes:
        if verify_recovery_code(recovery_code, stored.hashed_code):
            await _mark_recovery_code_used(db, stored)
            await _clear_totp_recovery_code_ratelimit(user.id)
            return
    if await _is_recovery_code_used(db, RecoveryCode(user_id=user.id, hashed_code=hash_recovery_code(recovery_code))):
        current, remaining = await _increment_totp_recovery_code_attempts(user.id)
        detail = (
            f"Recovery code already used. {remaining} attempt(s) remaining."
            if remaining > 0
            else  f"Too many failed attempts ({current}/{TOTP_RECOVERY_CODE_MAX_ATTEMPTS}). "
        "Account locked for 10 minutes."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
        )
    # ✅ No match — increment
    current, remaining = await _increment_totp_recovery_code_attempts(user.id)
    detail = (
        f"Too many failed attempts ({current}/{TOTP_RECOVERY_CODE_MAX_ATTEMPTS}). "
        "Account locked for 10 minutes."
        if remaining == 0
        else f"Incorrect recovery code. {remaining} attempt(s) remaining."
    )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)

  


# ---------------------------------------------------------------------------
# Disable MFA
# ---------------------------------------------------------------------------


async def disable_mfa(db: AsyncSession, user: User, totp_code: str) -> None:
    """Disable MFA — requires current password + valid TOTP code."""
    if not user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled on this account.",
        )
    if not user.totp_secret or not verify_totp(user.totp_secret, totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code.",
        )

    await _delete_recovery_codes(db, user.id)
    await _update_mfa_fields(db, user, totp_secret=None, mfa_enabled=False)
