from alembic.environment import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.auth.mfa.schemas import (
    MFAConfirmRequest,
    MFAEnrollResponse,
    MFAStatusResponse,
    MFAVerifyLoginRequest,
    PasswordWithTOTPRequest,
    RecoveryCodesResponse,
)
from app.api.auth.mfa import service as mfa_service
from app.common.responses import success_response  # your helpers
from app.core.config import settings
from app.common.dependencies import get_current_user, get_async_db
from app.api.auth.helpers.jwt import (
    create_access_token,
)
from app.db.models.user import User

mfa_router = APIRouter(prefix="/mfa", tags=["MFA"])
bearer_scheme = HTTPBearer()


# ---------------------------------------------------------------------------
# Pre-auth token dependency (used only by /verify-login)
# ---------------------------------------------------------------------------
def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT. Raises JWTError on failure."""
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


async def get_pre_auth_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_async_db),
) -> User:
    """Decode a pre-auth (mfa_pending) token and return the user.
    Used exclusively by POST /mfa/verify-login.
    """
    token = credentials.credentials
    try:
        payload = decode_token(token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired pre-auth token.",
        )

    if payload.get("scope") != "mfa_pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint requires a pre-auth token from /auth/login.",
        )

    user_id: str | None = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token.",
        )

    result = await db.execute(
        select(User).options(selectinload(User.role)).where(User.id == user_id, User.is_deleted == False)  # noqa: E712
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
        )
    return user


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@mfa_router.get("/status", response_model=MFAStatusResponse)
async def mfa_status(current_user: User = Depends(get_current_user)):
    return MFAStatusResponse(
        mfa_enabled=current_user.mfa_enabled,
        totp_enrolled=current_user.totp_secret is not None,
    )


@mfa_router.post(
    "/enroll",
    response_model=MFAEnrollResponse,
    summary="Start MFA enrollment — generates TOTP secret & QR URI",
)
async def enroll(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    secret, uri = await mfa_service.start_enrollment(db, current_user)
    return MFAEnrollResponse(secret=secret, otpauth_uri=uri)


@mfa_router.post(
    "/confirm",
    response_model=RecoveryCodesResponse,
    summary="Confirm enrollment — verify first TOTP code, receive recovery codes",
)
async def confirm_enrollment(
    payload: MFAConfirmRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    plaintext_codes = await mfa_service.confirm_enrollment(db, current_user, payload.totp_code)
    return RecoveryCodesResponse(recovery_codes=plaintext_codes)


@mfa_router.post(
    "/verify-login",
    summary="MFA login step 2 — verify TOTP or recovery code, receive full token",
)
async def verify_login(
    payload: MFAVerifyLoginRequest,
    pre_auth_user: User = Depends(get_pre_auth_user),
    db: AsyncSession = Depends(get_async_db),
):
    await mfa_service.verify_mfa_login(
        db,
        pre_auth_user,
        totp_code=payload.totp_code,
        recovery_code=payload.recovery_code,
    )
    token = create_access_token(data={"sub": str(pre_auth_user.id), "scope": "full_access"})
    return success_response(data={"access_token": token}, message="MFA verified successfully" )


@mfa_router.post("/disable", status_code=204, summary="Disable MFA")
async def disable_mfa(
    payload: PasswordWithTOTPRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_async_db),
):
    await mfa_service.disable_mfa(db, current_user, payload.totp_code)
    return success_response(data={}, message="MFA Disabled successfully")
