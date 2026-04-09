# ---------------------------------------------------------------------------
# TOTP rate-limiting (Redis-backed, mirrors OTP lockout pattern)
# ---------------------------------------------------------------------------

import redis
from app.core.config import settings
from fastapi import HTTPException, status

# Initialize Redis client (assuming default settings)
REDIS_HOST = settings.RedisHost
REDIS_PORT = settings.RedisPort
REDIS_DB = settings.RedisDB
REDIS_USERNAME = settings.RedisUsername
REDIS_PASSWORD = settings.RedisPassword
MASTER_OTP = settings.MASTER_OTP
ENV = settings.ENV


redis_client = redis.StrictRedis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    username=REDIS_USERNAME,
    password=REDIS_PASSWORD,
    decode_responses=True
)

TOTP_RECOVERY_CODE_MAX_ATTEMPTS = 5
TOTP_RECOVERY_CODE_LOCKOUT_DURATION = 600  # 10 minutes


async def _check_totp_recovery_code_ratelimit(user_id) -> None:
    """Raises 429 if user is locked out, increments attempt counter otherwise."""
    lockout_key = f"totp_lockout:{user_id}"   # <-- different prefix from otp_lockout:
    attempts_key = f"totp_attempts:{user_id}" # <-- different prefix from otp_attempts:

    # 1. Already locked out?
    if  redis_client.exists(lockout_key):
        remaining =  redis_client.ttl(lockout_key)
        remaining_minutes = (remaining + 59) // 60
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {remaining_minutes} minute(s).",
        )

    # 2. Read current attempts
    current = int( redis_client.get(attempts_key) or 0)

    # 3. Already hit the ceiling on previous call?
    if current >= TOTP_RECOVERY_CODE_MAX_ATTEMPTS:
        redis_client.setex(lockout_key, TOTP_RECOVERY_CODE_LOCKOUT_DURATION, "1")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts ({current}/{TOTP_RECOVERY_CODE_MAX_ATTEMPTS}). "
                   "Account locked for 10 minutes.",
        )


async def _increment_totp_recovery_code_attempts(user_id) -> tuple[int, int]:
    """Increments attempt counter. Returns (current_attempts, remaining_attempts)."""
    attempts_key = f"totp_attempts:{user_id}"
    lockout_key = f"totp_lockout:{user_id}"

    current = int(redis_client.get(attempts_key) or 0) + 1
    remaining = max(TOTP_RECOVERY_CODE_MAX_ATTEMPTS - current, 0)

    # Store attempts for 10 minutes (same as lockout window)
    redis_client.setex(attempts_key, TOTP_RECOVERY_CODE_LOCKOUT_DURATION, str(current))

    if current >= TOTP_RECOVERY_CODE_MAX_ATTEMPTS:
        redis_client.setex(lockout_key, TOTP_RECOVERY_CODE_LOCKOUT_DURATION, "1")

    return current, remaining


async def _clear_totp_recovery_code_ratelimit(user_id) -> None:
    """Call this on successful TOTP verification."""
    redis_client.delete(f"totp_attempts:{user_id}")
    redis_client.delete(f"totp_lockout:{user_id}")
    


