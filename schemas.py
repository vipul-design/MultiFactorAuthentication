from pydantic import BaseModel


class MFAEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MFAConfirmRequest(BaseModel):
    totp_code: str


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]
    message: str = (
        "Save these recovery codes in a safe place. "
        "Each code can only be used once and they will not be shown again."
    )


class MFAStatusResponse(BaseModel):
    mfa_enabled: bool
    totp_enrolled: bool


class MFAVerifyLoginRequest(BaseModel):
    totp_code: str | None = None
    recovery_code: str | None = None


class PasswordWithTOTPRequest(BaseModel):
    totp_code: str
