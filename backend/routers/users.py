"""
Users router.
POST /users/register — create account.
POST /users/login — authenticate and get JWT.
GET /users/me — get current user profile.
"""
import logging
import secrets
from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session

from auth import create_access_token, get_current_user
from database import get_db
from models import User, PasswordResetOTP
from schemas import (
    UserRegister,
    UserLogin,
    UserOut,
    Token,
    ForgotPasswordRequest,
    VerifyOTPRequest,
    ResetPasswordRequest,
)
from security import hash_password, verify_password

from datetime import datetime, timedelta, timezone

from email_service import send_otp_email

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from config import settings

from schemas import (
    UserRegister,
    UserLogin,
    UserOut,
    Token,
    ForgotPasswordRequest,
    VerifyOTPRequest,
    ResetPasswordRequest,
    GoogleLoginRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/users", tags=["users"])


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        full_name=payload.full_name,
        email=payload.email,
        username=payload.username,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token(subject=user.id)
    return Token(access_token=token, user=UserOut.model_validate(user))


@router.post("/login", response_model=Token)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    token = create_access_token(subject=user.id)
    return Token(access_token=token, user=UserOut.model_validate(user))

@router.post("/google", response_model=Token)
def google_login(
    payload: GoogleLoginRequest,
    db: Session = Depends(get_db)
):
    try:
        # Verify the credential with Google
        idinfo = id_token.verify_oauth2_token(
            payload.credential,
            google_requests.Request(),
            settings.GOOGLE_CLIENT_ID,
        )

        google_id = idinfo.get("sub")
        email = idinfo.get("email")
        email_verified = idinfo.get("email_verified", False)
        full_name = idinfo.get("name") or "Google User"

        if not google_id or not email or not email_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google account"
            )

        # First try to find an account already linked to this Google account
        user = db.query(User).filter(
            User.google_id == google_id
        ).first()

        # If not linked yet, check for an existing CyberVerify account
        # with the same verified Google email.
        if not user:
            user = db.query(User).filter(
                User.email == email
            ).first()

            if user:
                # Link Google to the existing account.
                user.google_id = google_id
                db.commit()
                db.refresh(user)

            else:
                # Generate a username from the Google email.
                base_username = email.split("@")[0]

                # Keep only safe username characters.
                base_username = "".join(
                    char for char in base_username
                    if char.isalnum() or char in "._-"
                )

                if not base_username:
                    base_username = "user"

                username = base_username

                # Ensure username is unique.
                while db.query(User).filter(
                    User.username == username
                ).first():
                    username = (
                        f"{base_username}_{secrets.token_hex(3)}"
                    )

                # The current database requires hashed_password.
                # Google users therefore receive an unusable random password.
                random_password = secrets.token_urlsafe(32)

                user = User(
                    full_name=full_name,
                    email=email,
                    username=username,
                    hashed_password=hash_password(random_password),
                    google_id=google_id,
                    auth_provider="google",
                )

                db.add(user)
                db.commit()
                db.refresh(user)

        # Issue the same CyberVerify JWT used by normal login.
        token = create_access_token(subject=user.id)

        return Token(
            access_token=token,
            user=UserOut.model_validate(user)
        )

    except HTTPException:
        raise

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired Google credential"
        )

    except Exception:
        logger.exception("Google Sign-In failed")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Google Sign-In failed"
        )

@router.post("/forgot-password")
def forgot_password(
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == payload.email).first()

    # Do not reveal whether an account exists
    if not user:
        return {
            "message": "If this email is registered, an OTP has been sent."
        }

    # Generate 6-digit OTP
    otp = f"{secrets.randbelow(1000000):06d}"

    # Hash OTP before storing it
    from security import hash_password

    otp_hash = hash_password(otp)

    reset_request = PasswordResetOTP(
        email=payload.email,
        otp_hash=otp_hash,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        attempts=0,
        verified=False,
    )

    db.add(reset_request)
    db.commit()

    send_otp_email(payload.email, otp)

    return {
        "message": "If this email is registered, an OTP has been sent."
    }

@router.post("/verify-otp")
def verify_otp(
    payload: VerifyOTPRequest,
    db: Session = Depends(get_db)
):
    from security import verify_password

    reset_request = (
        db.query(PasswordResetOTP)
        .filter(
            PasswordResetOTP.email == payload.email,
            PasswordResetOTP.verified == False
        )
        .order_by(PasswordResetOTP.created_at.desc())
        .first()
    )

    if not reset_request:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OTP"
        )

    now = datetime.now(timezone.utc)

    if reset_request.expires_at < now:
        raise HTTPException(
            status_code=400,
            detail="OTP has expired"
        )

    if reset_request.attempts >= 5:
        raise HTTPException(
            status_code=429,
            detail="Too many OTP attempts"
        )

    if not verify_password(payload.otp, reset_request.otp_hash):
        reset_request.attempts += 1
        db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid OTP"
        )

    reset_token = secrets.token_urlsafe(32)

    reset_request.verified = True
    reset_request.reset_token = reset_token

    db.commit()

    return {
        "message": "OTP verified successfully",
        "reset_token": reset_token
    }

@router.post("/reset-password")
def reset_password(
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=400,
            detail="Passwords do not match"
        )

    reset_request = (
        db.query(PasswordResetOTP)
        .filter(
            PasswordResetOTP.email == payload.email,
            PasswordResetOTP.reset_token == payload.reset_token,
            PasswordResetOTP.verified == True
        )
        .order_by(PasswordResetOTP.created_at.desc())
        .first()
    )

    if not reset_request:
        raise HTTPException(
            status_code=400,
            detail="Invalid password reset request"
        )

    if reset_request.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Password reset request has expired"
        )

    user = db.query(User).filter(
        User.email == payload.email
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    from security import hash_password

    user.hashed_password = hash_password(
        payload.new_password
    )

    # Invalidate reset token
    reset_request.reset_token = None
    reset_request.verified = False

    db.commit()

    return {
        "message": "Password reset successfully"
    }

@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return UserOut.model_validate(current_user)
