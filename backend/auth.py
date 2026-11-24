from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from sqlalchemy.orm import Session

from config import settings
from database import get_db
import models
import schemas

# Initialize password hasher with Argon2
password_hash = PasswordHash((Argon2Hasher(),))

def hash_password(password: str) -> str:
    """
    Takes a plain text password and returns a secure Argon2 hash.
    Argon2 automatically handles generating a cryptographically secure random salt.
    """
    return password_hash.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain text password against the stored Argon2 hash.
    Returns True if valid, False otherwise.
    """
    return password_hash.verify(plain_password, hashed_password)

# Tells FastAPI where clients should send credentials to get a token
# (Used in Swagger UI at /docs for the "Authorize" button)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a signed JWT access token.
    'data' dictionary must contain the subject ('sub'), e.g. user ID or email.
    """
    to_encode = data.copy()

    # Determine expiration time
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Standard JWT claims: exp (expiration), iat (issued at)
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    })

    # Encode and sign the JWT using our SECRET_KEY
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    """
    Decodes and validates a JWT token.
    Returns the payload dictionary if valid, or None if expired/tampered.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        return payload
    except jwt.PyJWTError:
        return None

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    """
    FastAPI dependency:
    1. Extracts token from 'Authorization: Bearer <token>' header.
    2. Decodes and verifies signature & expiration.
    3. Fetches the User record from the SQLite database.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception

    user_id_str: str = payload.get("sub")
    if user_id_str is None:
        raise credentials_exception

    try:
        user_id = int(user_id_str)
    except ValueError:
        raise credentials_exception

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise credentials_exception

    return user

def get_current_active_user(
    current_user: models.User = Depends(get_current_user)
) -> models.User:
    """
    Ensures that the user account is active.
    Deactivated users are blocked immediately even with a valid token.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user account"
        )
    return current_user

def require_admin(
    current_user: models.User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
) -> models.User:
    """
    Role-Based Access Control (RBAC):
    Allows access only if current_user.role == 'admin'.
    If an operator or unauthorized user attempts access:
    1. Records the unauthorized attempt in the audit_logs table.
    2. Raises HTTP 403 Forbidden with detail 'Insufficient permissions'.
    """
    if current_user.role != "admin":
        audit_entry = models.AuditLog(
            user_id=current_user.id,
            action="ADMIN_ACCESS_DENIED",
            resource_type="admin_endpoint",
            resource_id=None,
            status="failure",
            details={
                "username": current_user.username,
                "role": current_user.role,
                "reason": "Insufficient permissions: Administrator role required"
            }
        )
        db.add(audit_entry)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions: Administrator privileges required"
        )
    return current_user
