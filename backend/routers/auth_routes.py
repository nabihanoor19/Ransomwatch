from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from database import get_db
import models
import schemas
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_active_user,
    require_admin,
)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)

# -------------------------------------------------------------------
# 1. REGISTER ENDPOINT
# -------------------------------------------------------------------
@router.post(
    "/register",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new operator"
)
def register(user_data: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if username already exists
    existing_username = db.query(models.User).filter(models.User.username == user_data.username).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Check if email already exists
    existing_email = db.query(models.User).filter(models.User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Hash the password with Argon2
    hashed = hash_password(user_data.password)

    # Always default to 'operator' to prevent privilege escalation
    new_user = models.User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hashed,
        role="operator",
        is_active=True
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Record registration in Audit Log
    audit_entry = models.AuditLog(
        user_id=new_user.id,
        action="USER_REGISTERED",
        resource_type="users",
        resource_id=str(new_user.id),
        status="success",
        details={"username": new_user.username, "email": new_user.email, "role": new_user.role}
    )
    db.add(audit_entry)
    db.commit()

    return new_user


# -------------------------------------------------------------------
# 2. LOGIN ENDPOINT (Supports OAuth2 form for Swagger UI & standard clients)
# -------------------------------------------------------------------
@router.post(
    "/login",
    response_model=schemas.Token,
    summary="Login with credentials to obtain a JWT access token"
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    OAuth2 standard login:
    form_data.username can be either the user's email or username.
    """
    # Look up user by email OR username
    user = db.query(models.User).filter(
        (models.User.email == form_data.username) | (models.User.username == form_data.username)
    ).first()

    # Validate user existence and password hash
    if not user or not verify_password(form_data.password, user.password_hash):
        # Log failed attempt
        audit_entry = models.AuditLog(
            user_id=user.id if user else None,
            action="USER_LOGIN_FAILED",
            resource_type="auth",
            resource_id=form_data.username,
            status="failure",
            details={"attempted_identifier": form_data.username}
        )
        db.add(audit_entry)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username/email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account is inactive"
        )

    # Generate JWT (subject is user.id as string)
    access_token = create_access_token(data={"sub": str(user.id)})

    # Log successful login
    audit_entry = models.AuditLog(
        user_id=user.id,
        action="USER_LOGIN_SUCCESS",
        resource_type="auth",
        resource_id=str(user.id),
        status="success",
        details={"username": user.username, "role": user.role}
    )
    db.add(audit_entry)
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# -------------------------------------------------------------------
# 3. GET CURRENT USER PROFILE
# -------------------------------------------------------------------
@router.get(
    "/me",
    response_model=schemas.UserResponse,
    summary="Get profile of currently logged-in user"
)
def get_me(current_user: models.User = Depends(get_current_active_user)):
    return current_user


# -------------------------------------------------------------------
# 4. ADMIN-ONLY TEST ROUTE (RBAC Demonstration)
# -------------------------------------------------------------------
@router.get(
    "/admin-only",
    response_model=schemas.MessageResponse,
    summary="Admin-only test endpoint"
)
def admin_only_check(current_user: models.User = Depends(require_admin)):
    return {
        "message": f"Welcome Administrator {current_user.username}. You have elevated access."
    }