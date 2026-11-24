
from pydantic import BaseModel, ConfigDict, Field, EmailStr
from typing import Optional, Any, Literal
from datetime import datetime


# ==========================================
# COMMON CONFIGURATION
# ==========================================

class ORMBaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ==========================================
# 1. USER SCHEMAS
# ==========================================

# Data accepted when creating a user
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


# Data returned by the API
class UserResponse(ORMBaseSchema):
    id: int
    username: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime


# ==========================================
# 2. MONITORED FOLDER SCHEMAS
# ==========================================

class FolderCreate(BaseModel):
    folder_path: str = Field(min_length=1, max_length=500)
    folder_name: str = Field(min_length=1, max_length=255)


class FolderResponse(ORMBaseSchema):
    id: int
    folder_path: str
    folder_name: str
    status: str
    created_by: int
    created_at: datetime


# ==========================================
# 3. FILE EVENT SCHEMAS
# ==========================================

# Data received from the trusted security engine
class FileEventCreate(BaseModel):
    event_type: str = Field(min_length=1, max_length=50)
    file_name: str = Field(min_length=1, max_length=255)
    module: Optional[str] = None

    folder_id: int = Field(gt=0)

    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_score: float = Field(ge=0, le=100)

    evidence: list[str] = Field(default_factory=list)


# Data returned by the API
class FileEventResponse(ORMBaseSchema):
    id: int
    event_id: str
    event_type: str
    file_name: str
    module: Optional[str]
    severity: str
    risk_score: float
    evidence: list
    timestamp: datetime
    folder_id: int
    incident_id: Optional[int]


# ==========================================
# 4. INCIDENT SCHEMAS
# ==========================================

class IncidentCreate(BaseModel):
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_score: float = Field(ge=0, le=100)
    description: Optional[str] = None
    evidence: list[str] = Field(default_factory=list)


class IncidentResponse(ORMBaseSchema):
    id: int
    incident_id: str
    severity: str
    risk_score: float
    description: Optional[str]
    evidence: list
    status: str
    created_at: datetime
    updated_at: datetime


# ==========================================
# 5. AUDIT LOG SCHEMAS
# ==========================================

class AuditLogResponse(ORMBaseSchema):
    id: int
    user_id: Optional[int]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    status: str
    details: dict
    timestamp: datetime


# ==========================================
# 6. CONFIGURATION SCHEMAS
# ==========================================

class ConfigurationCreate(BaseModel):
    rule_name: str = Field(min_length=1, max_length=100)
    value: Any
    is_enabled: bool = True


class ConfigurationResponse(ORMBaseSchema):
    id: int
    rule_name: str
    value: Any
    is_enabled: bool
    updated_by: Optional[int]
    updated_at: datetime


# ==========================================
# 7. STANDARD API RESPONSE SCHEMAS
# ==========================================

class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    error_code: str
    message: str
# ==========================================
# AUTHENTICATION SCHEMAS
# ==========================================

# 1. Login Request (when clients send JSON credentials)
class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

# 2. Token Response (returned upon successful login)
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# 3. Token Data Payload (internal representation extracted from JWT)
class TokenData(BaseModel):
    user_id: Optional[int] = None