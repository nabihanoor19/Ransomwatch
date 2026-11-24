
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    Float,
    DateTime,
    ForeignKey,
    JSON,
    Text
)
from sqlalchemy.orm import relationship
from datetime import datetime

from database import Base


# ==========================================
# 1. USER TABLE
# ==========================================

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)

    # Roles: admin or operator
    role = Column(String(20), default="operator", nullable=False)

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    monitored_folders = relationship(
        "MonitoredFolder",
        back_populates="creator"
    )

    audit_logs = relationship(
        "AuditLog",
        back_populates="user"
    )


# ==========================================
# 2. MONITORED FOLDER TABLE
# ==========================================

class MonitoredFolder(Base):
    __tablename__ = "monitored_folders"

    id = Column(Integer, primary_key=True, index=True)
    folder_path = Column(String(500), unique=True, nullable=False)
    folder_name = Column(String(255), nullable=False)

    # Monitoring status
    status = Column(String(20), default="stopped")

    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    creator = relationship(
        "User",
        back_populates="monitored_folders"
    )

    file_events = relationship(
        "FileEvent",
        back_populates="folder"
    )


# ==========================================
# 3. FILE EVENT TABLE
# ==========================================

class FileEvent(Base):
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True, index=True)

    # Event information
    event_id = Column(String(100), unique=True, nullable=False, index=True)
    event_type = Column(String(50), nullable=False)

    # File information
    file_name = Column(String(255), nullable=False)
    module = Column(String(50))

    # Detection information
    severity = Column(String(20), default="LOW")
    risk_score = Column(Float, default=0.0)
    evidence = Column(JSON, default=list)

    timestamp = Column(DateTime, default=datetime.utcnow)

    # Related folder
    folder_id = Column(
        Integer,
        ForeignKey("monitored_folders.id"),
        nullable=False
    )

    # Related incident (can be empty if no incident is created)
    incident_id = Column(
        Integer,
        ForeignKey("incidents.id"),
        nullable=True
    )

    # Relationships
    folder = relationship(
        "MonitoredFolder",
        back_populates="file_events"
    )

    incident = relationship(
        "Incident",
        back_populates="file_events"
    )


# ==========================================
# 4. INCIDENT TABLE
# ==========================================

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(String(100), unique=True, nullable=False, index=True)

    # Incident details
    severity = Column(String(20), nullable=False)
    risk_score = Column(Float, default=0.0)
    description = Column(Text)

    # Supporting evidence
    evidence = Column(JSON, default=list)

    # Incident status: open, investigating, resolved
    status = Column(String(30), default="open")

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Relationships
    file_events = relationship(
        "FileEvent",
        back_populates="incident"
    )


# ==========================================
# 5. AUDIT LOG TABLE
# ==========================================

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    # User who performed the action.
    # Can be NULL for failed login attempts or system events.
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    action = Column(String(100), nullable=False)
    resource_type = Column(String(50))
    resource_id = Column(String(100))

    # success or failure
    status = Column(String(20), nullable=False)

    # Additional information about the action
    details = Column(JSON, default=dict)

    timestamp = Column(DateTime, default=datetime.utcnow)

    # Relationship
    user = relationship(
        "User",
        back_populates="audit_logs"
    )


# ==========================================
# 6. CONFIGURATION TABLE
# ==========================================

class Configuration(Base):
    __tablename__ = "configurations"

    id = Column(Integer, primary_key=True, index=True)

    rule_name = Column(String(100), unique=True, nullable=False)

    # Stores threshold or other rule settings
    value = Column(JSON, nullable=False)

    is_enabled = Column(Boolean, default=True)

    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Relationship
    updater = relationship("User")
