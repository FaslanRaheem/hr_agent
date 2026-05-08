import uuid
from datetime import datetime

from sqlalchemy import String, Boolean, DateTime, Column
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.session import Base

class User(Base):
    __tablename__ = "user"
    id : Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True,default=uuid.uuid4)
    email : Mapped[str] = mapped_column(String(255), nullable=False,unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    full_name: Mapped[str|None] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="employee")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    manager_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=True)

    google_access_token: Mapped[str] = mapped_column(String(255), nullable=True)
    google_refresh_token: Mapped[str] = mapped_column(String(255), nullable=True)
    google_token_expiry: Mapped[datetime] = mapped_column(String(255),nullable=True)

