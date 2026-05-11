from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session, query
from sqlalchemy import select
from app.models.user import User, PasswordHistory
from app.core.security import hash_password,verify_password,create_access_token

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
PASSWORD_EXPIRATION_DAYS = 90


def create_user(db:Session, email:str,password:str,full_name:str | None = None, role:str = "employee"):
    hashed_password = hash_password(password)
    user = User(
        email=email,
        password_hash=hashed_password,
        full_name=full_name,
        role=role,
        password_changed_at=datetime.now(timezone.utc)
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    history = PasswordHistory(user_id=user.id, password_hash=hashed_password)
    db.add(history)
    db.commit()
    return user

def authenticate_user(db:Session, email:str, password:str):
    stmt = select(User).where(User.email == email)
    user = db.scalar(stmt)

    if not user:
        return None, "Invalid Credentials", False

    if not user.is_active:
        return None,"Account is disabled. Please contact an administrator.",False

    if user.account_locked_until:
        now = datetime.now(timezone.utc)
        locked_until=user.account_locked_until.replace(tzinfo=timezone.utc)

        if locked_until>now:
            remaining = locked_until - now
            minutes = int(remaining.total_seconds() // 60)
            seconds = int(remaining.total_seconds() % 60)
            return None,f"Account locked Until {minutes}m {seconds} seconds.",False
        else:
            user.account_locked_until = None
            user.failed_login_attempts = 0
            db.commit()

    if not verify_password(password,user.password_hash):
        user.failed_login_attempts += 1
        remaining_tries=MAX_FAILED_ATTEMPTS - user.failed_login_attempts

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.account_locked_until = datetime.now(timezone.utc)+timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            error_msg = f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes. due to excessive failed attempts."
        else:
            error_msg = f"Invalid Credentials. {remaining_tries} more tries left."
        db.commit()
        return None,error_msg,False

    user.failed_login_attempts = 0
    user.account_locked_until = None
    db.commit()
    needs_reset=False
    if user.password_changed_at:
        days_since_change = (datetime.now(timezone.utc) - user.password_changed_at.replace(tzinfo=timezone.utc)).days
        if days_since_change >= PASSWORD_EXPIRATION_DAYS:
            needs_reset=True
    return user,None,needs_reset


def create_user_token(user):
    data = {"sub":str(user.id),"role":user.role}
    return create_access_token(data)

def unlock_user_account (db:Session, user:User):
    stmt = select(User).where(User.id == user.id)
    user = db.scalar(stmt)

    if not user:
        return False,"User Not Found."

    user.failed_login_attempts = 0
    user.account_locked_until = None
    user.is_active = True

    db.commit()
    return True, f"Account for {user.email} has been successfully unlocked."