from uuid import UUID

from fastapi import APIRouter,Depends,HTTPException,status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.deps import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import Token, UserCreate, UserLogin, UserUpdatePassword
from app.sercives import auth_service
from app.sercives.auth_service import create_user, create_user_token, authenticate_user, unlock_user_account

router = APIRouter(prefix="/auth",tags=["auth"])


@router.post("/register",response_model=Token)
def register(user_in:UserCreate,db:Session = Depends(get_db)):
    stmt = select(User).where(User.email == user_in.email)
    existing_user = db.scalar(stmt)

    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Email already registered")

    user = create_user(db,email=user_in.email,password=user_in.password,full_name=user_in.full_name)
    token = create_user_token(user)
    return {"access_token": token,"token_type":"bearer"}


@router.post("/login-form", response_model=Token)
def login(credentials: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user, error_msg, needs_reset = authenticate_user(db, credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_user_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "needs_password_reset": needs_reset
    }

@router.post("/login", response_model=Token)
def login_json(credentials: UserLogin, db: Session = Depends(get_db)):
    user = authenticate_user(db, credentials.email, credentials.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"access_token": create_user_token(user), "token_type": "bearer"}


@router.post("/change-password")
def change_password(payload: UserUpdatePassword, db: Session = Depends(get_db),
                    current_user: User = Depends(get_current_user)):
    success, msg = auth_service.change_password(
        db=db,
        user=current_user,
        old_password=payload.old_password,
        new_password=payload.new_password
    )

    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    return {"message": msg}

@router.get("/me", tags=["auth"])
def get_my_profile(current_user: User = Depends(get_current_user)):
    return {
        "message": "Authentication successful!",
        "employee_id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "annual_leave_balance": current_user.annual_leave_balance,
        "sick_leave_balance": current_user.sick_leave_balance
    }

@router.post("/users/{user_id}/unlock", tags=["admin", "auth"])
def admin_unlock_account(
        user_id: UUID,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    if current_user.role not in ["admin", "hr"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to perform this action."
        )
    success, message = unlock_user_account(db, user_id)

    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=message)

    return {"message": message}



