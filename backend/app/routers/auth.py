from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user, require_roles
from app.models import Role, User
from app.schemas import LoginRequest, TokenResponse, UserOut
from app.security import create_access_token, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user.username, user.role.value)
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/analysts", response_model=list[UserOut])
def list_analysts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst, Role.detection_engineer)),
):
    return (
        db.query(User)
        .filter(
            User.organization_id == current_user.organization_id,
            User.role.in_([Role.admin, Role.analyst]),
        )
        .order_by(User.full_name.asc())
        .all()
    )
