import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import LoginRequest, TokenResponse, UserContext
from app.services.auth_service import authenticate_user, create_token_for_user
from app.services.dependencies import get_current_user_context

router = APIRouter(prefix="/auth")
logger = logging.getLogger(__name__)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = authenticate_user(db, payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_token_for_user(user)
    logger.info("user_login", extra={"context": {"username": user.username, "role": user.role.value}})
    return TokenResponse(access_token=token, role=user.role.value)


@router.get("/me", response_model=UserContext)
def me(current_user: UserContext = Depends(get_current_user_context)) -> UserContext:
    return current_user
