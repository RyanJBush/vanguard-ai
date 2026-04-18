from collections.abc import Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.db.session import get_db
from app.models import User, UserRole
from app.schemas.auth import UserContext

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def get_current_user_context(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> UserContext:
    try:
        payload = decode_token(token)
        user_id = int(payload["sub"])
    except (ValueError, KeyError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return UserContext(
        id=user.id,
        username=user.username,
        role=user.role.value,
        organization_id=user.organization_id,
    )


def require_roles(*roles: UserRole) -> Callable:
    role_values = {role.value for role in roles}

    def role_dependency(user: UserContext = Depends(get_current_user_context)) -> UserContext:
        if user.role not in role_values:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return role_dependency
