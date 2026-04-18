from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token, get_password_hash, verify_password
from app.models import Organization, User, UserRole


DEMO_USERS = [
    {
        "username": "admin",
        "email": "admin@vanguard.local",
        "password": "admin123",
        "role": UserRole.admin,
    },
    {
        "username": "analyst",
        "email": "analyst@vanguard.local",
        "password": "analyst123",
        "role": UserRole.analyst,
    },
    {
        "username": "viewer",
        "email": "viewer@vanguard.local",
        "password": "viewer123",
        "role": UserRole.viewer,
    },
]


def seed_demo_users(db: Session) -> None:
    org = db.query(Organization).filter(Organization.name == "Vanguard SOC").first()
    if not org:
        org = Organization(name="Vanguard SOC")
        db.add(org)
        db.flush()

    for demo in DEMO_USERS:
        existing = db.query(User).filter(User.username == demo["username"]).first()
        if existing:
            continue
        db.add(
            User(
                username=demo["username"],
                email=demo["email"],
                hashed_password=get_password_hash(demo["password"]),
                role=demo["role"],
                organization_id=org.id,
            )
        )
    db.commit()


def authenticate_user(db: Session, username: str, password: str) -> User | None:
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_token_for_user(user: User) -> str:
    return create_access_token(
        subject=str(user.id),
        role=user.role.value,
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
    )
