from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Vanguard AI"
    environment: str = "development"
    database_url: str = "sqlite:///./vanguard_ai.db"
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_exp_minutes: int = 60

    model_config = SettingsConfigDict(env_file=".env", env_prefix="VANGUARD_")


settings = Settings()
