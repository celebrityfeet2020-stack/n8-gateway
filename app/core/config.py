"""
配置模块 - 管理应用配置
"""
import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """应用配置"""
    # 应用信息
    APP_NAME: str = "N8 Gateway"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # 数据库配置
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://n8_user:password@localhost:5432/n8_control"
    )
    
    # JWT配置
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET", "default_secret_key_change_in_production")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_HOURS: int = 24
    
    # API Key配置
    API_KEY_PREFIX: str = "n8_"
    
    class Config:
        env_file = ".env"


settings = Settings()
