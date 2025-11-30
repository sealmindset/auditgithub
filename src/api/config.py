import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    # Database
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: str = "5432"
    POSTGRES_USER: str = "auditgh"
    POSTGRES_PASSWORD: str = "auditgh_secret"
    POSTGRES_DB: str = "auditgh_kb"

    # Jira
    JIRA_URL: str = ""
    JIRA_USERNAME: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_PROJECT_KEY: str = "SEC"
    
    # Security
    SECRET_KEY: str = "your-secret-key-here"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # AI
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    AI_PROVIDER: str = "openai"
    AI_MODEL: str = "gpt-4-turbo-preview"

    class Config:
        env_file = ".env"

settings = Settings()
