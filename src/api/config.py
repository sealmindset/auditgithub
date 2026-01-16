import os
from pydantic_settings import BaseSettings

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

    # GitHub
    GITHUB_TOKEN: str = ""
    
    # Security
    SECRET_KEY: str = "your-secret-key-here"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # AI Configuration - Values come from .env file
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = ""  # Set in .env (e.g., gpt-5.1, gpt-4.1, gpt-3.5-turbo)
    
    ANTHROPIC_API_KEY: str = ""
    ANTHROPIC_MODEL: str = ""  # Set in .env (e.g., claude-sonnet-4-20250514)
    
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-pro-latest" # Default to 1.5 Pro
    
    AI_PROVIDER: str = "openai"  # openai, claude, anthropic_foundry, ollama, docker
    AI_MODEL: str = ""  # Fallback - typically use provider-specific model
    
    OLLAMA_BASE_URL: str = "http://ollama:11434"
    DOCKER_BASE_URL: str = "http://localhost:12434"  # Docker Model Runner
    DOCKER_MODEL: str = "ai/llama3.2:latest"  # Default model for Docker Model Runner
    
    AZURE_AI_FOUNDRY_ENDPOINT: str = ""
    AZURE_AI_FOUNDRY_API_KEY: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
