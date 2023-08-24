from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    api_key: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
