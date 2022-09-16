import os

T_ENV_TYPE = str | list | bool


def get_from_env(name: str, default: T_ENV_TYPE = None) -> str | list | bool:
    return os.getenv(name, default=default)
