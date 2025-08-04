from pathlib import Path

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings

# --- Models for the strategy configuration ---


class ApiSettings(BaseModel):
    demo_mode: bool


class StrategySettings(BaseModel):
    name: str
    epics: list[str]
    resolution: str
    rsi_period: int
    rsi_oversold_threshold: int
    rsi_overbought_threshold: int


class TradingSettings(BaseModel):
    trade_size_mode: str
    trade_size_percent: float
    trade_size_manual: float
    stop_loss_pips: int
    take_profit_pips: int


class StrategyConfig(BaseModel):
    """Model containing the complete strategy-specific configuration."""

    api: ApiSettings
    strategy: StrategySettings
    trading: TradingSettings


# --- Model for API credentials ---


class ApiCredentials(BaseSettings):
    """Loads API credentials from the .env file."""

    api_key: str
    identifier: str
    password: str

    class Config:
        env_prefix = "CAPITAL_"
        env_file = ".env"
        env_file_encoding = "utf-8"


# --- Standalone loader functions ---


def load_api_credentials() -> ApiCredentials:
    """Loads only the API credentials from the .env file."""
    return ApiCredentials()


def load_strategy_config(config_path: Path) -> StrategyConfig:
    """Loads the strategy-specific configuration from the given YAML file."""
    if not config_path.is_file():
        raise FileNotFoundError(f"Strategy config file not found at {config_path}")

    with open(config_path, "r") as f:
        yaml_config = yaml.safe_load(f)

    return StrategyConfig(**yaml_config)
