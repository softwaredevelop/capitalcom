# src/capitalcom_bot/config.py

from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel
from pydantic_settings import BaseSettings

# ==============================================================================
# --- Pydantic Models for Strategy Configuration (strategy_config.yml) ---
# ==============================================================================


class ApiSettings(BaseModel):
    """API-related settings from the config file."""

    demo_mode: bool


class StrategySettings(BaseModel):
    """Parameters specific to the trading strategy."""

    name: str
    epics: List[str]
    resolution: str
    rsi_period: int
    rsi_oversold_threshold: int
    rsi_overbought_threshold: int


class TradingSettings(BaseModel):
    """Settings related to trade execution and risk management."""

    trade_size_mode: str
    trade_size_percent: float
    trade_size_manual: float
    stop_loss_pips: int
    take_profit_pips: int


class StrategyConfig(BaseModel):
    """
    The root model for the entire strategy_config.yml file.
    It encapsulates all other configuration sections.
    """

    api: ApiSettings
    strategy: StrategySettings
    trading: TradingSettings


# ==============================================================================
# --- Pydantic Model for API Credentials (.env file) ---
# ==============================================================================


class ApiCredentials(BaseSettings):
    """
    Loads sensitive API credentials from environment variables or a .env file.

    Attributes:
        api_key (str): The API key generated from the Capital.com platform.
        identifier (str): The login identifier (usually email).
        password (str): The custom password associated with the API key.
    """

    api_key: str
    identifier: str
    password: str

    class Config:
        """Pydantic-settings configuration."""

        env_prefix = "CAPITAL_"  # Looks for env vars like CAPITAL_API_KEY
        env_file = ".env"
        env_file_encoding = "utf-8"


# ==============================================================================
# --- Standalone Loader Functions ---
# ==============================================================================


def load_api_credentials() -> ApiCredentials:
    """
    Loads only the API credentials.

    This function is a simple wrapper around the ApiCredentials model,
    which automatically handles loading from environment variables or a .env file.

    Returns:
        ApiCredentials: An instance of the ApiCredentials model.
    """
    return ApiCredentials()


def load_strategy_config(config_path: Path) -> StrategyConfig:
    """
    Loads the strategy-specific configuration from a given YAML file.

    Args:
        config_path (Path): The path to the strategy_config.yml file.

    Raises:
        FileNotFoundError: If the specified config file does not exist.

    Returns:
        StrategyConfig: An instance of the StrategyConfig model.
    """
    if not config_path.is_file():
        raise FileNotFoundError(f"Strategy config file not found at: {config_path}")

    with open(config_path, "r") as f:
        yaml_config = yaml.safe_load(f)

    return StrategyConfig(**yaml_config)
