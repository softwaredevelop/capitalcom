# src/capitalcom_bot/utils/data_processing.py

import pandas as pd
from loguru import logger


def clean_trading_data(df: pd.DataFrame, instrument_type: str) -> pd.DataFrame:
    """
    Cleans historical trading data based on the instrument type.

    - For most instruments (SHARES, INDICES, etc.), it removes weekend data.
    - For CRYPTOCURRENCIES, it keeps all data as they trade 24/7.

    Args:
        df (pd.DataFrame): The raw historical data with a DatetimeIndex.
        instrument_type (str): The type of the instrument (e.g., 'CRYPTOCURRENCIES').

    Returns:
        pd.DataFrame: The cleaned data ready for analysis.
    """
    if df.empty:
        return df

    original_count = len(df)

    if instrument_type.upper() == "CRYPTOCURRENCIES":
        logger.info(
            f"Instrument is a Cryptocurrency ({instrument_type}). Keeping weekend data."
        )
        # For crypto, we might still want to remove periods of no activity
        df_cleaned = df[df["high"] != df["low"]].copy()
    else:
        logger.info(f"Instrument type is {instrument_type}. Removing weekend data.")
        # For traditional markets, remove weekends (Saturday=5, Sunday=6)
        df_cleaned = df[df.index.dayofweek < 5].copy()

    cleaned_count = len(df_cleaned)
    logger.info(
        f"Data cleaning complete. Removed {original_count - cleaned_count} non-trading candles."
    )

    return df_cleaned
