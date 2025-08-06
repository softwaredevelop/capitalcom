# src/capitalcom_bot/utils/plotting.py

from typing import Any, Dict, List

from loguru import logger

from ..api_client import CapitalComAPIClient


def create_rangebreaks_for_epic(
    client: CapitalComAPIClient, epic: str
) -> List[Dict[str, Any]]:
    """
    Fetches opening hours for a given epic and creates a robust set of
    rangebreak rules for Plotly to hide non-trading periods.

    For cryptocurrencies, which trade 24/7, it returns an empty list.
    For other markets, it combines a general weekend break with a specific
    daily break derived from a representative weekday's schedule.

    Args:
        client (CapitalComAPIClient): An active API client instance.
        epic (str): The epic identifier of the instrument.

    Returns:
        List[Dict[str, Any]]: A list of rangebreak rules for Plotly's update_xaxes method.
    """
    try:
        logger.debug(f"Fetching details for {epic} to create precise rangebreaks...")
        full_details = client.get_full_market_details(epic=epic)
        instrument_type = full_details.instrument.type
        opening_hours = full_details.instrument.opening_hours

        # Handle 24/7 markets like cryptocurrencies
        if instrument_type.upper() == "CRYPTOCURRENCIES":
            logger.info(f"{epic} is a Cryptocurrency. No rangebreaks will be applied.")
            return []

        # --- Create rules for markets with closing times ---

        # Rule 1: Always hide the entire weekend. This is the most important rule.
        rangebreaks = [dict(bounds=["sat", "mon"])]

        # Rule 2: Find a representative daily schedule to hide overnight gaps.
        # We check Tuesday, Wednesday, or Thursday for a valid schedule, as they are
        # less likely to be affected by holidays than Monday or Friday.
        representative_schedule = (
            opening_hours.tue or opening_hours.wed or opening_hours.thu
        )

        if representative_schedule:
            # Assumes the first entry is the main trading session for the day
            schedule_parts = representative_schedule[0].split(" - ")
            open_hour = int(schedule_parts[0].split(":")[0])
            close_hour = int(schedule_parts[1].split(":")[0])

            # Add a rule for the daily non-trading period (e.g., from 21:00 to 08:00)
            rangebreaks.append(dict(bounds=[close_hour, open_hour], pattern="hour"))

            logger.info(
                f"Created precise rangebreaks for {epic} (daily break: {close_hour}:00 - {open_hour}:00 UTC)."
            )

        return rangebreaks

    except Exception as e:
        logger.warning(
            f"Could not create precise rangebreaks for {epic}, using default weekend break. Error: {e}"
        )
        # Fallback to a simple weekend break if anything goes wrong
        return [dict(bounds=["sat", "mon"])]
