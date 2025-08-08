# src/capitalcom_bot/api_client.py

from base64 import b64encode
from typing import Any, Dict, List, Optional

import pandas as pd
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from loguru import logger
from pydantic import BaseModel, Field

# ==============================================================================
# --- Pydantic Models for API Responses ---
# ==============================================================================


class SessionDetails(BaseModel):
    client_id: str = Field(alias="clientId")
    account_id: str = Field(alias="accountId")
    timezone_offset: int = Field(alias="timezoneOffset")
    locale: str
    currency: str
    symbol: str
    stream_endpoint: str = Field(alias="streamEndpoint")


class MarketNode(BaseModel):
    id: str
    name: str


class MarketNavigationResponse(BaseModel):
    nodes: List[MarketNode]


class OpeningHours(BaseModel):
    mon: List[str]
    tue: List[str]
    wed: List[str]
    thu: List[str]
    fri: List[str]
    sat: List[str]
    sun: List[str]
    zone: str


class OvernightFee(BaseModel):
    long_rate: float = Field(alias="longRate")
    short_rate: float = Field(alias="shortRate")
    swap_charge_timestamp: int = Field(alias="swapChargeTimestamp")
    swap_charge_interval: int = Field(alias="swapChargeInterval")


class Instrument(BaseModel):
    epic: str
    symbol: str
    expiry: str
    name: str
    lot_size: float = Field(alias="lotSize")
    type: str
    guaranteed_stop_allowed: bool = Field(alias="guaranteedStopAllowed")
    streaming_prices_available: bool = Field(alias="streamingPricesAvailable")
    currency: str
    margin_factor: float = Field(alias="marginFactor")
    margin_factor_unit: str = Field(alias="marginFactorUnit")
    opening_hours: OpeningHours = Field(alias="openingHours")
    country: Optional[str] = None
    overnight_fee: OvernightFee = Field(alias="overnightFee")


class DealingRuleValue(BaseModel):
    unit: str
    value: float


class DealingRules(BaseModel):
    min_step_distance: DealingRuleValue = Field(alias="minStepDistance")
    min_deal_size: DealingRuleValue = Field(alias="minDealSize")
    max_deal_size: DealingRuleValue = Field(alias="maxDealSize")
    min_size_increment: DealingRuleValue = Field(alias="minSizeIncrement")
    min_guaranteed_stop_distance: DealingRuleValue = Field(
        alias="minGuaranteedStopDistance"
    )
    min_stop_or_profit_distance: DealingRuleValue = Field(
        alias="minStopOrProfitDistance"
    )
    max_stop_or_profit_distance: DealingRuleValue = Field(
        alias="maxStopOrProfitDistance"
    )
    market_order_preference: str = Field(alias="marketOrderPreference")
    trailing_stops_preference: str = Field(alias="trailingStopsPreference")


class Snapshot(BaseModel):
    market_status: str = Field(alias="marketStatus")
    net_change: Optional[float] = Field(alias="netChange", default=None)
    percentage_change: Optional[float] = Field(alias="percentageChange", default=None)
    update_time: Optional[str] = Field(alias="updateTime", default=None)
    delay_time: int = Field(alias="delayTime")
    bid: Optional[float] = None
    offer: Optional[float] = None
    high: Optional[float] = None
    low: Optional[float] = None
    decimal_places_factor: int = Field(alias="decimalPlacesFactor")
    scaling_factor: int = Field(alias="scalingFactor")
    market_modes: List[str] = Field(alias="marketModes")


class FullMarketDetails(BaseModel):
    instrument: Instrument
    dealing_rules: DealingRules = Field(alias="dealingRules")
    snapshot: Snapshot


class MarketSummary(BaseModel):
    epic: str
    instrument_name: str = Field(alias="instrumentName")
    instrument_type: str = Field(alias="instrumentType")
    market_status: str = Field(alias="marketStatus")
    bid: Optional[float] = None
    offer: Optional[float] = None
    update_time: str = Field(alias="updateTime")
    high: Optional[float] = None
    low: Optional[float] = None
    percentage_change: Optional[float] = Field(alias="percentageChange", default=None)
    net_change: Optional[float] = Field(alias="netChange", default=None)
    market_modes: Optional[List[str]] = Field(alias="marketModes", default=None)


class SearchMarketsResponse(BaseModel):
    markets: List[MarketSummary]


class GetMarketsByEpicsResponse(BaseModel):
    market_details: List[FullMarketDetails] = Field(alias="marketDetails")


class WatchlistItem(BaseModel):
    id: str
    name: str
    editable: bool
    deleteable: bool
    default_system_watchlist: bool = Field(alias="defaultSystemWatchlist")


class GetWatchlistsResponse(BaseModel):
    watchlists: List[WatchlistItem]


class CreateWatchlistResponse(BaseModel):
    watchlist_id: str = Field(alias="watchlistId")
    status: str


class StatusResponse(BaseModel):
    status: str


class GetWatchlistDetailsResponse(BaseModel):
    markets: List[MarketSummary]


# ==============================================================================
# --- API Client Class ---
# ==============================================================================


class CapitalComAPIClient:
    """
    A Python client for the Capital.com REST API.

    This class handles session management, authentication (including encrypted password),
    and provides methods for interacting with the main API endpoints.
    """

    def __init__(
        self, identifier: str, password: str, api_key: str, demo_mode: bool = True
    ):
        """
        Initializes the client and creates a new session.

        Args:
            identifier (str): Your Capital.com login email.
            password (str): The custom password for your API key.
            api_key (str): Your generated API key.
            demo_mode (bool): If True, connects to the demo environment.
        """
        self.base_url = (
            "https://demo-api-capital.backend-capital.com/api/v1"
            if demo_mode
            else "https://api-capital.backend-capital.com/api/v1"
        )
        self._identifier = identifier
        self._password = password
        self._api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({"X-CAP-API-KEY": self._api_key})
        self.cst: Optional[str] = None
        self.security_token: Optional[str] = None
        logger.info("Initializing API client...")
        self._create_session(use_encryption=True)

    # --------------------------------------------------------------------------
    # --- Internal Helper Methods ---
    # --------------------------------------------------------------------------

    def _get_encryption_key(self) -> tuple[str, int]:
        """Fetches the public RSA key and timestamp for password encryption."""
        url = f"{self.base_url}/session/encryptionKey"
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        return data["encryptionKey"], data["timeStamp"]

    def _encrypt_password(self, public_key_str: str, timestamp: int) -> str:
        """Encrypts the password using the provided public key."""
        message = f"{self._password}|{timestamp}".encode("utf-8")
        encoded_message = b64encode(message)
        pem_key = f"-----BEGIN PUBLIC KEY-----\n{public_key_str}\n-----END PUBLIC KEY-----".encode(
            "utf-8"
        )
        public_key = serialization.load_pem_public_key(
            pem_key, backend=default_backend()
        )
        ciphertext = public_key.encrypt(encoded_message, padding.PKCS1v15())
        return b64encode(ciphertext).decode("utf-8")

    def _create_session(self, use_encryption: bool = True):
        """Creates a new trading session, stores tokens, and clears the password."""
        url = f"{self.base_url}/session"
        if use_encryption:
            logger.info("Attempting to create session with encrypted password.")
            try:
                if self._password is None:
                    raise ValueError(
                        "Password is not available for re-authentication. Please create a new client instance."
                    )
                key, ts = self._get_encryption_key()
                encrypted_pass = self._encrypt_password(key, ts)
                payload = {
                    "identifier": self._identifier,
                    "password": encrypted_pass,
                    "encryptedPassword": True,
                }
            except Exception as e:
                logger.error(
                    f"Password encryption failed, falling back to plain text. Error: {e}"
                )
                payload = {
                    "identifier": self._identifier,
                    "password": self._password,
                    "encryptedPassword": False,
                }
        else:
            logger.info("Creating session with plain text password.")
            payload = {
                "identifier": self._identifier,
                "password": self._password,
                "encryptedPassword": False,
            }

        response = self.session.post(url, json=payload)
        response.raise_for_status()
        self.cst = response.headers.get("CST")
        self.security_token = response.headers.get("X-SECURITY-TOKEN")
        if not self.cst or not self.security_token:
            raise Exception(
                "Failed to retrieve authentication tokens from session response."
            )
        self.session.headers.update(
            {"CST": self.cst, "X-SECURITY-TOKEN": self.security_token}
        )
        self._password = None
        logger.success("Session created successfully and password cleared from memory.")

    def _request(
        self, method: str, endpoint: str, auto_renew_session: bool = True, **kwargs
    ) -> Any:
        """A generic wrapper for making authenticated requests."""
        url = f"{self.base_url}/{endpoint}"
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401 and auto_renew_session:
                logger.warning(
                    "Session expired or invalid. Attempting to re-authenticate..."
                )
                self._create_session()
                response = self.session.request(method, url, **kwargs)
                response.raise_for_status()
                return response.json()
            else:
                logger.error(
                    f"HTTP Error on {method} {url}: {e.response.status_code} - {e.response.text}"
                )
                raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during request to {url}: {e}")
            raise

    # --------------------------------------------------------------------------
    # --- Session and Account Endpoints ---
    # --------------------------------------------------------------------------

    def ping(self) -> bool:
        """
        Checks if the current session is active by pinging the server.

        Returns:
            bool: True if the session is active, False otherwise.
        """
        try:
            response = self._request("GET", "ping")
            return response.get("status") == "OK"
        except Exception:
            return False

    def get_session_details(self) -> SessionDetails:
        """
        Retrieves details of the current session, including account and client IDs.

        Returns:
            SessionDetails: A Pydantic model with session information.
        """
        data = self._request("GET", "session")
        return SessionDetails(**data)

    def switch_active_account(self, account_id: str) -> Dict[str, Any]:
        """
        Switches the active trading account for the current session.

        Args:
            account_id (str): The ID of the account to switch to.

        Returns:
            Dict[str, Any]: The raw JSON response from the server.
        """
        payload = {"accountId": account_id}
        response_json = self._request("PUT", "session", json=payload)
        logger.success(f"Active account successfully switched to: {account_id}")
        return response_json

    def close_session(self):
        """
        Logs out of the current session, invalidating the session tokens.
        """
        logger.info("Closing session...")
        try:
            self._request("DELETE", "session", auto_renew_session=False)
            self.cst = None
            self.security_token = None
            self.session.headers.pop("CST", None)
            self.session.headers.pop("X-SECURITY-TOKEN", None)
            logger.success("Session closed and client tokens cleared.")
        except Exception as e:
            logger.error(f"Failed to close session cleanly: {e}")

    # --------------------------------------------------------------------------
    # --- Market and Instrument Endpoints ---
    # --------------------------------------------------------------------------

    def get_market_categories(self) -> MarketNavigationResponse:
        """
        Retrieves the top-level market navigation categories.

        Returns:
            MarketNavigationResponse: A Pydantic model with a list of market nodes.
        """
        logger.info("Fetching market categories...")
        data = self._request("GET", "marketnavigation")
        return MarketNavigationResponse(**data)

    def get_markets_by_category(self, node_id: str) -> Dict[str, Any]:
        """
        Retrieves all sub-nodes and markets for a given category node ID.

        Args:
            node_id (str): The ID of the market category node.

        Returns:
            Dict[str, Any]: The raw JSON response containing sub-nodes and markets.
        """
        logger.info(f"Fetching instruments from category '{node_id}'...")
        return self._request("GET", f"marketnavigation/{node_id}")

    def search_markets(self, search_term: str) -> SearchMarketsResponse:
        """
        Searches for markets by a term. Returns a list of flat market summaries.

        Args:
            search_term (str): The term to search for (e.g., 'Gold', 'Tesla').

        Returns:
            SearchMarketsResponse: A Pydantic model with a list of flat MarketSummary objects.
        """
        logger.info(f"Searching for markets with term: '{search_term}'...")
        data = self._request("GET", "markets", params={"searchTerm": search_term})
        return SearchMarketsResponse(**data)

    def get_markets_by_epics(self, epics: List[str]) -> GetMarketsByEpicsResponse:
        """
        Fetches detailed market data for a list of epics in a single bulk request.

        Args:
            epics (List[str]): A list of epic identifiers (max 50).

        Returns:
            GetMarketsByEpicsResponse: A Pydantic model with a list of nested FullMarketDetails objects.
        """
        if not 1 <= len(epics) <= 50:
            raise ValueError("The number of epics must be between 1 and 50.")
        logger.info(f"Fetching market details for {len(epics)} epics in bulk...")
        data = self._request("GET", "markets", params={"epics": ",".join(epics)})
        return GetMarketsByEpicsResponse(**data)

    def get_full_market_details(self, epic: str) -> FullMarketDetails:
        """
        Retrieves detailed (nested) information for a single market.

        Args:
            epic (str): The epic identifier of the instrument.

        Returns:
            FullMarketDetails: A Pydantic model with complete instrument details.
        """
        logger.info(f"Fetching full market details for epic: {epic}")
        data = self._request("GET", f"markets/{epic}")
        return FullMarketDetails(**data)

    def get_historical_prices(
        self, epic: str, resolution: str, max_items: int
    ) -> pd.DataFrame:
        """
        Retrieves historical price data for a specific instrument.

        Args:
            epic (str): The epic identifier of the instrument.
            resolution (str): The candle resolution (e.g., 'HOUR', 'DAY').
            max_items (int): The maximum number of candles to return.

        Returns:
            pd.DataFrame: A DataFrame with OHLCV data, indexed by timestamp.
        """
        params = {"resolution": resolution, "max": max_items}
        data = self._request("GET", f"prices/{epic}", params=params)
        if not data.get("prices"):
            return pd.DataFrame()

        processed = [
            {
                "timestamp": p["snapshotTimeUTC"],
                "open": p["openPrice"]["bid"],
                "high": p["highPrice"]["bid"],
                "low": p["lowPrice"]["bid"],
                "close": p["closePrice"]["bid"],
                "volume": p["lastTradedVolume"],
            }
            for p in data["prices"]
            if p.get("openPrice") and p.get("openPrice").get("bid")
        ]

        df = pd.DataFrame(processed)
        if df.empty:
            return df
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df.set_index("timestamp", inplace=True)
        return df

    # --------------------------------------------------------------------------
    # --- Positions and Orders Endpoints ---
    # --------------------------------------------------------------------------

    def get_open_positions(self) -> Dict[str, Any]:
        """
        Retrieves all open positions for the active account.

        Returns:
            Dict[str, Any]: The raw JSON response from the server.
        """
        return self._request("GET", "positions")

    # --------------------------------------------------------------------------
    # --- Watchlist Endpoints ---
    # --------------------------------------------------------------------------

    def get_watchlists(self) -> GetWatchlistsResponse:
        """
        Retrieves all watchlists for the current user.

        Returns:
            GetWatchlistsResponse: A Pydantic model with a list of watchlists.
        """
        logger.info("Fetching all watchlists...")
        data = self._request("GET", "watchlists")
        return GetWatchlistsResponse(**data)

    def create_watchlist(
        self, name: str, epics: List[str] = None
    ) -> CreateWatchlistResponse:
        """
        Creates a new watchlist, optionally populating it with epics.

        Args:
            name (str): The name for the new watchlist (max 20 chars).
            epics (List[str], optional): A list of epics to add initially.

        Returns:
            CreateWatchlistResponse: A Pydantic model with the new watchlist ID.
        """
        logger.info(f"Creating new watchlist with name: '{name}'...")
        payload = {"name": name}
        if epics:
            payload["epics"] = epics
        data = self._request("POST", "watchlists", json=payload)
        return CreateWatchlistResponse(**data)

    def get_watchlist_details(self, watchlist_id: str) -> GetWatchlistDetailsResponse:
        """
        Retrieves the contents (list of markets) for a specific watchlist.

        Args:
            watchlist_id (str): The ID of the watchlist to fetch.

        Returns:
            GetWatchlistDetailsResponse: A Pydantic model with a list of markets.
        """
        logger.info(f"Fetching details for watchlist ID: {watchlist_id}...")
        data = self._request("GET", f"watchlists/{watchlist_id}")
        return GetWatchlistDetailsResponse(**data)

    def add_to_watchlist(self, watchlist_id: str, epic: str) -> StatusResponse:
        """
        Adds a single instrument (epic) to an existing watchlist.

        Args:
            watchlist_id (str): The ID of the target watchlist.
            epic (str): The epic of the instrument to add.

        Returns:
            StatusResponse: A Pydantic model indicating success or failure.
        """
        logger.info(f"Adding epic '{epic}' to watchlist '{watchlist_id}'...")
        payload = {"epic": epic}
        data = self._request("PUT", f"watchlists/{watchlist_id}", json=payload)
        return StatusResponse(**data)

    def remove_from_watchlist(self, watchlist_id: str, epic: str) -> StatusResponse:
        """
        Removes a single instrument (epic) from a watchlist.

        Args:
            watchlist_id (str): The ID of the target watchlist.
            epic (str): The epic of the instrument to remove.

        Returns:
            StatusResponse: A Pydantic model indicating success or failure.
        """
        logger.info(f"Removing epic '{epic}' from watchlist '{watchlist_id}'...")
        data = self._request("DELETE", f"watchlists/{watchlist_id}/{epic}")
        return StatusResponse(**data)

    def delete_watchlist(self, watchlist_id: str) -> StatusResponse:
        """
        Deletes an entire watchlist.

        Args:
            watchlist_id (str): The ID of the watchlist to delete.

        Returns:
            StatusResponse: A Pydantic model indicating success or failure.
        """
        logger.warning(f"Deleting entire watchlist with ID: '{watchlist_id}'...")
        data = self._request("DELETE", f"watchlists/{watchlist_id}")
        return StatusResponse(**data)
