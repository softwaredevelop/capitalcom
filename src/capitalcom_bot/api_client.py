from base64 import b64encode
from typing import Any, Dict, List, Optional

import pandas as pd
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from loguru import logger
from pydantic import BaseModel, Field

# --- Pydantic Models ---


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
    bid: Optional[float]
    offer: Optional[float]
    update_time: str = Field(alias="updateTime")


class SearchMarketsResponse(BaseModel):
    markets: List[MarketSummary]


# --- API Client Class ---
class CapitalComAPIClient:
    def __init__(
        self, identifier: str, password: str, api_key: str, demo_mode: bool = True
    ):
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

    def _get_encryption_key(self) -> tuple[str, int]:
        """Fetches the public RSA key and timestamp for password encryption."""
        url = f"{self.base_url}/session/encryptionKey"
        response = self.session.get(url)
        response.raise_for_status()
        data = response.json()
        return data["encryptionKey"], data["timeStamp"]

    def _encrypt_password(self, public_key_str: str, timestamp: int) -> str:
        """Encrypts the password using the provided public key, mirroring the Java example."""
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
        """
        Creates a new trading session, stores authentication tokens,
        and clears the password from memory upon success.
        """
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
    ) -> dict:
        """A wrapper for making authenticated requests."""
        url = f"{self.base_url}/{endpoint}"
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401 and auto_renew_session:
                logger.warning("Session expired or invalid. Re-authenticating...")
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

    def ping(self) -> bool:
        """Checks if the current session is active by pinging the server."""
        try:
            response = self._request("GET", "ping")
            return response.get("status") == "OK"
        except Exception:
            return False

    def get_session_details(self) -> SessionDetails:
        """Returns details of the current session (GET /session)."""
        data = self._request("GET", "session")
        return SessionDetails(**data)

    def switch_active_account(self, account_id: str) -> Dict[str, Any]:
        """Switches to another account within the session (PUT /session)."""
        payload = {"accountId": account_id}
        response_json = self._request("PUT", "session", json=payload)
        logger.success(f"Active account successfully switched to: {account_id}")
        return response_json

    def get_market_categories(self) -> MarketNavigationResponse:
        """Returns top-level market categories (GET /marketnavigation)."""
        logger.info("Fetching market categories...")
        data = self._request("GET", "marketnavigation")
        return MarketNavigationResponse(**data)

    def get_markets_by_category(self, node_id: str) -> Dict[str, Any]:
        """Returns all instruments for a given category (node)."""
        logger.info(f"Fetching instruments from category '{node_id}'...")
        return self._request("GET", f"marketnavigation/{node_id}")

    def search_markets(self, search_term: str) -> SearchMarketsResponse:
        """Searches for instruments by a given term (GET /markets)."""
        logger.info(f"Searching for markets with term: '{search_term}'...")
        data = self._request("GET", "markets", params={"searchTerm": search_term})
        return SearchMarketsResponse(**data)

    def get_full_market_details(self, epic: str) -> FullMarketDetails:
        """Returns detailed information for a single market (GET /markets/{epic})."""
        logger.info(f"Fetching full market details for epic: {epic}")
        data = self._request("GET", f"markets/{epic}")
        return FullMarketDetails(**data)

    def get_open_positions(self) -> Dict[str, Any]:
        """Returns all open positions for the active account."""
        return self._request("GET", "positions")

    def get_historical_prices(
        self, epic: str, resolution: str, max_items: int
    ) -> pd.DataFrame:
        """Returns historical price data for a particular instrument."""
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
            if p.get("openPrice") and p["openPrice"].get("bid")
        ]
        df = pd.DataFrame(processed)
        if df.empty:
            return df
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df.set_index("timestamp", inplace=True)
        return df

    def ping_rest_session(self):
        """Pings the server to keep the REST session alive."""
        try:
            self._request("GET", "ping")
            logger.debug("REST session ping successful.")
        except Exception as e:
            logger.warning(f"REST session ping failed: {e}")

    def close_session(self):
        """Logs out of the current session (DELETE /session)."""
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
