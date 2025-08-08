# src/capitalcom_bot/client_factory.py

from contextlib import contextmanager
from typing import Generator

from .api_client import CapitalComAPIClient
from .config import load_api_credentials


@contextmanager
def get_client(demo_mode: bool = True) -> Generator[CapitalComAPIClient, None, None]:
    """
    A secure context manager for creating and automatically closing an ApiClient session.

    This factory function is the recommended way to interact with the API in scripts
    and notebooks. It handles loading credentials and ensures that the API session
    is properly closed upon exiting the 'with' block, even if errors occur.

    Args:
        demo_mode (bool): If True, connects to the demo environment. Defaults to True.

    Yields:
        CapitalComAPIClient: An initialized and authenticated API client instance,
                            ready for use within the 'with' block.
    """
    client = None
    try:
        # Credentials are loaded securely inside the context, minimizing their scope.
        api_creds = load_api_credentials()

        client = CapitalComAPIClient(
            identifier=api_creds.identifier,
            password=api_creds.password,
            api_key=api_creds.api_key,
            demo_mode=demo_mode,
        )

        # Yield the client to the 'with' block for use.
        yield client

    finally:
        # This cleanup code is guaranteed to run, ensuring the session is always closed.
        if client:
            client.close_session()
