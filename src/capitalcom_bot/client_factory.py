from contextlib import contextmanager

from .api_client import CapitalComAPIClient
from .config import load_api_credentials


@contextmanager
def get_client(demo_mode: bool = True):
    """
    A context manager to safely create and close an ApiClient session.

    This factory function handles loading credentials and ensures that the
    API session is properly closed upon exiting the 'with' block.

    Args:
        demo_mode (bool): If True, connects to the demo environment.
                        Defaults to True.

    Yields:
        CapitalComAPIClient: An initialized and authenticated API client instance.
    """
    client = None
    try:
        # Credentials are loaded inside the context, reducing their scope
        api_creds = load_api_credentials()

        client = CapitalComAPIClient(
            identifier=api_creds.identifier,
            password=api_creds.password,
            api_key=api_creds.api_key,
            demo_mode=demo_mode,
        )

        # Yield the client to the 'with' block
        yield client

    finally:
        # This code is guaranteed to run, even if errors occur inside the 'with' block
        if client:
            client.close_session()
