import logging
import time

import requests
from airflow_client.client import ApiClient

try:
    import boto3
except ImportError:
    boto3 = None

logger = logging.getLogger(__name__)

# Session token is valid for 12h; refresh 30min before expiry
_SESSION_REFRESH_BUFFER_SECONDS = 1800
_SESSION_TOKEN_TTL_SECONDS = 12 * 3600


class MWAATokenManager:
    """Manages session tokens for AWS MWAA.

    The flow is:
    1. Call `create_web_login_token` to get a short-lived web login token (~60s)
    2. Exchange it for a session token via POST to /aws_mwaa/login (valid for 12h)
    3. Use the session token as a cookie or Bearer token for Airflow REST API calls
    """

    def __init__(self, env_name: str, region: str | None = None, profile: str | None = None):
        self._env_name = env_name
        self._region = region
        self._profile = profile
        self._session_token: str | None = None
        self._session_expiry: float = 0
        self._airflow_host: str | None = None
        self._client = self._create_client()

    def _create_client(self):
        if boto3 is None:
            raise ImportError(
                "boto3 is required for MWAA authentication. "
                "Install it with: pip install mcp-server-apache-airflow[mwaa]"
            )

        session_kwargs = {}
        if self._region:
            session_kwargs["region_name"] = self._region
        if self._profile:
            session_kwargs["profile_name"] = self._profile

        session = boto3.Session(**session_kwargs)
        return session.client("mwaa")

    def _refresh_session(self):
        # Step 1: Get a short-lived web login token from MWAA API
        response = self._client.create_web_login_token(Name=self._env_name)
        web_token = response["WebToken"]
        hostname = response.get("WebServerHostname", "")

        if hostname:
            if not hostname.startswith("https://"):
                hostname = f"https://{hostname}"
            self._airflow_host = hostname.rstrip("/")

        # Step 2: Exchange web login token for a session token
        login_url = f"{self._airflow_host}/aws_mwaa/login"
        login_response = requests.post(
            login_url,
            data={"token": web_token},
            timeout=10,
        )

        if login_response.status_code != 200:
            raise RuntimeError(f"MWAA login failed with status {login_response.status_code}: {login_response.text}")

        # Extract session token from cookies
        session_cookie = login_response.cookies.get("session")
        if not session_cookie:
            raise RuntimeError("MWAA login response did not contain a session cookie")

        self._session_token = session_cookie
        self._session_expiry = time.time() + _SESSION_TOKEN_TTL_SECONDS - _SESSION_REFRESH_BUFFER_SECONDS
        logger.info("MWAA session token refreshed successfully")

    def get_token(self) -> str:
        if self._session_token is None or time.time() >= self._session_expiry:
            self._refresh_session()
        return self._session_token

    @property
    def airflow_host(self) -> str | None:
        if self._airflow_host is None:
            self._refresh_session()
        return self._airflow_host


class MWAAApiClient(ApiClient):
    """ApiClient subclass that refreshes MWAA session token before each request."""

    def __init__(self, configuration, token_manager: MWAATokenManager):
        super().__init__(configuration)
        self._token_manager = token_manager

    def call_api(self, *args, **kwargs):
        token = self._token_manager.get_token()
        self.default_headers["Cookie"] = f"session={token}"
        return super().call_api(*args, **kwargs)
