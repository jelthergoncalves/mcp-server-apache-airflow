"""Tests for the MWAA authentication module."""

import time
from unittest.mock import MagicMock, patch

import pytest
from airflow_client.client import ApiClient

from src.airflow.mwaa import MWAAApiClient, MWAATokenManager


def _mock_login_response(session_token="session-abc123"):
    """Create a mock requests.post response with a session cookie."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.cookies = {"session": session_token}
    return mock_response


def _mock_boto3_client(token="test-token", hostname="my-env.abc123.us-east-1.airflow.amazonaws.com"):
    """Set up a mock boto3 MWAA client."""
    mock_client = MagicMock()
    mock_client.create_web_login_token.return_value = {
        "WebToken": token,
        "WebServerHostname": hostname,
    }
    return mock_client


class TestMWAATokenManager:
    """Test cases for MWAATokenManager."""

    @patch("src.airflow.mwaa.requests.post", return_value=_mock_login_response())
    @patch("src.airflow.mwaa.boto3")
    def test_get_token_fetches_on_first_call(self, mock_boto3, mock_post):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client()

        manager = MWAATokenManager("my-env")
        token = manager.get_token()

        assert token == "session-abc123"
        mock_post.assert_called_once()

    @patch("src.airflow.mwaa.requests.post", return_value=_mock_login_response())
    @patch("src.airflow.mwaa.boto3")
    def test_get_token_returns_cached_token(self, mock_boto3, mock_post):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client()

        manager = MWAATokenManager("my-env")
        token1 = manager.get_token()
        token2 = manager.get_token()

        assert token1 == token2
        # Only one login request should be made
        assert mock_post.call_count == 1

    @patch("src.airflow.mwaa.requests.post")
    @patch("src.airflow.mwaa.boto3")
    def test_get_token_refreshes_when_expired(self, mock_boto3, mock_post):
        mock_post.side_effect = [
            _mock_login_response("session-1"),
            _mock_login_response("session-2"),
        ]
        mock_mwaa = _mock_boto3_client()
        mock_mwaa.create_web_login_token.side_effect = [
            {"WebToken": "token-1", "WebServerHostname": "host.example.com"},
            {"WebToken": "token-2", "WebServerHostname": "host.example.com"},
        ]
        mock_boto3.Session.return_value.client.return_value = mock_mwaa

        manager = MWAATokenManager("my-env")
        assert manager.get_token() == "session-1"

        # Force expiry
        manager._session_expiry = time.time() - 1
        assert manager.get_token() == "session-2"
        assert mock_post.call_count == 2

    @patch("src.airflow.mwaa.requests.post", return_value=_mock_login_response())
    @patch("src.airflow.mwaa.boto3")
    def test_airflow_host_derived_with_https_prefix(self, mock_boto3, mock_post):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client(
            hostname="my-env.abc123.us-east-1.airflow.amazonaws.com"
        )

        manager = MWAATokenManager("my-env")
        assert manager.airflow_host == "https://my-env.abc123.us-east-1.airflow.amazonaws.com"

    @patch("src.airflow.mwaa.requests.post", return_value=_mock_login_response())
    @patch("src.airflow.mwaa.boto3")
    def test_airflow_host_preserves_existing_https(self, mock_boto3, mock_post):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client(
            hostname="https://my-env.abc123.us-east-1.airflow.amazonaws.com"
        )

        manager = MWAATokenManager("my-env")
        assert manager.airflow_host == "https://my-env.abc123.us-east-1.airflow.amazonaws.com"

    @patch("src.airflow.mwaa.requests.post", return_value=_mock_login_response())
    @patch("src.airflow.mwaa.boto3")
    def test_login_url_constructed_correctly(self, mock_boto3, mock_post):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client(
            hostname="my-env.abc123.us-east-1.airflow.amazonaws.com"
        )

        manager = MWAATokenManager("my-env")
        manager.get_token()

        mock_post.assert_called_once_with(
            "https://my-env.abc123.us-east-1.airflow.amazonaws.com/aws_mwaa/login",
            data={"token": "test-token"},
            timeout=10,
        )

    @patch("src.airflow.mwaa.boto3")
    def test_region_and_profile_passed_to_session(self, mock_boto3):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client()

        MWAATokenManager("my-env", region="eu-west-1", profile="my-profile")

        mock_boto3.Session.assert_called_once_with(region_name="eu-west-1", profile_name="my-profile")

    @patch("src.airflow.mwaa.boto3")
    def test_no_region_or_profile_uses_defaults(self, mock_boto3):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client()

        MWAATokenManager("my-env")

        mock_boto3.Session.assert_called_once_with()

    def test_missing_boto3_raises_import_error(self):
        with patch("src.airflow.mwaa.boto3", None):
            with pytest.raises(ImportError, match="boto3 is required for MWAA authentication"):
                MWAATokenManager("my-env")

    @patch("src.airflow.mwaa.requests.post")
    @patch("src.airflow.mwaa.boto3")
    def test_login_failure_raises_error(self, mock_boto3, mock_post):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client()
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_post.return_value = mock_response

        manager = MWAATokenManager("my-env")
        with pytest.raises(RuntimeError, match="MWAA login failed with status 403"):
            manager.get_token()


class TestMWAAApiClient:
    """Test cases for MWAAApiClient."""

    @patch("src.airflow.mwaa.requests.post", return_value=_mock_login_response("fresh-session"))
    @patch("src.airflow.mwaa.boto3")
    def test_call_api_sets_session_cookie(self, mock_boto3, mock_post):
        mock_boto3.Session.return_value.client.return_value = _mock_boto3_client()

        from airflow_client.client import Configuration

        config = Configuration(host="https://host.example.com/api/v1")
        token_manager = MWAATokenManager("my-env")
        client = MWAAApiClient(config, token_manager)

        with patch.object(ApiClient, "call_api", return_value=None) as mock_call:
            client.call_api("/test", "GET")
            assert client.default_headers["Cookie"] == "session=fresh-session"
            mock_call.assert_called_once()

    @patch("src.airflow.mwaa.requests.post")
    @patch("src.airflow.mwaa.boto3")
    def test_call_api_refreshes_expired_session(self, mock_boto3, mock_post):
        mock_post.side_effect = [
            _mock_login_response("session-1"),
            _mock_login_response("session-2"),
        ]
        mock_mwaa = _mock_boto3_client()
        mock_mwaa.create_web_login_token.side_effect = [
            {"WebToken": "token-1", "WebServerHostname": "host.example.com"},
            {"WebToken": "token-2", "WebServerHostname": "host.example.com"},
        ]
        mock_boto3.Session.return_value.client.return_value = mock_mwaa

        from airflow_client.client import Configuration

        config = Configuration(host="https://host.example.com/api/v1")
        token_manager = MWAATokenManager("my-env")
        client = MWAAApiClient(config, token_manager)

        with patch.object(ApiClient, "call_api", return_value=None):
            client.call_api("/test", "GET")
            assert client.default_headers["Cookie"] == "session=session-1"

            # Force expiry
            token_manager._session_expiry = time.time() - 1
            client.call_api("/test", "GET")
            assert client.default_headers["Cookie"] == "session=session-2"
