import os
from urllib.parse import urljoin

from airflow_client.client import ApiClient, Configuration

from src.envs import (
    AIRFLOW_API_VERSION,
    AIRFLOW_HOST,
    AIRFLOW_JWT_TOKEN,
    AIRFLOW_PASSWORD,
    AIRFLOW_USERNAME,
    MWAA_ENV_NAME,
    MWAA_PROFILE,
    MWAA_REGION,
)

# Set up authentication - MWAA > JWT > Basic Auth
if MWAA_ENV_NAME:
    from src.airflow.mwaa import MWAAApiClient, MWAATokenManager

    token_manager = MWAATokenManager(MWAA_ENV_NAME, MWAA_REGION, MWAA_PROFILE)

    # Derive host from MWAA if not explicitly set
    airflow_host = AIRFLOW_HOST
    if not os.getenv("AIRFLOW_HOST"):
        airflow_host = token_manager.airflow_host

    configuration = Configuration(host=urljoin(airflow_host, f"/api/{AIRFLOW_API_VERSION}"))
    api_client = MWAAApiClient(configuration, token_manager)

elif AIRFLOW_JWT_TOKEN:
    configuration = Configuration(host=urljoin(AIRFLOW_HOST, f"/api/{AIRFLOW_API_VERSION}"))
    configuration.api_key = {"Authorization": f"{AIRFLOW_JWT_TOKEN}"}
    configuration.api_key_prefix = {"Authorization": "Bearer"}
    api_client = ApiClient(configuration)

    # JWT/Bearer auth requires manual header setup because auth_settings() in apache-airflow-client 2.x
    # only supports Basic authentication.
    # If ever updated to apache-airflow-client 3.x it's the other way around, JWT/Bearer is natively
    # supported through "access_token", and Basic auth requires manual header.
    api_client.default_headers["Authorization"] = configuration.get_api_key_with_prefix("Authorization")

elif AIRFLOW_USERNAME and AIRFLOW_PASSWORD:
    configuration = Configuration(host=urljoin(AIRFLOW_HOST, f"/api/{AIRFLOW_API_VERSION}"))
    configuration.username = AIRFLOW_USERNAME
    configuration.password = AIRFLOW_PASSWORD
    api_client = ApiClient(configuration)

else:
    configuration = Configuration(host=urljoin(AIRFLOW_HOST, f"/api/{AIRFLOW_API_VERSION}"))
    api_client = ApiClient(configuration)
