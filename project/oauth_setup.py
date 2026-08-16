"""OAuth2 / OpenID Connect (OIDC) client setup for SSO login.

Providers are registered only when their credentials are present in the
environment, so the app runs fine with SSO disabled (no credentials set).

Standards used:
  * OIDC for authentication (Google, Microsoft Entra, Okta)
  * OAuth2 + PKCE for all flows (enforced in auth.py)
  * Account linking by verified email
"""

from __future__ import annotations

import os

from authlib.integrations.flask_client import OAuth

oauth = OAuth()


def _register_providers() -> None:
    google_id = os.getenv("GOOGLE_CLIENT_ID")
    google_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    if google_id and google_secret:
        oauth.register(
            name="google",
            client_id=google_id,
            client_secret=google_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    github_id = os.getenv("GITHUB_CLIENT_ID")
    github_secret = os.getenv("GITHUB_CLIENT_SECRET")
    if github_id and github_secret:
        oauth.register(
            name="github",
            client_id=github_id,
            client_secret=github_secret,
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "read:user user:email"},
        )

    ms_id = os.getenv("MICROSOFT_CLIENT_ID")
    ms_secret = os.getenv("MICROSOFT_CLIENT_SECRET")
    ms_tenant = os.getenv("MICROSOFT_TENANT", "common")
    if ms_id and ms_secret:
        oauth.register(
            name="microsoft",
            client_id=ms_id,
            client_secret=ms_secret,
            server_metadata_url=f"https://login.microsoftonline.com/{ms_tenant}/v2.0/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )

    okta_id = os.getenv("OKTA_CLIENT_ID")
    okta_secret = os.getenv("OKTA_CLIENT_SECRET")
    okta_domain = os.getenv("OKTA_DOMAIN")
    if okta_id and okta_secret and okta_domain:
        oauth.register(
            name="okta",
            client_id=okta_id,
            client_secret=okta_secret,
            server_metadata_url=f"https://{okta_domain}/oauth2/default/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )


def init_oauth(app) -> None:
    oauth.init_app(app)
    _register_providers()
