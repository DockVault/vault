"""The presets of the "Add provider" wizard: for each identity provider an administrator is likely to have, what
its issuer looks like, the scopes to ask for, the claims its tokens use, the rule that keeps strangers out, and
where in the provider's own console the vault's two addresses go.

A preset only fills the form in: nothing here is enforced, every value can be changed, and a provider saved from
one is an ordinary row. Kept as data so the page, the guide and the tests read the same list.
"""
from __future__ import annotations

from typing import Optional

OTHER = "oidc"

PRESETS = (
    {
        "id": "entra", "name": "Microsoft Entra ID", "icon": "microsoft",
        "issuer_example": "https://login.microsoftonline.com/<tenant id>/v2.0",
        "issuer_help": "Use your tenant's id, never 'common' or 'organizations': the issuer in a token names one "
                       "tenant, and the vault accepts only the one written here.",
        "scopes": "openid profile email",
        "claims": {"tenant": "tid", "groups": "groups"},
        "restriction": "sso_allowed_tenants",
        "restriction_help": "Enter your tenant id under Access, so that only your organisation's accounts sign in.",
        "console": "Entra admin center: App registrations, your app, Authentication. Add the redirect address as "
                   "a Web redirect URI and the logout address as the front-channel or back-channel logout URL. "
                   "For groups, add the groups claim under Token configuration.",
    },
    {
        "id": "google", "name": "Google Workspace", "icon": "google",
        "issuer_example": "https://accounts.google.com",
        "issuer_help": "The issuer is the same for every Google account, so the restriction below is what keeps "
                       "other people's Google accounts out.",
        "scopes": "openid profile email",
        "claims": {"domain": "hd"},
        "restriction": "sso_allowed_domains",
        "restriction_help": "Enter your Workspace domain under Access. Without it any Google account could try.",
        "console": "Google Cloud console: APIs & Services, Credentials, your OAuth client (Web application). Add "
                   "the redirect address under Authorized redirect URIs. Google sends no groups and has no "
                   "back-channel logout.",
    },
    {
        "id": "okta", "name": "Okta", "icon": "okta",
        "issuer_example": "https://<your org>.okta.com",
        "issuer_help": "Your Okta domain, or a custom authorization server's issuer "
                       "(https://<your org>.okta.com/oauth2/default).",
        "scopes": "openid profile email groups",
        "claims": {"groups": "groups"},
        "restriction": "sso_required_groups",
        "restriction_help": "Assign the app in Okta to the people who may sign in; a required group under Access "
                            "narrows it further.",
        "console": "Okta admin console: Applications, your OIDC web app. Add the redirect address under Sign-in "
                   "redirect URIs. For groups, add a groups claim filter to the ID token.",
    },
    {
        "id": "keycloak", "name": "Keycloak", "icon": "keycloak",
        "issuer_example": "https://<host>/realms/<realm>",
        "issuer_help": "The realm's issuer, exactly as its discovery document states it.",
        "scopes": "openid profile email",
        "claims": {"groups": "groups"},
        "restriction": "sso_required_groups",
        "restriction_help": "A realm usually holds only your people; a required group under Access narrows it.",
        "console": "Keycloak admin console: Clients, your client (client authentication on, standard flow). Add "
                   "the redirect address under Valid redirect URIs and the logout address under Backchannel "
                   "logout URL. For groups, add a Group Membership mapper named groups.",
    },
    {
        "id": "authentik", "name": "Authentik", "icon": "authentik",
        "issuer_example": "https://<host>/application/o/<application slug>/",
        "issuer_help": "The provider's OpenID issuer, with the application's slug and the closing slash.",
        "scopes": "openid profile email",
        "claims": {"groups": "groups"},
        "restriction": "sso_required_groups",
        "restriction_help": "Bind the application in Authentik to the people who may use it; a required group "
                            "under Access narrows it further.",
        "console": "Authentik admin interface: Applications, Providers, your OAuth2/OpenID provider "
                   "(confidential client). Add the redirect address under Redirect URIs.",
    },
    {
        "id": OTHER, "name": "Another OpenID Connect provider", "icon": "generic",
        "issuer_example": "https://<your provider's issuer>",
        "issuer_help": "The issuer as the provider's discovery document states it "
                       "(<issuer>/.well-known/openid-configuration).",
        "scopes": "openid profile email",
        "claims": {},
        "restriction": "",
        "restriction_help": "Decide under Access who may sign in: a required group, or invitations only.",
        "console": "Register the vault as a confidential web client with the authorization code flow, and give "
                   "the provider the redirect address.",
    },
)
IDS = tuple(p["id"] for p in PRESETS)


def get(preset_id) -> Optional[dict]:
    """The preset named ``preset_id``, or None."""
    for preset in PRESETS:
        if preset["id"] == preset_id:
            return preset
    return None


def public() -> list:
    """The presets as the wizard is given them (copies: a caller changes nothing here)."""
    return [{**preset, "claims": dict(preset["claims"])} for preset in PRESETS]
