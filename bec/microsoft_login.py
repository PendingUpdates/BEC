"""Interactive Microsoft public-cloud sign-in for account-scoped investigations."""
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field

from .graph import PERMISSIONS, ROOT, SourceError
from .storage import CaseError

AUTHORITY = "https://login.microsoftonline.com/"
READ_SCOPES = sorted({"AuditLog.Read.All", *PERMISSIONS.values()})


def guid(value, label):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise CaseError(f"Microsoft {label} must be a valid GUID.") from exc


@dataclass
class InvestigatorSession:
    directory_id: str
    client_id: str
    app: object = field(repr=False)
    account: dict = field(repr=False)
    scopes: list = field(repr=False)

    def access_token(self):
        try:
            result = self.app.acquire_token_silent(self.scopes, account=self.account)
        except Exception as exc:
            raise SourceError("Microsoft could not refresh this sign-in. Resume the case to sign in again.") from exc
        if not result or not result.get("access_token"):
            raise SourceError("Microsoft sign-in expired or requires interaction. Resume the case to sign in again.")
        return result["access_token"]


@contextmanager
def sign_in(client_id=None, directory_id=None):
    client_id = client_id or os.environ.get("BEC_MICROSOFT_CLIENT_ID")
    if not client_id:
        raise CaseError("Microsoft sign-in has not been set up on this workstation. Ask your administrator "
                        "to deploy the BEC public client ID (BEC_MICROSOFT_CLIENT_ID). See docs/security.md.")
    client_id = guid(client_id, "BEC_MICROSOFT_CLIENT_ID")
    directory_id = directory_id or os.environ.get("BEC_MICROSOFT_TENANT_ID")
    if directory_id:
        directory_id = guid(directory_id, "tenant")
    try:
        import msal
        import requests
    except ImportError as exc:
        raise CaseError("Install BEC with the live extra in this environment to use Microsoft sign-in.") from exc

    # Each invocation gets a new in-memory account and token cache, including on resume.
    cache = msal.TokenCache()
    with requests.Session() as http:
        def client(tenant):
            return msal.PublicClientApplication(client_id, authority=AUTHORITY + tenant,
                                                token_cache=cache, http_client=http)

        print("Sign in to Microsoft in your browser with your investigation account.", flush=True)
        try:
            app = client(directory_id or "organizations")
            result = app.acquire_token_interactive([ROOT + "/.default"], prompt="select_account", timeout=300)
        except Exception as exc:
            raise CaseError("Microsoft sign-in could not finish. Check browser access and the BEC app setup.") from exc
        if not result or not result.get("access_token"):
            raise CaseError("Microsoft sign-in did not complete. Check the sign-in window and your approved access.")
        # MSAL validates the sign-in response. Bind to its ID-token claims; Graph access tokens are opaque.
        claims = result.get("id_token_claims") or {}
        tenant = guid(claims.get("tid"), "tenant")
        if claims.get("aud", "").lower() != client_id or (directory_id and tenant != directory_id):
            raise CaseError("Microsoft sign-in returned a different application or tenant.")
        granted = {scope.removeprefix(ROOT + "/").casefold() for scope in result.get("scope", "").split()}
        scopes = [ROOT + "/" + s for s in READ_SCOPES if s.casefold() in granted]
        if not scopes:
            raise CaseError("This sign-in has none of BEC's delegated Graph read permissions. "
                            "Ask the BEC application administrator to check existing consent.")
        try:
            # Refresh against this specific issuer, even when sign-in began at /organizations.
            bound = app if directory_id else client(tenant)
            accounts = bound.get_accounts()
        except Exception as exc:
            raise CaseError("Microsoft could not establish a tenant-bound investigator session.") from exc
        if len(accounts) != 1:
            raise CaseError("Microsoft could not identify a single signed-in investigator for this tenant.")
        yield InvestigatorSession(tenant, client_id, bound, accounts[0], scopes)
