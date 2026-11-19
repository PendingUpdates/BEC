"""Compatibility entry point for the retired Microsoft application sign-in."""
from .storage import CaseError


def sign_in(client_id=None, directory_id=None):
    raise CaseError("Use Invoke-BEC.ps1 in the analyst's existing Exchange Online PowerShell session.")
