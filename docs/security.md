# Security and permissions

Google Workspace collection uses a delegated service account with the Admin SDK Reports audit read-only scope. For Workspace-only and mixed-provider cases, follow the [Workspace setup guide](workspace.md).

## Investigator sign-in

The administrator who manages BEC confirms the existing Microsoft Entra public-client registration, its **Mobile and desktop applications** platform and its `http://localhost` redirect URI. The investigator signs in with a work or school account through the organization’s usual Microsoft sign-in and MFA. [Microsoft desktop app registration](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-app-registration)

### Workstation settings

| Setting | Approved value to deploy |
| --- | --- |
| `BEC_MICROSOFT_CLIENT_ID` | The application (client) ID of the organization's approved BEC desktop app. Required for investigator sign-in. |
| `BEC_MICROSOFT_TENANT_ID` | The directory (tenant) ID for a single-tenant app. A multitenant registration can discover the issuing directory at sign-in. |
| `BEC_CASES` | Optional directory for case evidence. The investigator command defaults to `BEC-Cases` in the user's home directory. |

An investigator can check whether the app ID is present in the current PowerShell session with `Test-Path Env:\BEC_MICROSOFT_CLIENT_ID`. For a single-tenant app also check `Test-Path Env:\BEC_MICROSOFT_TENANT_ID`. These checks report variable presence. The administrator confirms the values and existing workload approvals. **Stop before sign-in if the approved setup is missing.**

### Delegated Microsoft Graph permissions

The following read permissions apply to the **delegated** desktop app. Microsoft evaluates the signed-in investigator's workload access as well as the app's consent. Check the existing approval for the workloads in scope.

| Incident source | Delegated permission | What BEC requests |
| --- | --- | --- |
| Entra sign-ins and directory audits | `AuditLog.Read.All` | Sign-ins for the named account and directory audit entries it initiated. [Sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0), [directory audits](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0) |
| Purview Exchange audit | `AuditLogsQuery-Exchange.Read.All` | An Exchange audit search filtered to that account and the case window. [Purview audit searches](https://learn.microsoft.com/en-us/graph/api/security-auditcoreroot-post-auditlogqueries?view=graph-rest-1.0) |
| Exchange message trace | `ExchangeMessageTrace.Read.All` | Separate sender and recipient searches for the account. The tenant needs Microsoft's trace onboarding. [Message trace](https://learn.microsoft.com/en-us/graph/api/messagetracingroot-list-messagetraces?view=graph-rest-1.0) |
| Defender XDR email evidence | `ThreatHunting.Read.All` | Read-only hunting queries for the account and associated message IDs. Data depends on Defender deployment and coverage. [Advanced Hunting](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0) |

BEC requests the dedicated application's configured Graph permissions at sign-in. Its in-memory token cache binds collection to the issuing tenant and application. The case records both public identifiers for resume. Denied or unavailable sources are reported as telemetry gaps. [Microsoft Graph delegated access](https://learn.microsoft.com/en-us/graph/auth/auth-concepts#delegated-access-access-on-behalf-of-a-user), [Microsoft identity platform scope behavior](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc#the-default-scope)

## Unattended application access

Create a single-tenant application for the intended directory in Microsoft's public cloud. Assign the following **application** permissions in Microsoft Graph and grant administrator consent. A directory GUID and a client GUID bind the case to that application's tenant-specific authentication endpoint.

| Collector | Application permission | Scope used by BEC |
| --- | --- | --- |
| Entra interactive, non-interactive, service principal and directory audits | `AuditLog.Read.All` | Sign-ins by user, IP or consented service principal. Directory changes by initiating UPN or a discovered target user object ID |
| Purview Unified Audit Log | `AuditLogsQuery-Exchange.Read.All` | Exchange audit search filtered by user or IP, covering mailbox item, aggregated item, admin and search records |
| Exchange message trace | `ExchangeMessageTrace.Read.All` | Separate time-bounded searches for the sender and recipient |
| Defender XDR Advanced Hunting | `ThreatHunting.Read.All` | Account-scoped email, URL, attachment, click, post-delivery and alert evidence |

Microsoft documents the permissions and availability of each workload. Non-interactive and service principal sign-ins use Graph beta, whose contract can change. Session identifiers and optional fields may be absent. [Entra sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) · [Beta sign-in filters](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta) · [Directory audit properties](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0)

The UAL collector creates a search, polls the search ID and retrieves its records. BEC records the search ID locally to resume outstanding searches. Tenant audit settings, licensing, and retention determine which activities are available. [Purview audit search](https://learn.microsoft.com/en-us/graph/api/security-auditcoreroot-post-auditlogqueries?view=graph-rest-1.0) · [Audit records](https://learn.microsoft.com/en-us/graph/api/security-auditlogquery-list-records?view=graph-rest-1.0)

For Defender, grant administrator consent to the Microsoft Graph **application** permission `ThreatHunting.Read.All`. BEC submits read-only KQL using `POST /v1.0/security/runHuntingQuery`. Defender for Office 365 deployment, Safe Links coverage, incident dates and tenant retention affect which tables have data. Check a known network message ID in Defender Advanced Hunting when validating the first live case. Each query records its table, requested account, time range, status and returned row count. [Graph hunting API](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0) · [Defender email URLs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailurlinfo-table) · [Safe Links events](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table) · [XDR alert evidence](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table)

Message trace requires the Exchange message trace service principal to be provisioned in the tenant. An administrator completes Microsoft's onboarding once. BEC splits long windows into at most nine-day intervals. Microsoft limits historical availability to 90 days. [Exchange onboarding and limits](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/graph-api-message-trace)

Conditional Access policy details can be omitted from sign-in responses without additional policy-read permission such as `Policy.Read.ConditionalAccess` or `Policy.Read.All`. These are **not part of BEC's baseline permission set**. An empty or partial response is not proof of clean configuration or complete coverage.

## Credentials and case files

The unattended client uses Azure Identity certificate or client-secret authentication. Set `BEC_CERTIFICATE_PATH` to a PEM or PKCS#12 file containing the private key. Use `BEC_CERTIFICATE_PASSWORD` for an encrypted file, or `BEC_CLIENT_SECRET` for secret-based authentication. Certificates take precedence. The SDK acquires and refreshes access tokens. The CLI never needs the affected user's password. [CertificateCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.certificatecredential?view=azure-python) · [ClientSecretCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.clientsecretcredential?view=azure-python)

Use a restricted evidence directory appropriate to the case. The store inherits the operating system's permissions and encryption. Raw audit records, reports, and acquisition logs can contain sensitive user and mailbox metadata. The HTML report embeds the investigation data for offline use. Its evidence hyperlinks resolve within the case directory. CSV exports quote spreadsheet formula prefixes.

The collector accepts pagination links only on the public Graph HTTPS origin and disables redirects. Logs contain query status, workload, retry counts and pivot entities. They omit authentication headers, credential values and HTTP error bodies.

A SHA-256 manifest detects changes to the collected bytes against the recorded hashes. For independent custody, retain a protected copy of the manifest or case snapshot in your evidence system. An administrator with write access to the entire case can change both an artifact and its manifest.

## Coverage checks for a live case

Compare the case counts and times with a known sign-in, Exchange audit event and message trace in the chosen window. Inspect the raw record referenced by each known event. Check the per-query status for both baseline and incident windows and review any partial results before drawing conclusions. Successful empty queries can occur when retention has expired. BEC reports observed time ranges and cannot establish the tenant's actual retention policy from an empty response.
