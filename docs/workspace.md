# Google Workspace audit investigation

BEC collects three account-scoped activity reports from the Google Admin SDK. Use a Workspace-only profile for live Google investigations. Already acquired Google and Microsoft exports can share an offline case with both tenant bindings.

## Configure live access

1. Enable the Admin SDK API in the Google Cloud project for your reporting service account.
2. In the Google Admin console, authorize the service account's numeric OAuth client ID for domain-wide delegation with this single scope: `https://www.googleapis.com/auth/admin.reports.audit.readonly`.
3. Set `google_workspace.admin_email` to an administrator who can read the requested audit logs. Set `google_workspace.customer_id` to the actual Workspace customer ID. Supply the service-account JSON file through the `BEC_GOOGLE_SERVICE_ACCOUNT` environment variable. The tenant profile contains only identifiers. [Google delegation setup](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority) · [Reports API authorization and request fields](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list)

Use the affected user's primary email as the case user. For mixed-provider tenants with different account addresses, use `bec pivot user second-address@example.com --case CASE_ID` to include an additional address. Each query requests a specific account. BEC verifies the native customer ID and application on every Google activity before admitting it to a case.

| BEC dataset | Google application | Important evidence |
| --- | --- | --- |
| `google_login` | `login` | Login successes, failures, challenges, IPs and authentication details |
| `google_oauth` | `token` | Authorizations, revocations, denials, app names, client IDs, scopes and API usage |
| `google_gmail` | `gmail` | Receipt, send, view, application access, forwarding and other Gmail activity codes |

Gmail returns the event name `delivery` for many operations. BEC reads `event_info.mail_event_type` to identify what actually happened. Unknown codes remain visible with their code and original record. Google requires both time bounds for Gmail and limits each requested interval to 30 days. BEC splits longer windows and follows page tokens. Availability depends on edition, reporting privileges, retention and reporting delay. [Login reference](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/login) · [OAuth reference](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/token) · [Gmail reference](https://developers.google.com/workspace/admin/reports/v1/appendix/activity/gmail)

## Interpret a match

A successful login and an OAuth grant can be associated when both report the same user and IP within 30 minutes. For Gmail API use, BEC requires the same user and client ID on the grant and a subsequent OAuth activity tagged as Gmail. For Gmail message access, BEC requires Gmail event type 33 and the actor's reported OAuth client ID. Both grant-to-use rules have a two-hour window and apply only until a recorded revocation. When present, the finding also includes the preceding login. These observations support chronology and client attribution. Assessing who controlled the account requires additional evidence.

Use **Show linked events** on a finding, search for a client ID, or filter the complete timeline to one Workspace dataset. Each reference identifies the evidence file, activity index and child-event index. App names, OAuth scopes, raw Gmail codes and available RFC message IDs travel with the CSV, JSON and HTML timeline.

## Import ALFA or Reports exports

Use the same case tenant alias, Workspace customer ID and, for a Microsoft-bound case, Microsoft directory ID in your bundle manifest. Copy the evidence files alongside it. BEC accepts a Reports API page with an `items` array, a native activity array, or newline-delimited activities such as ALFA's per-log exports. Map the OAuth token export to `google_oauth`. For a missing Gmail export, add a native Reports Gmail export when available. Missing sources appear as coverage gaps. [ALFA acquisition](https://github.com/invictus-ir/ALFA)

```json
{
  "tenant": "CLIENT-A",
  "google_customer_id": "C012example",
  "files": [
    {"dataset": "google_login", "path": "login.json"},
    {"dataset": "google_oauth", "path": "token.json"},
    {"dataset": "google_gmail", "path": "gmail.json"}
  ]
}
```

```powershell
.\.venv\Scripts\bec.exe offline --bundle .\exports\bundle.json --tenant $TenantAlias --google-customer-id $CustomerId --user $AffectedAccount --start $StartUtc --end $EndUtc
```

An export case accepts later bundles. A live case resumes from its per-query checkpoints. A failed source is retried on the next investigation. Choose a new live case for a fresh acquisition when provider logs arrive late.
