# Access and case evidence

## Investigator sign-in

Use your own user identity and the customer's already approved **Exchange Online PowerShell** access. Use a supported PowerShell and ExchangeOnlineManagement version pair from the [platform setup](prerequisites.md#windows). In `Connect-ExchangeOnline -UserPrincipalName $YourCustomerSignIn`, set `$YourCustomerSignIn` to your own approved sign-in address. Microsoft handles authentication and MFA outside BEC. If the native client is blocked, prompts for new consent, or lacks a role, stop or use existing exports. BEC needs no registered application, client ID, application secret or token. [Microsoft connection guide](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps)

Supply the expected **tenant GUID from the incident record**. The adapter needs exactly one active, unprefixed, direct Exchange user session in the current PowerShell instance. It compares the tenant GUID, checks the signed-in account and connection ID, and uses only cmdlets exported by that connection's module. It checks the exact primary SMTP address with `Get-Mailbox` before incident reads. An unverifiable mailbox or session stops collection. `-DelegatedOrganization` is a Microsoft CSP facility for existing customer delegation. This adapter declines those sessions, app-only sessions, Security & Compliance sessions and ambiguous connections. A guest's sign-in suffix cannot establish the customer. [Session metadata](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-connectioninformation?view=exchange-ps) · [Microsoft connection guide](https://learn.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps)

## Microsoft sources and limits

| Source | What BEC reads and reports |
| --- | --- |
| Exchange message trace | One `Get-MessageTraceV2` read by sender and one by recipient, each for the exact account and UTC window. BEC requests up to 1,000 rows per direction and flags a full result. The service offers up to 90 days of history, 10 days per query and 5,000 rows per request. High-recipient messages can need an explicit trace ID. |
| Purview unified audit | Mailbox audit is not collected by the live adapter. The audit service's user filter identifies an actor and cannot establish which mailbox the actor accessed. Use a separately authorized offline case for mailbox-targeted audit exports. |
| Current mailbox rules | The adapter does not implement current inbox-rule inventory and records a coverage gap. Historical rule operations may appear in separately obtained offline audit evidence. Existing mailbox snapshots remain available offline. Microsoft excludes Global Reader and View-Only Organization Management from `Get-InboxRule`. |
| Entra sign-ins, directory activity and Defender email | Separate sources. Supply appropriately authorized exports for local analysis. The Exchange session provides no evidence of these workloads' coverage. |

[Message trace limits](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2?view=exchange-ps) · [Microsoft mailbox audit scope](https://learn.microsoft.com/en-us/purview/audit-troubleshooting-scenarios#search-for-mailbox-activities-performed-in-a-specific-mailbox-including-shared-mailboxes) · [Inbox rule role limits](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-inboxrule?view=exchange-ps)

## Local evidence

Choose a protected local drive with appropriate OS access controls and encryption. BEC writes one export directory per mailbox, its capture receipt, preserved JSON, SHA-256 manifest and reports. The original evidence here is the first local JSON serialization of PowerShell's returned objects. It does not claim to preserve the service's HTTP response bytes. A hash protects evidence relative to the recorded manifest. Retain a separately protected copy for independent custody.

The three Microsoft cmdlets are `Get-ConnectionInformation`, `Get-Mailbox` and `Get-MessageTraceV2`. Each complete page must match the account in the requested direction and the UTC interval before any trace bytes are written. Receipt import checks those same bytes again. The adapter uses a fixed read list. It never opens a browser, requests consent, changes a rule or permission, creates a tenant search job, or retrieves a session token. Reports can contain sensitive mailbox metadata and link to preserved evidence. [Offline import and report files](investigations.md#work-with-an-existing-export) · [Workspace access](workspace.md)
