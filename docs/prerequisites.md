# Install BEC

Start with the BEC source ZIP. On GitHub select **main → Code → Download ZIP**. Extract it and work in the folder containing `pyproject.toml` and `Invoke-BEC.ps1`. All platforms require Python 3.12 or later. The base installation supports Microsoft operator-session collection, local analysis and reporting. [BEC repository](https://github.com/PendingUpdates/BEC)

## Windows

Choose **Extract All** in File Explorer. Open PowerShell in the extracted project folder. Check `Get-Item .\pyproject.toml` and `py -3 --version`. If the Python launcher is missing or the version is below 3.12, obtain your organization's approved Python installation first. [Python for Windows](https://www.python.org/downloads/windows/)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\bec.exe --version
```

For an Exchange investigation, check the installed versions with `$PSVersionTable.PSVersion` and `Get-Module -ListAvailable ExchangeOnlineManagement | Select-Object Name, Version`. ExchangeOnlineManagement **3.10 or later requires PowerShell 7.6 or later**. Versions **3.7.0 through 3.9.2** support PowerShell 7.4 or later and provide the message trace cmdlet. Use the organization's approved module in the window where you signed in. [Microsoft module requirements](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps) · [Message trace version requirement](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac)

Windows execution-policy acceptance has not been verified for either launch path. The source ZIP launcher (`Invoke-BEC.ps1`) calls the adapter shipped in that ZIP (`bec/data/Invoke-BEC.ps1`). The wheel launch path invokes the installed adapter directly. Use the Python package and adapter from the same version. If Windows policy blocks either script, stop and follow your organization's approved process. [First investigation on Windows](../README.md#first-investigation-on-windows)

## macOS

Extract the ZIP in Finder. Open Terminal in the folder containing `pyproject.toml`. Check `python3 --version` and use an approved Python 3.12 or later. [Python for macOS](https://www.python.org/downloads/macos/)

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/bec --version
```

## Ubuntu

Extract the ZIP and open a terminal in the folder containing `pyproject.toml`. Check `python3 --version`. Use Python 3.12 or later with its matching `venv` support. [Ubuntu Python setup](https://ubuntu.com/developers/docs/howto/python-setup/)

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/bec --version
```

On macOS or Ubuntu, use `.venv/bin/bec` for local analysis. Microsoft collection requires a platform, PowerShell and Exchange module combination supported by your organization and Microsoft. In a supported, already connected PowerShell window, use `./Invoke-BEC.ps1`. [Exchange module requirements](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)

## Launch from the connected session

From an installed source ZIP, run `.\Invoke-BEC.ps1` in the PowerShell window with your direct, interactive Exchange Online connection. The launcher uses the ZIP's `.venv` and co-shipped adapter. With a wheel installed in an activated virtual environment, invoke its adapter in that same window.

```powershell
& (bec microsoft --adapter) -Python (Get-Command python -CommandType Application).Source
```

BEC requires one verified session and displays its tenant GUID and operator. It does not sign in automatically or infer a customer label from an email domain. An optional `-TenantId 'CUSTOMER-TENANT-GUID'` must match the session. Enter the accounts and choose a UTC window, then confirm with **yes**. Confirmation defaults to no and **q** cancels. [Windows first use](../README.md#first-investigation-on-windows) · [Window and retention limits](investigations.md#investigate-microsoft-365-in-powershell)

Live tenant operation remains unverified. Installation and command discovery do not establish that an operator's access, service retention or Windows script policy permits collection.

## What gets installed

| Component | Purpose |
| --- | --- |
| Base `pip install .` | The `bec` Python CLI, local case and report engine, rules, and PowerShell adapter. Windows also installs `tzdata` for time zones. |
| Existing ExchangeOnlineManagement module | Microsoft's sign-in and incident cmdlets in the operator's PowerShell window. Managed separately from pip. |
| Optional `pip install ".[live]"` | Requests and Google Auth for a separately authorized Google Workspace collector. The Microsoft route uses the base package. |

Pip can consult its package index during installation. For an offline install, use a prepared local wheel directory containing the build backend (`setuptools>=69`), its build requirements and the applicable runtime dependencies, for example `python -m pip install . --no-index --find-links "C:\IR\wheelhouse"`. Installed offline commands read local files. [Package metadata](../pyproject.toml) · [Operator guide](investigations.md)
