# Bacon Egg and Cheese

![BEC email investigation](docs/assets/BEC-Banner.gif)

BEC is a command-line tool for investigating business email compromise. For Microsoft 365, an analyst uses their own authorized Exchange Online PowerShell session to read sent and received message traces for named accounts. The live adapter does not collect mailbox audit events or current inbox rules. Python builds a local timeline and links findings to the saved evidence. BEC can also analyze existing Microsoft, Defender email and Google Workspace exports.

## First investigation on Windows

1. On the **main** branch of the [BEC repository](https://github.com/PendingUpdates/BEC), select **Code → Download ZIP**. In File Explorer, right-click the ZIP, choose **Extract All** and open the extracted folder containing `pyproject.toml` and `Invoke-BEC.ps1`.
2. Open PowerShell in that folder. For ExchangeOnlineManagement **3.10 or later**, use **PowerShell 7.6 or later**. Module versions **3.7.0 through 3.9.2** support **PowerShell 7.4 or later**. Check `py -3 --version` for **Python 3.12 or later**, then install the base package. [Platform setup and package contents](docs/prerequisites.md#windows)

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install .
   ```

3. In that same PowerShell window, sign in **as yourself** using your organization's already approved Exchange Online PowerShell access. If you already have a single direct connection to the customer, use it. BEC uses that session without registering an application or changing the tenant. If Microsoft asks for new consent, stop. [Microsoft sign-in and supported session types](docs/security.md#investigator-sign-in)

   ```powershell
   Connect-ExchangeOnline
   ```

4. Run the launcher in the connected window.

   ```powershell
   .\Invoke-BEC.ps1
   ```

   Check the displayed operator and tenant GUID, then enter the affected primary email addresses and choose a time window. Type **yes** to collect or **q** to cancel. [Window choices and retention](docs/investigations.md#investigate-microsoft-365-in-powershell)

BEC prints a local report path per account. Cases default to `BEC-Cases` in your user folder.

[Windows](docs/prerequisites.md#windows) · [macOS](docs/prerequisites.md#macos) · [Ubuntu](docs/prerequisites.md#ubuntu) · [Operator guide and custom windows](docs/investigations.md) · [Offline export fallback](docs/investigations.md#work-with-an-existing-export) · [MIT License](LICENSE)
