# Install BEC

BEC requires Python 3.12 or newer on Windows, macOS and Ubuntu. From the **main** branch of the BEC repository, choose **Code → Download ZIP**. Each platform section starts with that download. [PendingUpdates/BEC on GitHub](https://github.com/PendingUpdates/BEC)

## Windows

1. In File Explorer, right-click the ZIP, choose **Extract All**, and open the extracted folder that contains `pyproject.toml`. Click the address bar, type `powershell`, and press Enter. Run `Get-Item .\pyproject.toml` to confirm the working directory.

2. Run `py -3 --version`. If the launcher is missing or the version is below 3.12, obtain an approved Python 3.12 or newer installation, reopen PowerShell in that folder, and check again. If you need to select an installed version explicitly, use its launcher selector in both commands, for example `py -3.12 --version` and `py -3.12 -m venv .venv`. [Python for Windows](https://www.python.org/downloads/windows/)

3. Create the virtual environment with that interpreter and install the live collection libraries.

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install ".[live]"
   .\.venv\Scripts\bec.exe --version
   ```

4. Ask the administrator responsible for your organization's approved BEC Entra desktop app to confirm that `BEC_MICROSOFT_CLIENT_ID` is available in this PowerShell session. A single-tenant registration also requires `BEC_MICROSOFT_TENANT_ID`. If the app or a required value is missing, stop at this step. After an administrator deploys workstation settings, reopen PowerShell in the extracted folder. [Delegated sign-in setup and permissions](security.md#investigator-sign-in)

5. Launch BEC and sign in to Microsoft.

   ```powershell
   .\.venv\Scripts\bec.exe microsoft
   ```

   Confirm the displayed tenant. At `Accounts to investigate (separate addresses with commas):` enter the affected accounts. BEC prints the report path for each one.

## macOS

Double-click the downloaded ZIP in Finder. Open Terminal in the extracted directory containing `pyproject.toml`. Run `ls pyproject.toml` and `python3 --version`. If Python is missing or older than 3.12, install an approved supported interpreter and check its version before continuing. [Python for macOS](https://www.python.org/downloads/macos/)

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[live]'
.venv/bin/bec --version
```

For a Microsoft investigation, complete [workstation sign-in setup](#microsoft-sign-in-on-macos-or-ubuntu) next.

## Ubuntu

Use the file manager to extract the downloaded ZIP. Open a terminal in the extracted directory containing `pyproject.toml`. Run `ls pyproject.toml` and `python3 --version`. Use a Python 3.12 or newer interpreter with its matching `venv` support. If either is missing, obtain it through your approved Ubuntu software source before continuing. [Ubuntu Python setup](https://ubuntu.com/developers/docs/howto/python-setup/)

```sh
python3 -m venv .venv
.venv/bin/python -m pip install '.[live]'
.venv/bin/bec --version
```

## Microsoft sign-in on macOS or Ubuntu

Have your administrator confirm that the organization’s approved BEC desktop app ID is available to the terminal as `BEC_MICROSOFT_CLIENT_ID`. A single-tenant app also requires `BEC_MICROSOFT_TENANT_ID`. Stop if the approved registration or a required setting is missing. [Delegated sign-in setup and permissions](security.md#investigator-sign-in)

Once configured, run `.venv/bin/bec microsoft`. Sign in to Microsoft, confirm the displayed tenant, and enter the affected account addresses separated by commas. Each report covers the preceding 24 hours in UTC.

## What the install includes

The base package includes the `bec` command, local evidence analysis, report template and analysis rules. Windows also receives time-zone data. For a workstation used only for offline exports, comparison, search or mailbox snapshots, use `pip install .` in the virtual environment in place of `pip install ".[live]"`.

The `live` option includes MSAL and Requests for investigator sign-in, Azure Identity for unattended Microsoft application credentials, and Google Auth with Requests for Workspace. Pip also installs the dependencies these libraries declare. Workstation installation and tenant permission approval are separate steps. [Project dependencies](../pyproject.toml)

For Workspace account setup, private investigations and operator-authorized lab validation, see the [Workspace guide](workspace.md), [investigation guide](investigations.md) and [lab procedure](lab-validation.md).
