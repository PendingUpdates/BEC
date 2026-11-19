# Bacon Egg and Cheese

![BEC email investigation](docs/assets/BEC-Banner.gif)

BEC investigates business email compromise in Microsoft 365 and Google Workspace. It builds an account timeline from available logs and links findings to their original evidence. You can also investigate exported logs or search and compare saved cases offline.

Setup guides for [Windows](docs/prerequisites.md#windows), [macOS](docs/prerequisites.md#macos), and [Ubuntu](docs/prerequisites.md#ubuntu).

## First Microsoft investigation on Windows

1. Open the BEC repository on GitHub, select the **main** branch, then choose **Code → Download ZIP**. [PendingUpdates/BEC on GitHub](https://github.com/PendingUpdates/BEC)

2. In File Explorer, right-click the downloaded ZIP and choose **Extract All**. Open the extracted folder containing `pyproject.toml`. Click the address bar, type `powershell`, and press Enter. Run `py -3 --version`. Continue when it reports **Python 3.12 or newer**. [Windows Python setup](docs/prerequisites.md#windows)

3. Install BEC and its live collection libraries in that folder.

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install ".[live]"
   ```

4. Have your administrator confirm that your workstation has the **already approved Entra desktop app** for BEC. Its application ID must be available as `BEC_MICROSOFT_CLIENT_ID`. A single-tenant app also requires `BEC_MICROSOFT_TENANT_ID`. **Stop here if the approved app or a required ID is missing.** [Delegated sign-in setup and permissions](docs/security.md#investigator-sign-in)

5. Start the investigation in the same PowerShell window.

   ```powershell
   .\.venv\Scripts\bec.exe microsoft
   ```

   Sign in through Microsoft with your investigation account. If the displayed tenant is wrong, press Ctrl+C. Otherwise, at `Accounts to investigate (separate addresses with commas):` enter the affected account addresses and press Enter.

BEC collects the preceding 24 hours in UTC and prints a separate HTML report path for each account. Cases default to `BEC-Cases` in your Windows user folder. Each report identifies missing or denied logs.

For Google Workspace, unattended collection, exported logs and saved-case commands, see the [investigation guide](docs/investigations.md). BEC is distributed under the [MIT License](LICENSE).
