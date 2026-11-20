"""Check the installed command and package resources without reading or creating case data."""
import subprocess
import sys
import tempfile
from importlib import resources


def main():
    data = resources.files("bec").joinpath("data")
    if not all(data.joinpath(name).is_file() for name in ("rules.json", "report.html", "Invoke-BEC.ps1")):
        raise RuntimeError("The installed report template or rules file is missing.")
    if data.joinpath("demo").is_dir():
        raise RuntimeError("The installation contains a legacy sample directory.")
    with tempfile.TemporaryDirectory(prefix="bec-commands-") as folder:
        for args in (["--version"], ["--help"], ["microsoft", "--help"], ["microsoft", "--adapter"],
                     ["offline", "--help"], ["package", "--help"], ["investigate", "--help"]):
            result = subprocess.run([sys.executable, "-I", "-m", "bec", *args], cwd=folder,
                                    capture_output=True, text=True, check=True, timeout=30)
            if args == ["--help"] and (not all(name in result.stdout for name in ("microsoft", "offline", "package")) or "demo" in result.stdout):
                raise RuntimeError("The installed command list does not match the release.")
    print("Installed command help, version and reporting resources are available.")


if __name__ == "__main__":
    main()
