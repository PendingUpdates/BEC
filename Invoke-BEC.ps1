#requires -Version 7.4
# Run from the already connected Exchange Online PowerShell window.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [string[]]$Accounts,
    [string]$StartUtc,
    [string]$EndUtc,
    [string]$CaseRoot
)
$ErrorActionPreference = 'Stop'
$python = if ($IsWindows) { Join-Path $PSScriptRoot '.venv/Scripts/python.exe' }
          else { Join-Path $PSScriptRoot '.venv/bin/python' }
$adapter = & $python -I -m bec microsoft --adapter
if ($LASTEXITCODE -ne 0 -or -not $adapter) { throw 'Install BEC in the .venv under the extracted BEC folder.' }
& $adapter -Python $python @PSBoundParameters
exit $LASTEXITCODE
