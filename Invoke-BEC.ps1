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
# Use the co-shipped adapter. An older installed launcher may still include audit collection.
$adapter = Join-Path $PSScriptRoot 'bec/data/Invoke-BEC.ps1'
& $adapter -Python $python @PSBoundParameters
exit $LASTEXITCODE
