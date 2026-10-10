<#
.SYNOPSIS
    asta-sec - Network Packet Analyzer CLI Launcher
.DESCRIPTION
    Runs asta-sec.exe and auto-elevates to Administrator if required by Npcap.
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$exe = Join-Path $PSScriptRoot "asta-sec.exe"

if (-not (Test-Path $exe)) {
    Write-Error "asta-sec.exe not found! Please build it first."
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    & $exe @ScriptArgs
} else {
    Write-Host "[*] Requesting Administrator privileges for Npcap..." -ForegroundColor Yellow
    $argString = if ($ScriptArgs) { ($ScriptArgs | ForEach-Object { "`"$_`"" }) -join " " } else { "" }
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "& '$exe' $argString" -Verb RunAs
}
