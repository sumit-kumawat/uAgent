#Requires -Version 5.1
<#
.SYNOPSIS
  Uninstalls the uAgent Windows service.

.DESCRIPTION
  Runs the installed agent's uninstall command, which deregisters the agent from the manager, stops and
  removes the service, and (unless -KeepData) deletes its data and credentials. Equivalent to
  "uAgent.exe /uninstall" or removing "uAgent Endpoint Agent" from Installed apps.
#>
param(
    [switch]$Quiet,
    [switch]$KeepData
)
$ErrorActionPreference = "Stop"

$exePath = Join-Path $env:ProgramFiles "uAgent\uAgent.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "uAgent does not appear to be installed ($exePath not found)."
    exit 0
}

$arguments = @("/uninstall")
if ($Quiet) { $arguments += "/quiet" }
if ($KeepData) { $arguments += "/keepdata" }

Write-Host "Launching $exePath $($arguments -join ' ') (it will prompt for administrator elevation)..."
$process = Start-Process -FilePath $exePath -ArgumentList $arguments -Wait -PassThru
exit $process.ExitCode
