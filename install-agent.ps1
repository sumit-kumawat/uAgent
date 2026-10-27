#Requires -Version 5.1
<#
.SYNOPSIS
  Installs the uAgent Windows service.

.DESCRIPTION
  The agent ships as a single self-installing executable, uAgent-Setup.exe, downloaded from the portal
  (Dashboard -> Download Agent EXE, or the sign-in page). It embeds the manager URL, certificate pin and
  enrollment key, self-elevates, installs the hardened auto-start service, and registers automatically.

  Prefer downloading uAgent-Setup.exe from your portal so the
  manager connection is preconfigured. To build it from source, run scripts/build-agent.sh (needs the .NET
  SDK); the output is portal/agent-dist/uAgent-Setup.exe.
#>
param(
    [string]$SetupExe,
    [switch]$Quiet
)
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $SetupExe) {
    $SetupExe = Join-Path $root "portal\agent-dist\uAgent-Setup.exe"
}

if (-not (Test-Path -LiteralPath $SetupExe -PathType Leaf)) {
    throw "uAgent-Setup.exe was not found at '$SetupExe'. Download it from the portal (Download Agent EXE) or build it with scripts/build-agent.sh, then pass -SetupExe <path>."
}

$arguments = @("/install")
if ($Quiet) { $arguments += "/quiet" }

Write-Host "Launching $SetupExe $($arguments -join ' ') (it will prompt for administrator elevation)..."
$process = Start-Process -FilePath $SetupExe -ArgumentList $arguments -Wait -PassThru
exit $process.ExitCode
