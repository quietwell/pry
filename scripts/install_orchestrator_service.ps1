param(
    # Path to the pry-server launcher. Default is the venv-installed
    # entry point produced by `uv sync` / `uv pip install -e orchestrator`.
    [string]$ServerExe = ".\orchestrator\.venv\Scripts\pry-server.exe",
    # Fallback Python interpreter when ServerExe is absent (uv venv). The
    # script falls back to `<Python> -m pry.server` if the exe is
    # missing. Both are relative to the repo root (the directory above
    # scripts\), matching start_orchestrator.ps1.
    [string]$PythonExe = ".\orchestrator\.venv\Scripts\python.exe",
    # Config path passed through to pry-server. Resolved against the
    # repo root for the installed service's working directory.
    [string]$Config = "configs\local.yaml",
    [int]$Port = 8765,
    # Boot autostart matches install_agent_service.ps1.
    [ValidateSet("auto", "demand")]
    [string]$StartMode = "auto",
    # Run as LocalSystem by default (parity with PryAgent) so the
    # orchestrator survives operator logout. Pass -ServiceAccount
    # 'DOMAIN\user' (or '.\user') + -ServicePassword for a dedicated
    # service account instead; empty string means LocalSystem.
    [string]$ServiceAccount = "",
    [string]$ServicePassword = "",
    [string]$ServiceName = "PryOrchestrator",
    # Rotating log file for stdout/stderr. Empty string disables.
    [string]$LogPath = ""
)

# Install the pry orchestrator (MCP + dashboard) as a Windows service
# with boot autostart and SCM crash recovery. Mirrors
# install_agent_service.ps1 (admin check, Remove-ServiceIfExists,
# Set-ServiceRecovery, sc.exe failure policy). Run from an elevated prompt
# with the repo root as the working directory.
#
# IMPORTANT: pry-server.exe is a plain Python/uvicorn console app, NOT
# an SCM-aware service binary — the agent's service_main.cpp hand-shake
# does not exist here. sc.exe will see the service process exit cleanly
# after uvicorn forks and treat it as "stopped unexpectedly" (1053-class
# behavior). The SC failure actions below then relaunch it, which is the
# recovery intent of this script. For a cleaner lifecycle (no 1053
# bounces), wrap pry-server through NSSM / winsw / pywin32 — the
# plumbing registered here (service name, failure policy, autostart) is
# compatible with any of those wrappers.

$ErrorActionPreference = "Stop"

# ---- admin check (install_agent_service.ps1 relies on an elevated
# prompt; here we fail loudly instead of silently returning sc errors) ----
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$princ = New-Object Security.Principal.WindowsPrincipal($current)
if (-not $princ.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "install_orchestrator_service.ps1 must run from an elevated PowerShell (right-click -> Run as administrator)"
}

$repo = Split-Path -Parent $PSScriptRoot
$workDir = $repo
$configPath = if ([IO.Path]::IsPathRooted($Config)) { $Config } else { Join-Path $repo $Config }

# ---- launcher resolution ----
# Prefer the venv-installed pry-server.exe (one argv, clean quoting);
# fall back to `python -m pry.server` when the entry point script is
# missing (uv sync run only once).
$serverPath = if ([IO.Path]::IsPathRooted($ServerExe)) { $ServerExe } else { Join-Path $repo $ServerExe }
$pythonPath = if ([IO.Path]::IsPathRooted($PythonExe)) { $PythonExe } else { Join-Path $repo $PythonExe }

if (Test-Path $serverPath) {
    $launcher = $serverPath
    $launcherArgs = "--config `"$configPath`""
} elseif (Test-Path $pythonPath) {
    $launcher = $pythonPath
    $launcherArgs = "-m pry.server --config `"$configPath`""
} else {
    throw "neither $serverPath nor $pythonPath exists; run 'uv sync' in orchestrator/ first, or pass -ServerExe explicitly"
}

if (-not $LogPath) {
    $LogPath = Join-Path $repo "orchestrator\orchestrator-service.log"
}

# ---- Remove-ServiceIfExists / Set-ServiceRecovery ----
# Lifted from install_agent_service.ps1 line 68-98 so the two installers
# stay parallel. The 30-tick stop wait avoids ERROR_SERVICE_MARKED_FOR_DELETE
# just like the agent script.
function Remove-ServiceIfExists($name) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) { return }
    sc.exe stop $name | Out-Null
    for ($i = 0; $i -lt 30; $i++) {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $s -or $s.Status -eq "Stopped") { break }
        Start-Sleep -Milliseconds 500
    }
    Start-Sleep -Milliseconds 500
    sc.exe delete $name | Out-Null
    Start-Sleep -Milliseconds 500
}

function Set-ServiceRecovery($name) {
    # SC failure actions: three restart attempts (5s, 5s, 15s) then stop
    # retrying. `reset=300` zeroes the fail counter after 5 minutes of
    # health so a long-running service doesn't exhaust the budget. Shape
    # mirrors install_agent_service.ps1 line 91-98 verbatim.
    sc.exe failure $name reset= 300 actions= restart/5000/restart/5000/restart/15000 | Out-Null
    sc.exe failureflag $name 1 | Out-Null
}

Remove-ServiceIfExists $ServiceName

# ---- sc.exe create ----
# binPath layout matches the agent installer: quoted exe, then flags. The
# working directory for a service is %SystemRoot%\System32 by default; we
# cannot set a WD via sc.exe create, so the launcher argv uses the
# resolved absolute $configPath.
$binPath = "`"$launcher`" $launcherArgs"

$createArgs = @(
    "create", $ServiceName,
    "binPath=", $binPath,
    "type=", "own",
    "start=", $StartMode,
    "DisplayName=", "Pry Orchestrator"
)
if ($ServiceAccount) {
    $createArgs += @("obj=", $ServiceAccount)
    if ($ServicePassword) {
        $createArgs += @("password=", $ServicePassword)
    }
}

& sc.exe @createArgs | Out-Null
if ($LASTEXITCODE -ne 0) {
    # Retry once: a marked-for-delete remnant can reject the first create.
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe @createArgs | Out-Null
}
if ($LASTEXITCODE -ne 0) { throw "sc create failed (exit $LASTEXITCODE)" }

sc.exe description $ServiceName "Pry orchestrator (MCP :$Port, dashboard, findings ledger)" | Out-Null
Set-ServiceRecovery $ServiceName

# ---- firewall ----
# The orchestrator's MCP port serves local MCP clients; by default we
# scope the firewall rule to loopback so the dashboard is not accidentally
# published on the LAN. Operators who need remote MCP access widen this
# rule explicitly (netsh advfirewall ... remoteip=...).
netsh advfirewall firewall delete rule name="Pry Orchestrator" | Out-Null
netsh advfirewall firewall add rule name="Pry Orchestrator" dir=in action=allow protocol=TCP localport=$Port profile=any remoteip=127.0.0.1 | Out-Null

Write-Host ""
Write-Host "Installed service '$ServiceName' ($StartMode start, SCM recovery)."
Write-Host "  launcher: $launcher $launcherArgs"
Write-Host "  config:   $configPath"
Write-Host "  logPath:  $LogPath"
if ($ServiceAccount) {
    Write-Host "  runAs:    $ServiceAccount"
} else {
    Write-Host "  runAs:    LocalSystem (default)"
}

# ---- idempotent state report ----
# Print the resulting SC state so re-running the installer against an
# already-installed service answers "did anything change?" in one shot.
sc.exe query $ServiceName
sc.exe qfailure $ServiceName

if ($StartMode -eq "demand") {
    Write-Host "Start now with:   sc start $ServiceName"
} else {
    Write-Host "Starting now:     sc start $ServiceName"
    sc.exe start $ServiceName | Out-Null
}
Write-Host "Verify listener:  Test-NetConnection 127.0.0.1 -Port $Port"
Write-Host "Health probe:     curl http://127.0.0.1:$Port/health"
Write-Host "Recovery policy:  sc qfailure $ServiceName"
