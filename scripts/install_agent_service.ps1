param(
    [string]$AgentPath = ".\build\agent\Release\pry_agent.exe",
    [string]$DriverPath = ".\build\driver\Release\pry_driver.sys",
    [string]$MapperPath = ".\build\mapper\Release\mapper.exe",
    [string]$ExerciserPath = ".\build\tools\Release\drv_exerciser.exe",
    [int]$Port = 50074,
    [int]$UmagentPort = 50075,
    [string]$Token = $(throw "-Token is required (long random string)"),
    # boot autostart. 'auto' (default) starts the services at
    # boot; 'demand' preserves the old manual-start behavior.
    [ValidateSet("auto", "demand")]
    [string]$StartMode = "auto",
    # Rotating diagnostic log (agent + gRPC internals; session-0 post-mortem).
    # Empty string disables.
    [string]$LogPath = "",
    # Firewall remote scope for the agent ports. Default keeps the lab subnets;
    # pass "any" to allow all sources (token is the only gate then).
    [string]$RemoteIp = "127.0.0.1,192.168.0.0/16,10.0.0.0/8",
    # the token is written HERE (ACL: SYSTEM + Administrators only)
    # and both services get --token-file instead of --token, so it no longer
    # sits in the world-readable service binPath (`sc qc` showed it to any
    # local user). Older agents do not know --token-file:
    # install them with -LegacyTokenInBinPath.
    [string]$TokenFile = "C:\pry\agent.token",
    [switch]$LegacyTokenInBinPath,
    # Hard deletes (Files.Delete no_trash=true) are refused unless the agent
    # runs with --allow-delete. On by default so existing behaviour is kept
    # (the orchestrator still gates no_trash behind security.allow_delete);
    # pass -AllowHardDelete:$false to make the agent refuse them too.
    [bool]$AllowHardDelete = $true,
    # Skip the install-directory ACL hardening (see Set-InstallDirAcl).
    [switch]$SkipAclHardening
)

# Install the agent (and optional umagent) as Windows services with boot
# autostart, SCM crash recovery, rotating logs and firewall rules for every
# profile. Run this ON THE TARGET VM from an elevated prompt, with the
# pry payload directory as the working directory. Imports any *.cer
# sitting next to it into LocalMachine Root + TrustedPublishers so the
# test-signed driver loads.
#
# NOTE: the exe IS a proper Windows service binary (SCM handshake in
# service_main.cpp). Never wrap it in `cmd /c ...` — the wrapper, not the
# exe, is what failed the SCM handshake with 1053 on the rig, and cmd pipes
# for stdio are the known "process up, port dead" wedge. Point binPath at
# the exe itself; put flags (--port/--token/--log/...) after it.

$ErrorActionPreference = "Stop"
$dest = $PSScriptRoot

foreach ($pair in @(@("agent", $AgentPath), @("driver", $DriverPath), @("mapper", $MapperPath), @("exerciser", $ExerciserPath))) {
    $src = Resolve-Path $pair[1] -ErrorAction SilentlyContinue
    if ($src) {
        Copy-Item $src.Path $dest -Force
    }
}

$agent = Join-Path $dest "pry_agent.exe"
if (-not (Test-Path $agent)) {
    throw "pry_agent.exe not found in $dest; pass -AgentPath"
}

# Well-known SIDs (locale-independent icacls principals).
$SidSystem = "*S-1-5-18"
$SidAdmins = "*S-1-5-32-544"
$SidUsers = "*S-1-5-32-545"

function Set-InstallDirAcl($dir) {
    # The install dir used to inherit Authenticated Users:Modify from C:\,
    # so any local user could replace pry_agent.exe / pry_driver.sys
    # and get SYSTEM (or kernel) code execution at the next service start.
    # New ACL: SYSTEM + Administrators full control, Users read/execute,
    # nothing inherited; existing children re-inherit from it.
    $full = (Resolve-Path $dir).Path.TrimEnd("\")
    if ($full -match '^[A-Za-z]:$' -or ($env:USERPROFILE -and $full.StartsWith($env:USERPROFILE, [StringComparison]::OrdinalIgnoreCase))) {
        Write-Warning "not hardening the ACL of $full (volume root or user profile); install from e.g. C:\pry"
        return
    }
    icacls $full /inheritance:r /grant:r "${SidSystem}:(OI)(CI)F" "${SidAdmins}:(OI)(CI)F" "${SidUsers}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls (install dir) failed" }
    icacls (Join-Path $full "*") /reset /T /C /Q | Out-Null
    Write-Host "hardened ACL on $full (SYSTEM/Administrators full, Users read)"
}

function Write-TokenFile($path, $value) {
    # Create empty, lock the ACL down, THEN write the secret, so the token
    # is never readable under an inherited ACL.
    $parent = Split-Path -Parent $path
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
    if (-not (Test-Path $path)) { New-Item -ItemType File -Path $path | Out-Null }
    icacls $path /inheritance:r /grant:r "${SidSystem}:F" "${SidAdmins}:F" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls (token file) failed" }
    [IO.File]::WriteAllText($path, $value, (New-Object Text.UTF8Encoding $false))
    Write-Host "token written to $path (SYSTEM + Administrators only)"
}

if (-not $SkipAclHardening) { Set-InstallDirAcl $dest }
if ($LegacyTokenInBinPath) {
    Write-Warning "-LegacyTokenInBinPath: the token stays visible to every local user via 'sc qc'"
    $authArg = "--token `"$Token`""
} else {
    Write-TokenFile $TokenFile $Token
    $authArg = "--token-file `"$TokenFile`""
}
$deleteArg = if ($AllowHardDelete) { " --allow-delete" } else { "" }

if (-not $LogPath) {
    $LogPath = Join-Path $dest "pry_agent.log"
}

# trust the test-signing cert chain on THIS machine (required for the kernel
# to accept the driver; TESTSIGNING ON alone is not sufficient for a
# self-signed code-signing cert)
Get-ChildItem $dest -Filter "*.cer" | ForEach-Object {
    Write-Host "importing $($_.Name) into LocalMachine Root + TrustedPublisher"
    Import-Certificate -FilePath $_.FullName -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    Import-Certificate -FilePath $_.FullName -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
}

# testsigning must be ON for the driver; warn early
$ts = (bcdedit /enum '{current}' | Select-String "testsigning\s+Yes")
if (-not $ts) {
    Write-Warning "TESTSIGNING is OFF. Run: bcdedit /set TESTSIGNING ON  (then REBOOT) or the driver will not load."
}

function Remove-ServiceIfExists($name) {
    # idempotent: stop + WAIT FOR FULL STOP + delete any existing instance
    # before creating. The wait matters: the agent stops gracefully
    # (server shutdown + breadcrumb flush can take seconds), and deleting
    # a still-stopping service marks it for deletion — the subsequent
    # create then fails with ERROR_SERVICE_MARKED_FOR_DELETE and the old
    # service vanishes on next reboot. Never run this installer through
    # the agent's own exec API while it recreates the agent service: the
    # stopping agent reaps the child. Run it from a rig console (or via
    # exec run_detached, whose children survive agent restarts).
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
    # Auto-restart on unclean exit: bugs in the debug/engine path have
    # crashed the agent process before, and without this the RPC endpoint
    # stays dead until someone with local access intervenes. reset= keeps
    # the fail counter honest so a real user-triggered stop isn't
    # restarted.
    sc.exe failure $name reset= 300 actions= restart/5000/restart/5000/restart/15000 | Out-Null
    sc.exe failureflag $name 1 | Out-Null
}

Remove-ServiceIfExists "PryAgent"

# One canonical autostart: the SCM service above. Remove the legacy
# scheduled-task workarounds (onstart `cmd /c --dev` launcher + the 5-min
# netstat watchdog that re-ran it) — they raced the service at boot and
# left orphaned instances holding the port. The watchdog's job (revive a
# dead endpoint) is covered by sc failure recovery + the agent's built-in
# listener self-test/rebind.
foreach ($legacy in @("pry-agent", "pry-agent-watch")) {
    schtasks /change /tn $legacy /disable 2>$null | Out-Null
    schtasks /delete /tn $legacy /f 2>$null | Out-Null
    if ($?) { Write-Host "removed legacy task: $legacy" }
}

sc.exe create PryAgent binPath= "`"$agent`" --port $Port $authArg$deleteArg --log `"$LogPath`"" type= own start= $StartMode DisplayName= "Pry Agent"
if ($LASTEXITCODE -ne 0) {
    # retry once: a marked-for-delete remnant can reject the first create
    sc.exe delete PryAgent | Out-Null
    Start-Sleep -Seconds 1
    sc.exe create PryAgent binPath= "`"$agent`" --port $Port $authArg$deleteArg --log `"$LogPath`"" type= own start= $StartMode DisplayName= "Pry Agent"
}
if ($LASTEXITCODE -ne 0) { throw "sc create failed" }

sc.exe description PryAgent "Pry authorized-lab assessment agent (gRPC :$Port)"
if ($LASTEXITCODE -ne 0) { throw "sc description failed" }

Set-ServiceRecovery "PryAgent"

# profile=any: the rig lost LAN reachability after NIC flaps moved the
# interface between firewall profiles — a profile-scoped rule went silent
# until an any-profile rule replaced it.
netsh advfirewall firewall delete rule name="Pry Agent" | Out-Null
netsh advfirewall firewall add rule name="Pry Agent" dir=in action=allow protocol=TCP localport=$Port profile=any remoteip=$RemoteIp | Out-Null

if ($UmagentPort -gt 0) {
    $umagent = Join-Path $dest "pry_umagent.exe"
    if (Test-Path $umagent) {
        Remove-ServiceIfExists "PryUmagent"
        $uLog = Join-Path $dest "pry_umagent.log"
        # --bind 0.0.0.0: the umagent defaults to 127.0.0.1 (same-host parity
        # view); the orchestrator reaches it remotely, so bind all interfaces.
        # Same token (same --token-file) as the agent: the token is the only
        # gate — keep the VM off untrusted networks.
        sc.exe create PryUmagent binPath= "`"$umagent`" --port $UmagentPort --bind 0.0.0.0 $authArg --log `"$uLog`"" type= own start= $StartMode DisplayName= "Pry Umagent"
        if ($LASTEXITCODE -ne 0) {
            sc.exe delete PryUmagent | Out-Null
            Start-Sleep -Seconds 1
            sc.exe create PryUmagent binPath= "`"$umagent`" --port $UmagentPort --bind 0.0.0.0 $authArg --log `"$uLog`"" type= own start= $StartMode DisplayName= "Pry Umagent"
        }
        if ($LASTEXITCODE -ne 0) { throw "sc create (umagent) failed" }
        sc.exe description PryUmagent "Pry usermode-only parity view (gRPC :$UmagentPort)"
        Set-ServiceRecovery "PryUmagent"
        netsh advfirewall firewall delete rule name="Pry Umagent" | Out-Null
        netsh advfirewall firewall add rule name="Pry Umagent" dir=in action=allow protocol=TCP localport=$UmagentPort profile=any remoteip=$RemoteIp | Out-Null
        Write-Host "Umagent installed: sc start PryUmagent"
    } else {
        Write-Warning "pry_umagent.exe not found in $dest - umagent service skipped"
    }
}

Write-Host ""
Write-Host "Installed ($StartMode start, SCM recovery, log: $LogPath)."
if ($StartMode -eq "demand") {
    Write-Host "Start now with:   sc start PryAgent"
} else {
    Write-Host "Starting now:     sc start PryAgent"
    sc.exe start PryAgent | Out-Null
}
Write-Host "Verify listener:  Test-NetConnection 127.0.0.1 -Port $Port"
Write-Host "Recovery policy:  sc qfailure PryAgent"
if (-not $LegacyTokenInBinPath) { Write-Host "Token file:       $TokenFile (rotate: rerun with a new -Token)" }
Write-Host "Driver load happens via MCP target_manage(action='driver_load') or:"
Write-Host "  sc create PryDrv type= kernel start= demand binPath= '\??\$dest\pry_driver.sys'"
Write-Host "NOTE: driver binary updates need a reboot if the driver is currently loaded."
