param(
    [ValidateSet("all", "user", "driver", "orchestrator")]
    [string]$Target = "all",
    [string]$Configuration = "Release",
    [switch]$SkipVcpkgCheck
)

# Pry build orchestrator: python stubs -> cmake (comm/exerciser/mapper/agent)
# -> driver (WDK via cmake) -> orchestrator env sync.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$presets = Join-Path $root "CMakePresets.json"
$failures = @()

function Invoke-Step([string]$name, [scriptblock]$body) {
    Write-Host ""
    Write-Host "==> $name" -ForegroundColor Cyan
    & $body
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Host "    step FAILED: $name" -ForegroundColor Red
        $script:failures += $name
    }
}

# 1) python stubs (checked in, but regenerate to stay in sync)
Invoke-Step "proto -> python stubs" {
    & (Join-Path $PSScriptRoot "gen_proto.ps1")
}

# 2) vcpkg grpc presence
if (-not $SkipVcpkgCheck) {
    Invoke-Step "vcpkg grpc check" {
        $env:VCPKG_DOWNLOADS = "C:\vcpkg-downloads"
        if (-not (Test-Path $env:VCPKG_DOWNLOADS)) {
            New-Item -ItemType Directory -Force -Path $env:VCPKG_DOWNLOADS | Out-Null
        }
        # CMakePresets.json pins the toolchain at D:/vcpkg; fall back to the
        # classic C:\vcpkg only when neither VCPKG_ROOT nor D:\vcpkg exists.
        $vcpkgRoot = if ($env:VCPKG_ROOT) { $env:VCPKG_ROOT }
                     elseif (Test-Path "D:\vcpkg\vcpkg.exe") { "D:\vcpkg" }
                     else { "C:\vcpkg" }
        $grpcInstalled = Test-Path (Join-Path $vcpkgRoot "installed\x64-windows-static-release\share\grpc\grpcConfig.cmake")
        if (-not $grpcInstalled) {
            Write-Host "    grpc:x64-windows-static not installed yet; building it now (this is slow on first run)" -ForegroundColor Yellow
            Write-Host "    (VCPKG_DOWNLOADS moved to NTFS C:\ - exFAT volumes break vcpkg tool extraction)" -ForegroundColor Yellow
            & (Join-Path $vcpkgRoot "vcpkg.exe") install grpc:x64-windows-static-release --overlay-ports="$root\vcpkg-overlays"
        }
    }
}

# 3) cmake configure + build
if ($Target -in @("all", "user")) {
    Invoke-Step "cmake configure (user-mode)" {
        cmake --preset win64-user -S $root -B (Join-Path $root "build")
    }
    Invoke-Step "cmake build (user-mode: comm, exerciser, mapper, agent)" {
        cmake --build --preset win64-user-release
    }
}

if ($Target -in @("all", "driver")) {
    Invoke-Step "cmake configure (driver)" {
        cmake --preset win64 -S $root -B (Join-Path $root "build")
    }
    Invoke-Step "cmake build (pry_driver.sys)" {
        cmake --build --preset win64-release --target pry_driver
    }
}

# 4) orchestrator env
if ($Target -in @("all", "orchestrator")) {
    Invoke-Step "uv sync (orchestrator)" {
        Push-Location (Join-Path $root "orchestrator")
        try {
            # uv emits progress on stderr; with $ErrorActionPreference=Stop
            # each stderr line otherwise aborts the build. Merge to stdout.
            # codegen (keystone/unicorn/speakeasy) backs emulate_manage and
            # memory_manage assemble; a plain `--extra dev` sync uninstalls it.
            cmd /c "uv sync --extra dev --extra codegen 2>&1"
        } finally { Pop-Location }
    }
}

Write-Host ""
if ($failures.Count) {
    Write-Host "BUILD FAILED: $($failures -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "BUILD OK" -ForegroundColor Green
Write-Host "  build\tools\Release\drv_exerciser.exe   (driver IOCTL gate - run on the target first)"
Write-Host "  build\mapper\Release\mapper.exe"
Write-Host "  build\agent\Release\pry_agent.exe"
Write-Host "  build\driver\Release\pry_driver.sys  (test-signed only; TESTSIGNING ON on target)"
