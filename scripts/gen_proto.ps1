param(
    [string]$Python = ""
)

# Generates Python gRPC stubs from proto/pry.proto into
# orchestrator/src/pry/generated and rewrites the pb2 import for in-package use.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not $Python) {
    $Python = Join-Path $root "orchestrator\.venv\Scripts\python.exe"
    if (-not (Test-Path $Python)) {
        $Python = "python"
    }
}

$genDir = Join-Path $root "orchestrator\src\pry\generated"
New-Item -ItemType Directory -Force -Path $genDir | Out-Null

& $Python -m grpc_tools.protoc `
    -I (Join-Path $root "proto") `
    --python_out=$genDir --pyi_out=$genDir `
    --grpc_python_out=$genDir `
    (Join-Path $root "proto\pry.proto")
if ($LASTEXITCODE -ne 0) { throw "grpc_tools.protoc failed" }

$grpcFile = Join-Path $genDir "pry_pb2_grpc.py"
(Get-Content $grpcFile -Raw) `
    -replace [regex]::Escape("import pry_pb2 as pry__pb2"), "from . import pry_pb2 as pry__pb2" |
    Set-Content $grpcFile -NoNewline

Set-Content (Join-Path $genDir "__init__.py") "" -NoNewline
Write-Host "Python stubs generated in $genDir"
