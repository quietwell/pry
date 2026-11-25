@echo off
rem Double-click launcher for the pry status watch window.
rem Opens a PowerShell process running watch.ps1 in its own console.
powershell.exe -NoExit -ExecutionPolicy Bypass -File "%~dp0watch.ps1"
