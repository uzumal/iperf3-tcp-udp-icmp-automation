@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "CONFIG_PATH=%~1"

if "%CONFIG_PATH%"=="" set "CONFIG_PATH=%SCRIPT_DIR%config.json"

if not exist "%CONFIG_PATH%" (
  echo Configuration file was not found: "%CONFIG_PATH%"
  echo Copy config.example.json to config.json and update the target addresses.
  exit /b 2
)

where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%SCRIPT_DIR%monitor.py" --config "%CONFIG_PATH%"
) else (
  python "%SCRIPT_DIR%monitor.py" --config "%CONFIG_PATH%"
)

endlocal
