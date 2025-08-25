@echo off
echo ========================================
echo Employee Monitoring Server - Startup Installer
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as Administrator - proceeding with installation...
) else (
    echo This script must be run as Administrator
    echo Right-click and select "Run as Administrator"
    pause
    exit /b 1
)

echo.
echo Installing server to Windows startup...

REM Get the current directory
set "CURRENT_DIR=%~dp0"
set "PYTHON_PATH=python"
set "SERVER_SCRIPT=%CURRENT_DIR%apps\server\main.py"

REM Create startup batch file
set "STARTUP_BAT=%CURRENT_DIR%start_server.bat"
echo @echo off > "%STARTUP_BAT%"
echo cd /d "%CURRENT_DIR%" >> "%STARTUP_BAT%"
echo echo Starting Employee Monitoring Server... >> "%STARTUP_BAT%"
echo echo Started at: %date% %time% >> "%STARTUP_BAT%"
echo "%PYTHON_PATH%" "%SERVER_SCRIPT%" >> "%STARTUP_BAT%"
echo pause >> "%STARTUP_BAT%"

REM Create VBS script to run batch file hidden
set "STARTUP_VBS=%CURRENT_DIR%start_server_hidden.vbs"
echo Set WshShell = CreateObject("WScript.Shell") > "%STARTUP_VBS%"
echo WshShell.Run chr(34) ^& "%STARTUP_BAT%" ^& Chr(34), 0 >> "%STARTUP_VBS%"
echo Set WshShell = Nothing >> "%STARTUP_VBS%"

REM Add to Windows startup registry
echo Adding to Windows startup registry...
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "EmployeeMonitoringServer" /t REG_SZ /d "%STARTUP_VBS%" /f

if %errorLevel% == 0 (
    echo.
    echo ========================================
    echo Installation completed successfully!
    echo ========================================
    echo.
    echo The server will now start automatically when you log in.
    echo.
    echo Files created:
    echo - %STARTUP_BAT%
    echo - %STARTUP_VBS%
    echo.
    echo To remove from startup, run:
    echo reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "EmployeeMonitoringServer" /f
    echo.
) else (
    echo.
    echo ========================================
    echo Installation failed!
    echo ========================================
    echo.
    echo Error code: %errorLevel%
    echo Please run as Administrator and try again.
    echo.
)

echo Press any key to continue...
pause >nul
