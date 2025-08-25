@echo off
echo Installing Employee Monitoring Client as Windows Service...
echo.
echo This script must be run as Administrator
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running as Administrator - proceeding with installation...
) else (
    echo ERROR: This script must be run as Administrator
    echo Please right-click and select "Run as Administrator"
    pause
    exit /b 1
)

REM Set Python path
set PYTHON_PATH=C:\Users\owner\AppData\Local\Programs\Python\Python310\python.exe
set SERVICE_SCRIPT=%~dp0client_service.py

REM Check if Python exists
if not exist "%PYTHON_PATH%" (
    echo ERROR: Python not found at %PYTHON_PATH%
    echo Please update the PYTHON_PATH in this script
    pause
    exit /b 1
)

REM Check if service script exists
if not exist "%SERVICE_SCRIPT%" (
    echo ERROR: Service script not found at %SERVICE_SCRIPT%
    pause
    exit /b 1
)

echo Installing service...
"%PYTHON_PATH%" "%SERVICE_SCRIPT%" install

if %errorLevel% == 0 (
    echo.
    echo Service installed successfully!
    echo.
    echo To start the service:
    echo   sc start EmployeeMonitoringClient
    echo.
    echo To stop the service:
    echo   sc stop EmployeeMonitoringClient
    echo.
    echo To remove the service:
    echo   "%PYTHON_PATH%" "%SERVICE_SCRIPT%" remove
    echo.
) else (
    echo.
    echo Service installation failed!
    echo.
)

pause
