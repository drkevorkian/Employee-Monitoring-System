@echo off
echo Employee Monitoring Client Service Manager
echo.

:menu
echo Select an option:
echo 1. Start Service
echo 2. Stop Service
echo 3. Service Status
echo 4. Remove Service
echo 5. Exit
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto start_service
if "%choice%"=="2" goto stop_service
if "%choice%"=="3" goto service_status
if "%choice%"=="4" goto remove_service
if "%choice%"=="5" goto exit
echo Invalid choice. Please enter 1-5.
echo.
goto menu

:start_service
echo Starting service...
sc start EmployeeMonitoringClient
echo.
pause
goto menu

:stop_service
echo Stopping service...
sc stop EmployeeMonitoringClient
echo.
pause
goto menu

:service_status
echo Service status:
sc query EmployeeMonitoringClient
echo.
pause
goto menu

:remove_service
echo.
echo WARNING: This will remove the service completely!
echo.
set /p confirm="Are you sure? (y/N): "
if /i "%confirm%"=="y" (
    echo Removing service...
    C:\Users\owner\AppData\Local\Programs\Python\Python310\python.exe client_service.py remove
    echo.
) else (
    echo Service removal cancelled.
    echo.
)
pause
goto menu

:exit
echo Goodbye!
exit /b 0
