@echo off
echo Starting Employee Monitoring Client (GUI)...
echo.
echo This will start the monitoring client with a modern GUI interface.
echo The client will run in the system tray and can be minimized.
echo.
echo Press any key to continue...
pause >nul

python client_gui.py

echo.
echo Client stopped. Press any key to exit...
pause >nul
