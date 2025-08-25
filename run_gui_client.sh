#!/bin/bash

echo "Starting Employee Monitoring Client (GUI)..."
echo ""
echo "This will start the monitoring client with a modern GUI interface."
echo "The client will run in the system tray and can be minimized."
echo ""
echo "Press Enter to continue..."
read

python3 client_gui.py

echo ""
echo "Client stopped. Press Enter to exit..."
read
