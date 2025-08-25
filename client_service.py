#!/usr/bin/env python3
"""
Windows Service Wrapper for Employee Monitoring Client
This script runs the monitoring client in a Windows service environment.
"""

import os
import sys
import time
import logging
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import threading
from pathlib import Path

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Configure logging for service environment
log_file = os.path.join(current_dir, 'client_service.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class MonitoringClientService(win32serviceutil.ServiceFramework):
    """
    Windows Service wrapper for the monitoring client.
    """
    
    _svc_name_ = "EmployeeMonitoringClient"
    _svc_display_name_ = "Employee Monitoring Client"
    _svc_description_ = "Monitors employee computer activity for security purposes"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.client_thread = None
        self.is_running = False
        self.client_instance = None
        
    def SvcStop(self):
        """Stop the service."""
        logger.info("Service stop requested")
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        self.is_running = False
        try:
            if self.client_instance:
                self.client_instance.stop()
        except Exception as e:
            logger.error(f"Error stopping client instance: {e}")
        try:
            if self.client_thread:
                self.client_thread.join(timeout=10)
        except Exception:
            pass
        
    def SvcDoRun(self):
        """Run the service."""
        logger.info("Service starting...")
        try:
            self.is_running = True
            self._run_client()
        except Exception as e:
            logger.error(f"Service failed: {e}")
            self.is_running = False
            
    def _run_client(self):
        """Run the monitoring client in a separate thread."""
        try:
            # Import the client module
            from client import MonitoringClient
            
            # Create client instance
            self.client_instance = MonitoringClient()
            
            # Start client in a separate thread
            self.client_thread = threading.Thread(target=self._client_worker, args=(self.client_instance,))
            self.client_thread.daemon = True
            self.client_thread.start()
            
            # Wait for stop event
            while self.is_running:
                if win32event.WaitForSingleObject(self.stop_event, 1000) == win32event.WAIT_OBJECT_0:
                    break
                    
        except Exception as e:
            logger.error(f"Failed to start client: {e}")
            
    def _client_worker(self, client):
        """Worker thread for the client."""
        try:
            logger.info("Starting monitoring client...")
            client.start()
        except Exception as e:
            logger.error(f"Client worker failed: {e}")
        finally:
            try:
                client.stop()
            except Exception:
                pass

def main():
    """Main entry point for the service."""
    if len(sys.argv) == 1:
        # Running as service
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(MonitoringClientService)
            servicemanager.StartServiceCtrlDispatcher()
        except Exception as e:
            logger.error(f"Service dispatcher failed: {e}")
    else:
        # Running as command line tool
        win32serviceutil.HandleCommandLine(MonitoringClientService)

if __name__ == '__main__':
    main()
