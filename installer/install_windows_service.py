#!/usr/bin/env python3
"""
Windows Service Installation Script for Employee Monitoring Client
This script installs the monitoring client as a Windows service using NSSM.
"""

import os
import sys
import subprocess
import shutil
import winreg
import ctypes
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def check_nssm():
    """Check if NSSM is available in the system PATH."""
    nssm_path = shutil.which('nssm')
    if nssm_path:
        logger.info(f"NSSM found at: {nssm_path}")
        return nssm_path
    else:
        logger.warning("NSSM not found in PATH")
        return None

def download_nssm():
    """Download and install NSSM if not available."""
    try:
        import urllib.request
        import zipfile
        import tempfile
        
        logger.info("Downloading NSSM...")
        
        # NSSM download URL (latest stable version)
        nssm_url = "https://nssm.cc/release/nssm-2.24.zip"
        
        # Create temporary directory
        temp_dir = Path(tempfile.mkdtemp())
        zip_path = temp_dir / "nssm.zip"
        
        # Download NSSM
        logger.info(f"Downloading from {nssm_url}...")
        urllib.request.urlretrieve(nssm_url, zip_path)
        
        # Extract zip file
        logger.info("Extracting NSSM...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        # Find nssm.exe in extracted files
        nssm_exe = None
        for file_path in temp_dir.rglob("nssm.exe"):
            nssm_exe = file_path
            break
        
        if not nssm_exe:
            logger.error("Error: nssm.exe not found in downloaded files")
            return False
        
        # Copy to System32 (requires admin privileges)
        target_path = Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'System32' / 'nssm.exe'
        
        try:
            shutil.copy2(nssm_exe, target_path)
            logger.info(f"NSSM installed to {target_path}")
            
            # Clean up temporary files
            shutil.rmtree(temp_dir)
            return True
            
        except PermissionError:
            logger.error("Permission denied. Please run as Administrator to install NSSM to System32")
            logger.info("Installing NSSM to current directory instead...")
            
            # Install to current directory as fallback
            current_dir = Path.cwd()
            target_path = current_dir / 'nssm.exe'
            
            try:
                shutil.copy2(nssm_exe, target_path)
                logger.info(f"NSSM installed to {target_path}")
                logger.info("Note: You may need to add this directory to your PATH")
                
                # Clean up temporary files
                shutil.rmtree(temp_dir)
                return True
                
            except Exception as copy_error:
                logger.error(f"Failed to copy NSSM to current directory: {copy_error}")
                logger.info(f"Please manually copy {nssm_exe} to a directory in your PATH")
                return False
            
    except Exception as e:
        logger.error(f"Error downloading NSSM: {e}")
        logger.info("Please download manually from: https://nssm.cc/download")
        return False

def install_service():
    """Install the monitoring client as a Windows service."""
    try:
        # Service configuration
        service_name = "EmployeeMonitoringClient"
        service_display_name = "Employee Monitoring Client"
        service_description = "Monitors employee computer activity for security purposes"
        
        # Get current script path and client path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        client_path = os.path.join(os.path.dirname(current_dir), 'apps', 'client', 'main.py')
        python_exe = sys.executable
        
        # Check if client.py exists
        if not os.path.exists(client_path):
            logger.error(f"Client script not found at: {client_path}")
            logger.error("Please ensure apps/client/main.py is present")
            return False
        
        # Check if service already exists
        if check_service_exists(service_name):
            logger.warning(f"Service '{service_name}' already exists")
            reply = input("Do you want to reinstall it? (y/N): ").strip().lower()
            if reply != 'y':
                logger.info("Service installation cancelled")
                return False
            
            # Remove existing service
            remove_service(service_name)
        
        # Install service using NSSM
        nssm_path = check_nssm()
        if not nssm_path:
            if not download_nssm():
                logger.error("Cannot install service without NSSM")
                return False
            nssm_path = check_nssm()
            if not nssm_path:
                logger.error("NSSM still not available after download attempt")
                return False
        
        # Set working directory
        working_dir = os.path.dirname(client_path)
        
        logger.info(f"Installing service '{service_name}'...")
        logger.info(f"Python executable: {python_exe}")
        logger.info(f"Client script: {client_path}")
        logger.info(f"Working directory: {working_dir}")
        
        # Install service (run client.py as the service)
        # Use absolute paths to avoid path issues
        subprocess.run([
            nssm_path, 'install', service_name, python_exe, client_path
        ], check=True)
        
        # Set service description
        subprocess.run([
            nssm_path, 'set', service_name, 'Description', service_description
        ], check=True)
        
        # Set display name
        subprocess.run([
            nssm_path, 'set', service_name, 'DisplayName', service_display_name
        ], check=True)
        
        # Set startup type to automatic
        subprocess.run([
            nssm_path, 'set', service_name, 'Start', 'SERVICE_AUTO_START'
        ], check=True)
        
        # Set working directory (already defined above)
        subprocess.run([
            nssm_path, 'set', service_name, 'AppDirectory', working_dir
        ], check=True)
        
        # Set environment variables (NSSM expects individual KEY=VALUE pairs)
        try:
            subprocess.run([
                nssm_path, 'set', service_name, 'AppEnvironmentExtra', 'SERVICE_NAME=EmployeeMonitoringClient'
            ], check=True)
        except subprocess.CalledProcessError:
            logger.warning("Could not set environment variable (this is optional)")
        
        # Set service to restart on failure
        subprocess.run([
            nssm_path, 'set', service_name, 'AppRestartDelay', '10000'
        ], check=True)
        
        # Set service to restart on failure
        subprocess.run([
            nssm_path, 'set', service_name, 'AppStopMethodSkip', '0'
        ], check=True)
        
        # Set service to restart on failure
        subprocess.run([
            nssm_path, 'set', service_name, 'AppStopMethodConsole', '1500'
        ], check=True)
        
        # Set service to restart on failure
        subprocess.run([
            nssm_path, 'set', service_name, 'AppStopMethodWindow', '1500'
        ], check=True)
        
        # Set service to restart on failure
        subprocess.run([
            nssm_path, 'set', service_name, 'AppStopMethodThreads', '1500'
        ], check=True)
        
        logger.info(f"Service '{service_name}' installed successfully")
        
        # Add a small delay to ensure all parameters are set
        import time
        time.sleep(1)
        
        # Start the service
        logger.info("Starting service...")
        try:
            subprocess.run(['sc', 'start', service_name], check=True)
            logger.info("Service started successfully")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Service start failed: {e}")
            logger.info("You can manually start the service using: sc start EmployeeMonitoringClient")
            logger.info("Or check the service status using: sc query EmployeeMonitoringClient")
        
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Service installation failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during service installation: {e}")
        return False

def check_service_exists(service_name):
    """Check if a Windows service exists."""
    try:
        result = subprocess.run(['sc', 'query', service_name], 
                              capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False

def remove_service(service_name):
    """Remove a Windows service."""
    try:
        logger.info(f"Removing existing service '{service_name}'...")
        
        # Stop service first
        try:
            subprocess.run(['sc', 'stop', service_name], check=True)
            logger.info("Service stopped")
        except Exception:
            pass
        
        # Remove service
        nssm_path = check_nssm()
        if nssm_path:
            subprocess.run([nssm_path, 'remove', service_name, 'confirm'], check=True)
        else:
            subprocess.run(['sc', 'delete', service_name], check=True)
        
        logger.info(f"Service '{service_name}' removed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to remove service: {e}")
        return False

def uninstall_service():
    """Uninstall the monitoring client service."""
    try:
        service_name = "EmployeeMonitoringClient"
        
        if not check_service_exists(service_name):
            logger.info(f"Service '{service_name}' does not exist")
            return True
        
        return remove_service(service_name)
        
    except Exception as e:
        logger.error(f"Service uninstallation failed: {e}")
        return False

def show_service_status():
    """Show the status of the monitoring client service."""
    try:
        service_name = "EmployeeMonitoringClient"
        
        if not check_service_exists(service_name):
            logger.info(f"Service '{service_name}' does not exist")
            return
        
        # Get service status
        result = subprocess.run(['sc', 'query', service_name], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("Service Status:")
            print(result.stdout)
        else:
            logger.error("Failed to get service status")
            
    except Exception as e:
        logger.error(f"Failed to get service status: {e}")

def main():
    """Main entry point."""
    print("=== Employee Monitoring Client - Windows Service Installer ===")
    print()
    
    # Check if running as administrator
    if not is_admin():
        logger.error("This script must be run as Administrator")
        logger.error("Please right-click and select 'Run as Administrator'")
        input("Press Enter to exit...")
        return
    
    # Check if NSSM is available
    if not check_nssm():
        logger.warning("NSSM not found. This script requires NSSM to install Windows services.")
        logger.info("Attempting to download and install NSSM automatically...")
        
        if download_nssm():
            logger.info("NSSM installed successfully!")
            # Verify installation
            if not check_nssm():
                logger.error("NSSM installation failed. Please install manually:")
                logger.info("1. Download from: https://nssm.cc/download")
                logger.info("2. Extract nssm.exe to C:/Windows/System32/ or add to PATH")
                logger.info("3. Run this script again")
                input("Press Enter to exit...")
                return
        else:
            logger.error("Failed to install NSSM automatically. Please install manually:")
            logger.info("1. Download from: https://nssm.cc/download")
            logger.info("2. Extract nssm.exe to C:/Windows/System32/ or add to PATH")
            logger.info("3. Run this script again")
            input("Press Enter to exit...")
            return
    
    while True:
        print("\nSelect an option:")
        print("1. Install Service")
        print("2. Uninstall Service")
        print("3. Show Service Status")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            if install_service():
                logger.info("Service installation completed successfully!")
            else:
                logger.error("Service installation failed!")
        
        elif choice == '2':
            if uninstall_service():
                logger.info("Service uninstallation completed successfully!")
            else:
                logger.error("Service uninstallation failed!")
        
        elif choice == '3':
            show_service_status()
        
        elif choice == '4':
            logger.info("Exiting...")
            break
        
        else:
            logger.warning("Invalid choice. Please enter 1-4.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
