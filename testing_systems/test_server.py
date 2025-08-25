#!/usr/bin/env python3
"""
Simple test script to isolate server initialization issues.
"""

import sys
import os
import logging

# Configure basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_server_init():
    """Test server initialization without GUI."""
    try:
        logger.info("Testing server initialization...")
        # Ensure project root is importable
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        
        # Test platform system
        import platform
        system = platform.system()
        logger.info(f"Platform system: {system} (type: {type(system)})")
        
        # Test security manager
        from security import SecurityManager
        import configparser
        
        config = configparser.ConfigParser()
        config.read('config.ini')
        
        logger.info("Creating SecurityManager...")
        security = SecurityManager(config)
        logger.info("SecurityManager created successfully")
        
        # Test database
        from database import SecureDatabase
        logger.info("Creating SecureDatabase...")
        db = SecureDatabase(config)
        logger.info("SecureDatabase created successfully")
        
        # Test server
        from server import MonitoringServer
        logger.info("Creating MonitoringServer...")
        server = MonitoringServer()
        logger.info("MonitoringServer created successfully")
        
        logger.info("All tests passed!")
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_server_init()
    sys.exit(0 if success else 1)
