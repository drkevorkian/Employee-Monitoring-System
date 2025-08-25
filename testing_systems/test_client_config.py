#!/usr/bin/env python3
"""
Test script to verify client configuration reading.
"""

import configparser
import os

def test_client_config():
    """Test that the client reads the correct server configuration."""
    config = configparser.ConfigParser()
    
    if os.path.exists('config.ini'):
        config.read('config.ini')
        print("Configuration loaded successfully")
        
        # Test server section
        print(f"\n[Server] section:")
        print(f"  host: {config.get('Server', 'host', fallback='NOT_FOUND')}")
        print(f"  port: {config.getint('Server', 'port', fallback=0)}")
        
        # Test client section
        print(f"\n[Client] section:")
        print(f"  server_host: {config.get('Client', 'server_host', fallback='NOT_FOUND')}")
        print(f"  server_port: {config.getint('Client', 'server_port', fallback=0)}")
        
        # Test what the client would actually use
        print(f"\nClient would connect to:")
        print(f"  host: {config.get('Client', 'server_host', fallback='localhost')}")
        print(f"  port: {config.getint('Client', 'server_port', fallback=8080)}")
        
    else:
        print("config.ini not found!")

if __name__ == "__main__":
    test_client_config()
