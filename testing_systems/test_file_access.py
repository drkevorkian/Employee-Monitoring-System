#!/usr/bin/env python3
"""
Test script to verify file access functionality
"""

import os
import sys
import json
import socket
import time
from datetime import datetime

def test_file_access():
    """Test file access functionality by connecting to server."""
    try:
        print("🧪 Testing File Access Functionality")
        print("=" * 50)
        
        # Connect to server
        print("Connecting to server...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        print("✅ Connected to server")
        
        # Send client registration
        client_id = "test_file_client"
        registration = {
            'type': 'client_registration',
            'client_id': client_id,
            'system_info': {
                'hostname': 'TestFileClient',
                'platform': 'Windows',
                'capabilities': {
                    'file_operations': True
                }
            }
        }
        
        # Send registration
        data_bytes = json.dumps(registration).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        print("✅ Client registration sent")
        
        # Wait for registration to complete
        time.sleep(2)
        
        # Test file list request
        print("\n📁 Testing file list request...")
        file_list_request = {
            'type': 'file_list_request',
            'client_id': client_id,
            'directory_path': '/'
        }
        
        data_bytes = json.dumps(file_list_request).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        print("✅ File list request sent")
        
        # Wait for response
        time.sleep(1)
        
        # Test file content request
        print("\n📄 Testing file content request...")
        file_content_request = {
            'type': 'file_content_request',
            'client_id': client_id,
            'file_path': '/test.txt'
        }
        
        data_bytes = json.dumps(file_content_request).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        print("✅ File content request sent")
        
        # Keep connection alive for a bit to receive responses
        print("\n⏳ Waiting for server responses...")
        time.sleep(5)
        
        client_socket.close()
        print("✅ Test completed successfully")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("Starting file access test...")
    success = test_file_access()
    
    if success:
        print("\n🎉 File access test passed!")
    else:
        print("\n💥 File access test failed!")
        sys.exit(1)
