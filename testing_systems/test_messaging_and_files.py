#!/usr/bin/env python3
"""
Test script for messaging and file system functionality
"""

import time
import json
import socket
import threading
import base64
from datetime import datetime

def test_client_connection():
    """Test client connection and basic functionality."""
    try:
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        
        # Send client registration
        client_id = "test_client_001"
        registration = {
            'type': 'client_registration',
            'client_id': client_id,
            'system_info': {
                'hostname': 'TestClient',
                'platform': 'Windows',
                'capabilities': {
                    'messaging': True,
                    'file_operations': True
                }
            }
        }
        
        # Send registration
        data_bytes = json.dumps(registration).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        
        print(f"✅ Client registration sent: {client_id}")
        
        # Wait for response
        time.sleep(1)
        
        # Send a test chat message
        chat_message = {
            'type': 'chat_message',
            'client_id': client_id,
            'message': 'Hello from test client!',
            'timestamp': datetime.now().isoformat()
        }
        
        data_bytes = json.dumps(chat_message).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        
        print("✅ Chat message sent")
        
        # Send a test file list response
        file_list_response = {
            'type': 'file_list_response',
            'client_id': client_id,
            'directory_path': '/test',
            'files': [
                {'name': 'test.txt', 'type': 'file', 'size': 1024, 'modified': '2025-01-16T12:00:00'},
                {'name': 'document.pdf', 'type': 'file', 'size': 2048, 'modified': '2025-01-16T11:00:00'}
            ],
            'directories': ['documents', 'pictures']
        }
        
        data_bytes = json.dumps(file_list_response).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        
        print("✅ File list response sent")
        
        # Keep connection alive for a bit
        time.sleep(5)
        
        client_socket.close()
        print("✅ Test completed successfully")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

def test_server_commands():
    """Test server command sending."""
    try:
        # Connect to server
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        
        # Send client registration first
        client_id = "test_client_002"
        registration = {
            'type': 'client_registration',
            'client_id': client_id,
            'system_info': {
                'hostname': 'TestClient2',
                'platform': 'Linux',
                'capabilities': {
                    'messaging': True,
                    'file_operations': True
                }
            }
        }
        
        data_bytes = json.dumps(registration).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        
        print(f"✅ Client registration sent: {client_id}")
        
        # Wait for registration to complete
        time.sleep(2)
        
        # Now listen for commands
        print("🔍 Listening for server commands...")
        
        # Set timeout for receiving
        client_socket.settimeout(10)
        
        try:
            while True:
                # Receive data length
                length_bytes = client_socket.recv(4)
                if not length_bytes:
                    break
                
                data_length = int.from_bytes(length_bytes, byteorder='big')
                
                # Receive data
                data_bytes = b''
                while len(data_bytes) < data_length:
                    chunk = client_socket.recv(min(4096, data_length - len(data_bytes)))
                    if not chunk:
                        break
                    data_bytes += chunk
                
                if len(data_bytes) == data_length:
                    # Server may send typed registration responses or commands; always decode as JSON
                    command = json.loads(data_bytes.decode('utf-8'))
                    print(f"📨 Received command: {command['type']}")
                    
                    # Handle different command types
                    if command['type'] == 'chat_message':
                        print(f"💬 Chat message: {command.get('message', 'No message')}")
                        
                        # Send response
                        response = {
                            'type': 'command_response',
                            'command_id': command.get('command_id'),
                            'status': 'success',
                            'message': 'Chat message received'
                        }
                        data_bytes = json.dumps(response).encode('utf-8')
                        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
                        client_socket.sendall(length_bytes + data_bytes)
                        
                    elif command['type'] == 'file_list_request':
                        print(f"📁 File list request for: {command.get('directory_path', 'Unknown')}")
                        
                        # Send mock file list
                        file_list_response = {
                            'type': 'file_list_response',
                            'client_id': client_id,
                            'directory_path': command.get('directory_path', '/'),
                            'files': [
                                {'name': 'test.txt', 'type': 'file', 'size': 1024, 'modified': '2025-01-16T12:00:00'},
                                {'name': 'readme.md', 'type': 'file', 'size': 512, 'modified': '2025-01-16T10:00:00'}
                            ],
                            'directories': ['home', 'var']
                        }
                        
                        data_bytes = json.dumps(file_list_response).encode('utf-8')
                        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
                        client_socket.sendall(length_bytes + data_bytes)
                        
                    elif command['type'] == 'file_content_request':
                        print(f"📄 File content request for: {command.get('file_path', 'Unknown')}")
                        
                        # Send mock file content
                        file_content_response = {
                            'type': 'file_content_response',
                            'client_id': client_id,
                            'file_path': command.get('file_path', ''),
                            'content': 'This is test file content for demonstration purposes.',
                            'file_size': 67,
                            'is_binary': False
                        }
                        
                        data_bytes = json.dumps(file_content_response).encode('utf-8')
                        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
                        client_socket.sendall(length_bytes + data_bytes)
                        
                    else:
                        print(f"❓ Unknown command type: {command.get('type', 'unknown')}")
                        
        except socket.timeout:
            print("⏰ Timeout waiting for commands")
        
        client_socket.close()
        print("✅ Command test completed")
        
    except Exception as e:
        print(f"❌ Command test failed: {e}")

if __name__ == "__main__":
    print("🧪 Testing Employee Monitoring System - Messaging & File Operations")
    print("=" * 70)
    
    print("\n1️⃣ Testing basic client connection and message sending...")
    test_client_connection()
    
    print("\n2️⃣ Testing server command handling...")
    test_server_commands()
    
    print("\n🎉 All tests completed!")
