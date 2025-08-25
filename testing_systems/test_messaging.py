#!/usr/bin/env python3
"""
Test script for messaging functionality between server and client.
"""

import socket
import json
import time
import sys

def test_messaging():
    """Test messaging functionality."""
    print("🧪 Testing Messaging Functionality")
    print("=" * 50)
    
    # Connect to server
    print("Connecting to server...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 8080))
        print("✅ Connected to server")
    except Exception as e:
        print(f"❌ Failed to connect to server: {e}")
        return False
    
    # Send client registration
    print("📝 Sending client registration...")
    registration = {
        'type': 'client_registration',
        'client_id': 'test-messaging-client',
        'system_info': {
            'hostname': 'TEST-MESSAGING-CLIENT',
            'platform': 'windows',
            'capabilities': ['messaging', 'file_access']
        }
    }
    
    try:
        data_bytes = json.dumps(registration).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        sock.sendall(length_bytes + data_bytes)
        print("✅ Client registration sent")
    except Exception as e:
        print(f"❌ Failed to send registration: {e}")
        sock.close()
        return False
    
    # Wait for registration response
    print("⏳ Waiting for registration response...")
    try:
        length_bytes = sock.recv(4)
        if not length_bytes:
            print("❌ No response received")
            sock.close()
            return False
        
        data_length = int.from_bytes(length_bytes, byteorder='big')
        data_bytes = sock.recv(data_length)
        
        if len(data_bytes) == data_length:
            response = json.loads(data_bytes.decode('utf-8'))
            # Accept either legacy or typed response
            if response.get('status') == 'accepted' or response.get('type') == 'registration_response':
                print("✅ Registration accepted")
            else:
                print(f"❌ Registration rejected: {response.get('message', 'Unknown error')}")
                sock.close()
                return False
        else:
            print("❌ Incomplete response received")
            sock.close()
            return False
            
    except Exception as e:
        print(f"❌ Failed to receive registration response: {e}")
        sock.close()
        return False
    
    # Send a test message
    print("💬 Sending test message...")
    test_message = {
        'type': 'chat_message',
        'client_id': 'test-messaging-client',
        'message': 'Hello from test client! This is a test message to verify the messaging system is working.',
        'timestamp': time.time()
    }
    
    try:
        data_bytes = json.dumps(test_message).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        sock.sendall(length_bytes + data_bytes)
        print("✅ Test message sent")
    except Exception as e:
        print(f"❌ Failed to send test message: {e}")
        sock.close()
        return False
    
    # Wait a bit for message processing
    print("⏳ Waiting for message processing...")
    time.sleep(2)
    
    # Close connection
    sock.close()
    print("✅ Test completed successfully")
    print("🎉 Messaging test passed!")
    return True

if __name__ == "__main__":
    success = test_messaging()
    sys.exit(0 if success else 1)
