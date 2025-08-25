#!/usr/bin/env python3
"""
Test script for multiple messaging functionality between server and client.
Tests the OOP-based messaging system that can handle multiple popups.
"""

import socket
import json
import time
import sys

def test_multiple_messages():
    """Test multiple messaging functionality."""
    print("🧪 Testing Multiple Messaging Functionality")
    print("=" * 60)
    
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
        'client_id': 'test-multiple-messages',
        'system_info': {
            'hostname': 'TEST-MULTIPLE-MESSAGES',
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
            if response.get('status') == 'accepted':
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
    
    # Send multiple test messages
    messages = [
        "First message: Welcome to the monitoring system!",
        "Second message: This is a test of multiple popups.",
        "Third message: The OOP messaging system should handle this.",
        "Fourth message: Each message should have its own popup.",
        "Fifth message: You can close them individually or all at once."
    ]
    
    print(f"💬 Sending {len(messages)} test messages...")
    
    for i, message in enumerate(messages, 1):
        print(f"   Sending message {i}/{len(messages)}...")
        
        test_message = {
            'type': 'chat_message',
            'client_id': 'test-multiple-messages',
            'message': message,
            'timestamp': time.time()
        }
        
        try:
            data_bytes = json.dumps(test_message).encode('utf-8')
            length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
            sock.sendall(length_bytes + data_bytes)
            print(f"   ✅ Message {i} sent")
            
            # Small delay between messages
            time.sleep(0.5)
            
        except Exception as e:
            print(f"   ❌ Failed to send message {i}: {e}")
            sock.close()
            return False
    
    # Wait for message processing
    print("⏳ Waiting for message processing...")
    time.sleep(3)
    
    # Close connection
    sock.close()
    print("✅ Test completed successfully")
    print("🎉 Multiple messaging test passed!")
    print("\n📋 Expected Results:")
    print("   • 5 message popups should appear on the client")
    print("   • Each popup should be positioned with offset")
    print("   • Message count should show 'Messages: 5'")
    print("   • 'Close All Messages' button should close all popups")
    print("   • Individual popups can be closed separately")
    
    return True

if __name__ == "__main__":
    success = test_multiple_messages()
    sys.exit(0 if success else 1)
