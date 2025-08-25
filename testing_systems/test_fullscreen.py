#!/usr/bin/env python3
"""
Test script to demonstrate the full-screen functionality of the monitoring server.
This script simulates a client connection and screen capture updates.
"""

import time
import threading
import socket
import json
import base64
import uuid
from PIL import Image, ImageDraw, ImageFont
import io

def create_test_image(width=1920, height=1080):
    """Create a test image with timestamp and client info."""
    # Create a new image with a dark background
    image = Image.new('RGB', (width, height), color='#2c3e50')
    draw = ImageDraw.Draw(image)
    
    # Add some test content
    try:
        # Try to use a default font
        font = ImageFont.load_default()
    except Exception:
        font = None
    
    # Draw a test pattern
    for i in range(0, width, 100):
        for j in range(0, height, 100):
            color = '#3498db' if (i + j) % 200 == 0 else '#e74c3c'
            draw.rectangle([i, j, i+50, j+50], fill=color)
    
    # Add timestamp
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    draw.text((50, 50), f"Test Client Screen - {timestamp}", fill='white', font=font)
    draw.text((50, 100), "This is a simulated screen capture for testing", fill='white', font=font)
    draw.text((50, 150), "Full-screen functionality should work with this image", fill='white', font=font)
    
    # Convert to bytes
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format='PNG', quality=85, optimize=True)
    img_byte_arr = img_byte_arr.getvalue()
    
    return img_byte_arr

def simulate_client():
    """Simulate a monitoring client."""
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        print("Connected to server")
        
        # Generate client ID
        client_id = str(uuid.uuid4())[:16]
        
        # Send registration
        registration = {
            'type': 'client_registration',
            'client_id': client_id,
            'system_info': {
                'hostname': 'TEST-CLIENT',
                'platform': 'Windows',
                'capabilities': {'screen_capture': True},
                'network_info': {'mac_address': '00:11:22:33:44:55'}
            }
        }
        
        # Send registration
        data = json.dumps(registration).encode('utf-8')
        sock.sendall(len(data).to_bytes(4, byteorder='big') + data)
        
        # Wait for response
        response_length = int.from_bytes(sock.recv(4), byteorder='big')
        response_data = sock.recv(response_length)
        response = json.loads(response_data.decode('utf-8'))
        
        if response.get('status') == 'accepted':
            print(f"Client registered successfully: {client_id}")
            
            # Send screen captures
            for i in range(10):
                # Create test image
                image_data = create_test_image()
                image_b64 = base64.b64encode(image_data).decode('utf-8')
                
                # Send screen capture
                capture = {
                    'type': 'screen_capture',
                    'client_id': client_id,
                    'image_data': image_b64,
                    'metadata': {
                        'timestamp': time.time(),
                        'resolution': '1920x1080',
                        'format': 'PNG',
                        'size_bytes': len(image_data)
                    }
                }
                
                data = json.dumps(capture).encode('utf-8')
                sock.sendall(len(data).to_bytes(4, byteorder='big') + data)
                
                print(f"Sent screen capture {i+1}/10 ({len(image_data)} bytes)")
                time.sleep(2)  # Wait 2 seconds between captures
            
            print("Test completed successfully")
            
        else:
            print(f"Registration failed: {response}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

if __name__ == "__main__":
    print("Starting full-screen functionality test...")
    print("Make sure the server is running first!")
    print("This will create a test client that sends screen captures.")
    print("You can then click the 'Full Screen' button on the thumbnail.")
    print()
    
    input("Press Enter to start the test...")
    
    # Start client simulation
    simulate_client()
    
    print("\nTest completed. Check the server GUI for the full-screen functionality!")
    print("Look for the 'Full Screen' button on the client thumbnail.")
