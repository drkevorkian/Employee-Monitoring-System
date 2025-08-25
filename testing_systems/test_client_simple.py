#!/usr/bin/env python3
"""
Simple test client to test the full-screen functionality.
"""

import time
import socket
import json
import base64
import uuid
from PIL import Image, ImageDraw, ImageFont
import io

def create_simple_test_image(width=1920, height=1080):
    """Create a simple test image."""
    # Create a new image with a dark background
    image = Image.new('RGB', (width, height), color='#2c3e50')
    draw = ImageDraw.Draw(image)
    
    # Add some test content
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    
    # Draw a simple pattern
    for i in range(0, width, 200):
        for j in range(0, height, 200):
            color = '#3498db' if (i + j) % 400 == 0 else '#e74c3c'
            draw.rectangle([i, j, i+100, j+100], fill=color)
    
    # Add text
    timestamp = time.strftime("%H:%M:%S")
    draw.text((50, 50), f"Test Screen - {timestamp}", fill='white', font=font)
    draw.text((50, 100), "Click Full Screen button to test", fill='white', font=font)
    draw.text((50, 150), "Then click Back to List", fill='white', font=font)
    
    # Convert to bytes
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format='PNG', quality=85)
    return img_byte_arr.getvalue()

def test_fullscreen_functionality():
    """Test the full-screen functionality."""
    try:
        print("Connecting to server...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        print("✓ Connected to server")
        
        # Generate client ID
        client_id = str(uuid.uuid4())[:16]
        print(f"Client ID: {client_id}")
        
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
        
        data = json.dumps(registration).encode('utf-8')
        sock.sendall(len(data).to_bytes(4, byteorder='big') + data)
        
        # Wait for response
        response_length = int.from_bytes(sock.recv(4), byteorder='big')
        response_data = sock.recv(response_length)
        response = json.loads(response_data.decode('utf-8'))
        
        if response.get('status') == 'accepted':
            print("✓ Client registered successfully")
            
            # Send a few screen captures
            for i in range(5):
                print(f"Sending screen capture {i+1}/5...")
                
                # Create test image
                image_data = create_simple_test_image()
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
                
                time.sleep(3)  # Wait 3 seconds between captures
            
            print("✓ All screen captures sent")
            print("\nNow test the full-screen functionality:")
            print("1. Look for the 'Full Screen' button on the client thumbnail")
            print("2. Click it to enter full-screen mode")
            print("3. Click '← Back to List' to return to the grid view")
            print("4. The grid view should now be visible with all clients")
            
            # Keep connection alive for testing
            print("\nKeeping connection alive for 30 seconds...")
            time.sleep(30)
            
        else:
            print(f"✗ Registration failed: {response}")
            
    except Exception as e:
        print(f"✗ Error: {e}")
    finally:
        try:
            sock.close()
            print("✓ Connection closed")
        except Exception:
            pass

if __name__ == "__main__":
    print("=== Full-Screen Functionality Test ===")
    print("Make sure the server is running first!")
    print()
    
    input("Press Enter to start the test...")
    test_fullscreen_functionality()
    
    print("\nTest completed!")
