#!/usr/bin/env python3
"""
Test script to demonstrate the remote control functionality of the monitoring system.
This script simulates a client connection and tests various remote control commands.
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
    """Create a test image with timestamp and system info."""
    # Create a new image with a dark background
    img = Image.new('RGB', (width, height), color='#2c3e50')
    draw = ImageDraw.Draw(img)
    
    try:
        # Try to use a default font
        font = ImageFont.load_default()
    except Exception:
        font = None
    
    # Add timestamp
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    draw.text((50, 50), f"Test Client - {timestamp}", fill='white', font=font)
    
    # Add system info
    draw.text((50, 100), "Platform: Windows/Linux", fill='white', font=font)
    draw.text((50, 150), "Status: Online", fill='#27ae60', font=font)
    draw.text((50, 200), "Remote Control: Enabled", fill='#3498db', font=font)
    
    # Add a colored rectangle to make it visually distinct
    draw.rectangle([50, 250, 400, 300], fill='#e74c3c', outline='white', width=2)
    draw.text((70, 260), "Remote Control Test", fill='white', font=font)
    
    # Convert to bytes
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    return img_byte_arr.getvalue()

class RemoteControlTestClient:
    """Test client that responds to remote control commands."""
    
    def __init__(self, client_id, hostname="TEST-CLIENT"):
        self.client_id = client_id
        self.hostname = hostname
        self.platform = "Windows" if socket.gethostname().startswith('WIN') else "Linux"
        self.socket = None
        self.connected = False
        self.running = True
        
        # Command response tracking
        self.command_responses = {}
        
    def connect(self, host='localhost', port=8080):
        """Connect to the monitoring server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True
            print(f"✓ Connected to server {host}:{port}")
            return True
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False
    
    def register(self):
        """Register with the server."""
        try:
            registration = {
                'type': 'client_registration',
                'client_id': self.client_id,
                'system_info': {
                    'hostname': self.hostname,
                    'platform': self.platform,
                    'capabilities': {
                        'screen_capture': True,
                        'remote_reboot': True,
                        'service_management': True
                    },
                    'network_info': {
                        'mac_address': '00:11:22:33:44:55'
                    }
                }
            }
            
            self._send_data(registration)
            response = self._receive_data()
            
            if response and response.get('status') == 'accepted':
                print(f"✓ Client registered successfully: {self.client_id}")
                return True
            else:
                print(f"✗ Registration failed: {response}")
                return False
                
        except Exception as e:
            print(f"✗ Registration error: {e}")
            return False
    
    def start_screen_capture(self):
        """Start sending screen captures."""
        def capture_loop():
            frame_count = 0
            while self.running and self.connected:
                try:
                    # Create test image
                    image_data = create_test_image()
                    image_b64 = base64.b64encode(image_data).decode('utf-8')
                    
                    # Send screen capture
                    capture = {
                        'type': 'screen_capture',
                        'client_id': self.client_id,
                        'image_data': image_b64,
                        'metadata': {
                            'timestamp': time.time(),
                            'resolution': '1920x1080',
                            'format': 'PNG',
                            'size_bytes': len(image_data),
                            'frame_number': frame_count
                        }
                    }
                    
                    self._send_data(capture)
                    frame_count += 1
                    
                    # Wait between captures
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"✗ Screen capture error: {e}")
                    break
        
        # Start capture thread
        capture_thread = threading.Thread(target=capture_loop, daemon=True)
        capture_thread.start()
        print("✓ Screen capture started")
    
    def start_command_listener(self):
        """Start listening for remote control commands."""
        def command_loop():
            while self.running and self.connected:
                try:
                    # Check for incoming commands
                    command = self._receive_data()
                    if command:
                        self._handle_command(command)
                        
                except Exception as e:
                    if self.running:
                        print(f"✗ Command listener error: {e}")
                    break
        
        # Start command listener thread
        command_thread = threading.Thread(target=command_loop, daemon=True)
        command_thread.start()
        print("✓ Command listener started")
    
    def _handle_command(self, command):
        """Handle remote control commands from the server."""
        try:
            command_type = command.get('type')
            command_id = command.get('command_id')
            
            print(f"📨 Received command: {command_type}")
            
            if command_type == 'reboot':
                self._handle_reboot_command(command_id)
            elif command_type == 'shutdown':
                self._handle_shutdown_command(command_id)
            elif command_type == 'service_control':
                self._handle_service_control_command(command_id, command.get('action'))
            elif command_type == 'update_config':
                self._handle_config_update_command(command_id, command.get('config'))
            else:
                print(f"⚠ Unknown command type: {command_type}")
                
        except Exception as e:
            print(f"✗ Error handling command: {e}")
    
    def _handle_reboot_command(self, command_id):
        """Handle reboot command."""
        print("🔄 Processing reboot command...")
        
        # Simulate reboot process
        time.sleep(1)
        
        # Send response
        response = {
            'type': 'command_response',
            'command_id': command_id,
            'status': 'success',
            'message': 'Reboot command executed successfully'
        }
        
        self._send_data(response)
        print("✓ Reboot command response sent")
        
        # Simulate reboot delay
        print("🔄 Simulating reboot in 3 seconds...")
        time.sleep(3)
        
        # Reconnect after "reboot"
        print("🔄 Reconnecting after reboot...")
        self.connected = False
        if self.socket:
            self.socket.close()
        
        # Wait a bit then reconnect
        time.sleep(2)
        if self.connect():
            self.register()
            self.start_screen_capture()
            self.start_command_listener()
    
    def _handle_shutdown_command(self, command_id):
        """Handle shutdown command."""
        print("⏹ Processing shutdown command...")
        
        # Simulate shutdown process
        time.sleep(1)
        
        # Send response
        response = {
            'type': 'command_response',
            'command_id': command_id,
            'status': 'success',
            'message': 'Shutdown command executed successfully'
        }
        
        self._send_data(response)
        print("✓ Shutdown command response sent")
        
        # Simulate shutdown
        print("⏹ Simulating shutdown...")
        self.running = False
        self.connected = False
    
    def _handle_service_control_command(self, command_id, action):
        """Handle service control command."""
        print(f"⚙ Processing service control command: {action}")
        
        # Simulate service control
        time.sleep(1)
        
        # Send response
        response = {
            'type': 'command_response',
            'command_id': command_id,
            'status': 'success',
            'message': f'Service {action} completed successfully'
        }
        
        self._send_data(response)
        print(f"✓ Service control command response sent: {action}")
    
    def _handle_config_update_command(self, command_id, config):
        """Handle configuration update command."""
        print(f"⚙ Processing configuration update command")
        
        # Simulate config update
        time.sleep(1)
        
        # Send response
        response = {
            'type': 'command_response',
            'command_id': command_id,
            'status': 'success',
            'message': 'Configuration updated successfully'
        }
        
        self._send_data(response)
        print("✓ Configuration update command response sent")
    
    def _send_data(self, data):
        """Send data to server."""
        try:
            if not self.socket:
                return
            
            # Convert to JSON and encode
            json_data = json.dumps(data, default=str)
            data_bytes = json_data.encode('utf-8')
            
            # Send data length first, then data
            length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
            self.socket.sendall(length_bytes + data_bytes)
            
        except Exception as e:
            print(f"✗ Failed to send data: {e}")
            self.connected = False
    
    def _receive_data(self):
        """Receive data from server."""
        try:
            if not self.socket:
                return None
            
            # Set timeout for non-blocking receive
            self.socket.settimeout(0.1)
            
            # Receive data length first
            length_bytes = self.socket.recv(4)
            if not length_bytes:
                return None
            
            data_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive data in chunks
            data_bytes = b''
            while len(data_bytes) < data_length:
                chunk = self.socket.recv(min(4096, data_length - len(data_bytes)))
                if not chunk:
                    break
                data_bytes += chunk
            
            if len(data_bytes) == data_length:
                # Parse JSON data
                json_data = data_bytes.decode('utf-8')
                return json.loads(json_data)
            else:
                return None
                
        except socket.timeout:
            # No data available
            return None
        except Exception as e:
            print(f"✗ Failed to receive data: {e}")
            return None
        finally:
            # Reset timeout
            if self.socket:
                self.socket.settimeout(None)
    
    def run(self, host='localhost', port=8080):
        """Run the test client."""
        try:
            print(f"🚀 Starting remote control test client: {self.client_id}")
            print(f"📍 Connecting to server: {host}:{port}")
            
            # Connect to server
            if not self.connect(host, port):
                return
            
            # Register with server
            if not self.register():
                return
            
            # Start screen capture
            self.start_screen_capture()
            
            # Start command listener
            self.start_command_listener()
            
            # Keep running
            print("✅ Test client running. Use server GUI to test remote control features.")
            print("📋 Available commands:")
            print("   - Reboot client (🔄 button)")
            print("   - Shutdown client (⏹ button)")
            print("   - Restart service (⚙ button)")
            print("   - Broadcast commands (toolbar buttons)")
            print("\n⏹ Press Ctrl+C to stop the client")
            
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n⏹ Stopping test client...")
        except Exception as e:
            print(f"✗ Test client error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the test client."""
        self.running = False
        self.connected = False
        
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass
        
        print("✅ Test client stopped")

def main():
    """Main entry point."""
    print("=== Remote Control Test Client ===")
    print("This script tests the remote control functionality of the monitoring system.")
    print()
    
    # Get server connection details
    host = input("Enter server host (default: localhost): ").strip() or 'localhost'
    port = input("Enter server port (default: 8080): ").strip() or '8080'
    
    try:
        port = int(port)
    except ValueError:
        print("Invalid port number. Using default port 8080.")
        port = 8080
    
    print(f"\nConnecting to server: {host}:{port}")
    print("Make sure the server is running first!")
    print()
    
    # Create and run test client
    client_id = str(uuid.uuid4())[:16]
    client = RemoteControlTestClient(client_id)
    
    try:
        client.run(host, port)
    except KeyboardInterrupt:
        print("\n⏹ Test interrupted by user")
    except Exception as e:
        print(f"✗ Test failed: {e}")

if __name__ == "__main__":
    main()
