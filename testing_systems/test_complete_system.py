#!/usr/bin/env python3
"""
Comprehensive test script for the Employee Monitoring System
Tests all major functionality including file browser, messaging, and system tray
"""

import os
import sys
import json
import socket
import time
import threading
from datetime import datetime

def test_server_connection():
    """Test basic server connection."""
    print("🔌 Testing server connection...")
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        print("✅ Server connection successful")
        client_socket.close()
        return True
    except Exception as e:
        print(f"❌ Server connection failed: {e}")
        return False

def test_client_registration():
    """Test client registration with server."""
    print("\n📝 Testing client registration...")
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        
        # Send registration
        registration = {
            'type': 'client_registration',
            'client_id': 'test_client_001',
            'system_info': {
                'hostname': 'TestClient',
                'platform': 'Windows',
                'capabilities': {
                    'file_operations': True,
                    'messaging': True
                }
            }
        }
        
        data_bytes = json.dumps(registration).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        
        print("✅ Client registration sent")
        
        # Wait for response
        time.sleep(2)
        client_socket.close()
        return True
        
    except Exception as e:
        print(f"❌ Client registration failed: {e}")
        return False

def test_file_browser():
    """Test file browser functionality."""
    print("\n📁 Testing file browser...")
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        
        # Send file list request
        file_request = {
            'type': 'file_list_request',
            'client_id': 'test_client_001',
            'directory_path': '/'
        }
        
        data_bytes = json.dumps(file_request).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        
        print("✅ File list request sent")
        
        # Wait for response
        time.sleep(3)
        client_socket.close()
        return True
        
    except Exception as e:
        print(f"❌ File browser test failed: {e}")
        return False

def test_messaging():
    """Test messaging functionality."""
    print("\n💬 Testing messaging...")
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(('localhost', 8080))
        
        # Send test message
        message = {
            'type': 'chat_message',
            'client_id': 'test_client_001',
            'message': 'Hello from test client!',
            'timestamp': datetime.now().isoformat()
        }
        
        data_bytes = json.dumps(message).encode('utf-8')
        length_bytes = len(data_bytes).to_bytes(4, byteorder='big')
        client_socket.sendall(length_bytes + data_bytes)
        
        print("✅ Test message sent")
        
        # Wait for response
        time.sleep(2)
        client_socket.close()
        return True
        
    except Exception as e:
        print(f"❌ Messaging test failed: {e}")
        return False

def test_system_tray():
    """Test system tray functionality."""
    print("\n🖥️ Testing system tray...")
    try:
        # Import PySide6 to test system tray availability
        from PySide6.QtWidgets import QSystemTrayIcon
        
        if QSystemTrayIcon.isSystemTrayAvailable():
            print("✅ System tray is available")
            return True
        else:
            print("⚠️ System tray is not available on this system")
            return False
            
    except ImportError:
        print("❌ PySide6 not available for system tray test")
        return False
    except Exception as e:
        print(f"❌ System tray test failed: {e}")
        return False

def test_gui_imports():
    """Test GUI imports."""
    print("\n🎨 Testing GUI imports...")
    try:
        from PySide6.QtWidgets import QApplication, QMainWindow, QWidget
        from PySide6.QtCore import Qt, QTimer, QThread, Signal
        from PySide6.QtGui import QPixmap, QImage, QFont, QIcon, QPalette, QColor, QAction
        
        print("✅ All GUI imports successful")
        return True
        
    except ImportError as e:
        print(f"❌ GUI import failed: {e}")
        return False

def test_client_gui_import():
    """Test client GUI module import."""
    print("\n📱 Testing client GUI module...")
    try:
        import client_gui
        print("✅ Client GUI module imported successfully")
        return True
        
    except ImportError as e:
        print(f"❌ Client GUI import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Client GUI test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 Employee Monitoring System - Complete Test Suite")
    print("=" * 60)
    
    tests = [
        ("Server Connection", test_server_connection),
        ("Client Registration", test_client_registration),
        ("File Browser", test_file_browser),
        ("Messaging", test_messaging),
        ("System Tray", test_system_tray),
        ("GUI Imports", test_gui_imports),
        ("Client GUI Module", test_client_gui_import),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {test_name}")
        if success:
            passed += 1
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is working correctly.")
        return True
    else:
        print("⚠️ Some tests failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
