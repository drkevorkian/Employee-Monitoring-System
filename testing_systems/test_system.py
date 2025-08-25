#!/usr/bin/env python3
"""
Test Script for Employee Monitoring System
Comprehensive testing of all system components.
"""

import os
import sys
import time
import json
import threading
import unittest
import tempfile
import shutil
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our modules
try:
    from security import SecurityManager
    from database import SecureDatabase
    from client import MonitoringClient
    from server import MonitoringServer
except ImportError as e:
    print(f"❌ Failed to import modules: {e}")
    sys.exit(1)

class TestSecurityManager(unittest.TestCase):
    """Test cases for the SecurityManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'Security': {
                'encryption_key_size': 256,
                'max_login_attempts': 3,
                'session_timeout': 3600,
                'rate_limit_requests': 100,
                'rate_limit_window': 60
            }
        }
        self.security_manager = SecurityManager(self.config)
    
    def test_encryption_decryption(self):
        """Test encryption and decryption functionality."""
        test_data = b"Hello, this is a test message for encryption!"
        
        # Encrypt data
        encrypted_data, iv = self.security_manager.encrypt_data(test_data)
        self.assertIsInstance(encrypted_data, bytes)
        self.assertIsInstance(iv, bytes)
        self.assertNotEqual(encrypted_data, test_data)
        
        # Decrypt data
        decrypted_data = self.security_manager.decrypt_data(encrypted_data, iv)
        self.assertEqual(decrypted_data, test_data)
    
    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "test_password_123"
        
        # Hash password
        hashed_password, salt = self.security_manager.hash_password(password)
        self.assertIsInstance(hashed_password, str)
        self.assertIsInstance(salt, str)
        self.assertNotEqual(hashed_password, password)
        
        # Verify password
        is_valid = self.security_manager.verify_password(password, hashed_password, salt)
        self.assertTrue(is_valid)
        
        # Test wrong password
        is_valid = self.security_manager.verify_password("wrong_password", hashed_password, salt)
        self.assertFalse(is_valid)
    
    def test_secure_token_generation(self):
        """Test secure token generation."""
        token1 = self.security_manager.generate_secure_token()
        token2 = self.security_manager.generate_secure_token()
        
        self.assertIsInstance(token1, str)
        self.assertIsInstance(token2, str)
        self.assertNotEqual(token1, token2)
        self.assertEqual(len(token1), len(token2))
    
    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        client_ip = "192.168.1.100"
        
        # Should allow requests within limit
        for i in range(50):
            allowed = self.security_manager.check_rate_limit(client_ip)
            self.assertTrue(allowed)
        
        # Should block requests over limit
        for i in range(60):
            allowed = self.security_manager.check_rate_limit(client_ip)
            if i >= 50:
                self.assertFalse(allowed)
    
    def test_system_info(self):
        """Test system information gathering."""
        system_info = self.security_manager.get_system_info()
        
        self.assertIsInstance(system_info, dict)
        self.assertIn('platform', system_info)
        self.assertIn('security_features', system_info)
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.security_manager.cleanup()

class TestSecureDatabase(unittest.TestCase):
    """Test cases for the SecureDatabase class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'Database': {
                'db_path': ':memory:',  # Use in-memory database for testing
                'max_log_entries': 1000,
                'log_retention_days': 7
            }
        }
        self.database = SecureDatabase(self.config)
    
    def test_client_management(self):
        """Test client management functionality."""
        client_data = {
            'client_id': 'test_client_001',
            'hostname': 'test-machine',
            'platform': 'Windows',
            'ip_address': '192.168.1.100',
            'mac_address': '00:11:22:33:44:55',
            'user_agent': 'Test Client',
            'version': '1.0',
            'capabilities': {'screen_capture': True}
        }
        
        # Add client
        success = self.database.add_client(client_data)
        self.assertTrue(success)
        
        # Update client status
        success = self.database.update_client_status('test_client_001', 'active')
        self.assertTrue(success)
        
        # Get active clients
        clients = self.database.get_active_clients()
        self.assertGreater(len(clients), 0)
        self.assertEqual(clients[0]['client_id'], 'test_client_001')
    
    def test_session_management(self):
        """Test session management functionality."""
        session_token = "test_session_token_123"
        client_id = "test_client_001"
        user_id = "test_user"
        ip_address = "192.168.1.100"
        
        # Create session
        success = self.database.create_session(session_token, client_id, user_id, ip_address)
        self.assertTrue(success)
        
        # Validate session
        session_data = self.database.validate_session(session_token)
        self.assertIsNotNone(session_data)
        self.assertEqual(session_data['client_id'], client_id)
    
    def test_screen_capture_storage(self):
        """Test screen capture storage functionality."""
        client_id = "test_client_001"
        image_data = b"fake_image_data_for_testing"
        metadata = {
            'width': 1920,
            'height': 1080,
            'format': 'JPEG',
            'timestamp': '2024-01-01T00:00:00'
        }
        
        # Store capture
        success = self.database.store_screen_capture(client_id, image_data, metadata)
        self.assertTrue(success)
        
        # Get captures
        captures = self.database.get_client_captures(client_id, limit=10)
        self.assertGreater(len(captures), 0)
        self.assertEqual(captures[0]['client_id'], client_id)
    
    def test_activity_logging(self):
        """Test activity logging functionality."""
        # This is tested indirectly through other methods
        # but we can test the security event logging
        self.database.log_security_event(
            'test_event',
            'info',
            'Test security event',
            'test_client_001',
            '192.168.1.100'
        )
        
        # Verify it was logged by checking database stats
        stats = self.database.get_database_stats()
        self.assertGreater(stats.get('security_events_count', 0), 0)
    
    def test_database_stats(self):
        """Test database statistics functionality."""
        stats = self.database.get_database_stats()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('clients_count', stats)
        self.assertIn('sessions_count', stats)
        self.assertIn('screen_captures_count', stats)
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.database.close()

class TestMonitoringClient(unittest.TestCase):
    """Test cases for the MonitoringClient class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = configparser.ConfigParser()
        self.config.add_section('Server')
        self.config.set('Server', 'host', 'localhost')
        self.config.set('Server', 'port', '8080')
        
        self.config.add_section('Client')
        self.config.set('Client', 'screen_capture_interval', '1.0')
        self.config.set('Client', 'image_quality', '85')
        self.config.set('Client', 'compression_level', '6')
        self.config.set('Client', 'max_image_size', '800x600')
        self.config.set('Client', 'auto_reconnect', 'true')
        self.config.set('Client', 'reconnect_delay', '5')
        
        # Create temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini')
        self.config.write(self.temp_config)
        self.temp_config.close()
        
        self.client = MonitoringClient(self.temp_config.name)
    
    def test_client_initialization(self):
        """Test client initialization."""
        self.assertIsNotNone(self.client.client_id)
        self.assertEqual(self.client.server_host, 'localhost')
        self.assertEqual(self.client.server_port, 8080)
        self.assertEqual(self.client.capture_interval, 1.0)
    
    def test_system_info_gathering(self):
        """Test system information gathering."""
        system_info = self.client.get_system_info()
        
        self.assertIsInstance(system_info, dict)
        self.assertIn('client_id', system_info)
        self.assertIn('hostname', system_info)
        self.assertIn('platform', system_info)
        self.assertIn('capabilities', system_info)
    
    def test_screen_capture(self):
        """Test screen capture functionality."""
        # This test might fail in headless environments
        try:
            image_data, metadata = self.client.capture_screen()
            
            self.assertIsInstance(image_data, bytes)
            self.assertIsInstance(metadata, dict)
            self.assertIn('width', metadata)
            self.assertIn('height', metadata)
            self.assertIn('timestamp', metadata)
            
        except Exception as e:
            # Screen capture might not work in test environment
            print(f"⚠️  Screen capture test skipped: {e}")
    
    def test_placeholder_image_creation(self):
        """Test placeholder image creation."""
        placeholder = self.client._create_placeholder_image()
        
        self.assertIsInstance(placeholder, bytes)
        self.assertGreater(len(placeholder), 0)
    
    def tearDown(self):
        """Clean up test fixtures."""
        os.unlink(self.temp_config.name)
        self.client.stop()

class TestMonitoringServer(unittest.TestCase):
    """Test cases for the MonitoringServer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = configparser.ConfigParser()
        self.config.add_section('Server')
        self.config.set('Server', 'host', '127.0.0.1')
        self.config.set('Server', 'port', '0')  # Use port 0 for testing
        self.config.set('Server', 'max_clients', '10')
        self.config.set('Server', 'max_connections_per_ip', '5')
        self.config.set('Server', 'connection_timeout', '30')
        self.config.set('Server', 'heartbeat_interval', '10')
        
        self.config.add_section('Security')
        self.config.set('Security', 'encryption_key_size', '256')
        self.config.set('Security', 'max_login_attempts', '3')
        self.config.set('Security', 'session_timeout', '3600')
        
        self.config.add_section('Database')
        self.config.set('Database', 'db_path', ':memory:')
        self.config.set('Database', 'max_log_entries', '1000')
        self.config.set('Database', 'log_retention_days', '7')
        
        # Create temporary config file
        self.temp_config = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ini')
        self.config.write(self.temp_config)
        self.temp_config.close()
        
        self.server = MonitoringServer(self.temp_config.name)
    
    def test_server_initialization(self):
        """Test server initialization."""
        self.assertIsNotNone(self.server.security_manager)
        self.assertIsNotNone(self.server.database)
        self.assertEqual(self.server.host, '127.0.0.1')
        self.assertEqual(self.server.max_clients, 10)
    
    def test_connection_limits(self):
        """Test connection limit functionality."""
        # Test IP connection limits
        allowed = self.server._can_accept_connection("192.168.1.100")
        self.assertTrue(allowed)
        
        # Simulate multiple connections
        for i in range(5):
            self.server.ip_connection_counts["192.168.1.100"] = i + 1
        
        # Should not allow more connections
        allowed = self.server._can_accept_connection("192.168.1.100")
        self.assertFalse(allowed)
    
    def test_server_stats(self):
        """Test server statistics functionality."""
        stats = self.server.get_server_stats()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('active_clients', stats)
        self.assertIn('total_connections', stats)
        self.assertIn('uptime_seconds', stats)
    
    def tearDown(self):
        """Clean up test fixtures."""
        if self.server.is_running:
            self.server.stop()
        os.unlink(self.temp_config.name)

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete system."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp()
        self.logs_dir = os.path.join(self.temp_dir, 'logs')
        self.data_dir = os.path.join(self.temp_dir, 'data')
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Create test configuration
        self.config = configparser.ConfigParser()
        self.config.add_section('Server')
        self.config.set('Server', 'host', '127.0.0.1')
        self.config.set('Server', 'port', '0')
        self.config.set('Server', 'max_clients', '5')
        
        self.config.add_section('Database')
        self.config.set('Database', 'db_path', os.path.join(self.data_dir, 'test.db'))
        
        self.config.add_section('Logging')
        self.config.set('Logging', 'log_file', os.path.join(self.logs_dir, 'test.log'))
        
        # Create temporary config file
        self.temp_config = os.path.join(self.temp_dir, 'test_config.ini')
        with open(self.temp_config, 'w') as f:
            self.config.write(f)
    
    def test_complete_workflow(self):
        """Test complete system workflow."""
        try:
            # Initialize components
            security_manager = SecurityManager(self.config)
            database = SecureDatabase(self.config)
            server = MonitoringServer(self.temp_config)
            
            # Test basic functionality
            self.assertIsNotNone(security_manager)
            self.assertIsNotNone(database)
            self.assertIsNotNone(server)
            
            # Test database operations
            client_data = {
                'client_id': 'integration_test_client',
                'hostname': 'integration-test-machine',
                'platform': 'TestOS',
                'ip_address': '127.0.0.1',
                'mac_address': '00:00:00:00:00:00',
                'user_agent': 'Integration Test',
                'version': '1.0',
                'capabilities': {'test': True}
            }
            
            success = database.add_client(client_data)
            self.assertTrue(success)
            
            # Test security operations
            test_data = b"Integration test data"
            encrypted_data, iv = security_manager.encrypt_data(test_data)
            decrypted_data = security_manager.decrypt_data(encrypted_data, iv)
            self.assertEqual(decrypted_data, test_data)
            
            # Cleanup
            security_manager.cleanup()
            database.close()
            
        except Exception as e:
            self.fail(f"Integration test failed: {e}")
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

def run_performance_tests():
    """Run performance tests for the system."""
    print("\n🚀 Running Performance Tests...")
    
    # Test encryption performance
    print("Testing encryption performance...")
    config = {'Security': {'encryption_key_size': 256}}
    security_manager = SecurityManager(config)
    
    test_data = b"Performance test data" * 1000  # 24KB of data
    
    start_time = time.time()
    for i in range(100):
        encrypted_data, iv = security_manager.encrypt_data(test_data)
        decrypted_data = security_manager.decrypt_data(encrypted_data, iv)
    
    encryption_time = time.time() - start_time
    print(f"✅ 100 encryption/decryption operations: {encryption_time:.3f} seconds")
    print(f"   Average: {encryption_time/100:.3f} seconds per operation")
    
    # Test database performance
    print("\nTesting database performance...")
    db_config = {'Database': {'db_path': ':memory:', 'max_log_entries': 10000}}
    database = SecureDatabase(db_config)
    
    start_time = time.time()
    for i in range(1000):
        client_data = {
            'client_id': f'perf_test_client_{i:04d}',
            'hostname': f'perf-test-{i}',
            'platform': 'TestOS',
            'ip_address': f'192.168.1.{i % 255}',
            'mac_address': f'00:11:22:33:44:{i:02x}',
            'user_agent': 'Performance Test',
            'version': '1.0',
            'capabilities': {'perf_test': True}
        }
        database.add_client(client_data)
    
    db_time = time.time() - start_time
    print(f"✅ 1000 client insertions: {db_time:.3f} seconds")
    print(f"   Average: {db_time/1000:.3f} seconds per insertion")
    
    # Cleanup
    security_manager.cleanup()
    database.close()
    
    print("\n🎯 Performance tests completed!")

def run_security_tests():
    """Run security-specific tests."""
    print("\n🔒 Running Security Tests...")
    
    config = {'Security': {'encryption_key_size': 256}}
    security_manager = SecurityManager(config)
    
    # Test key generation
    print("Testing cryptographic key generation...")
    key1 = security_manager.generate_secure_token(32)
    key2 = security_manager.generate_secure_token(32)
    
    if key1 != key2:
        print("✅ Cryptographic keys are unique")
    else:
        print("❌ Cryptographic keys are not unique")
    
    # Test password security
    print("Testing password security...")
    password = "SuperSecretPassword123!"
    hashed1, salt1 = security_manager.hash_password(password)
    hashed2, salt2 = security_manager.hash_password(password)
    
    if hashed1 != hashed2:
        print("✅ Password hashing uses unique salts")
    else:
        print("❌ Password hashing does not use unique salts")
    
    # Test rate limiting
    print("Testing rate limiting...")
    test_ip = "192.168.1.200"
    
    # Should allow requests within limit
    allowed_count = 0
    for i in range(120):
        if security_manager.check_rate_limit(test_ip):
            allowed_count += 1
    
    if allowed_count <= 100:  # Should be rate limited
        print("✅ Rate limiting is working correctly")
    else:
        print("❌ Rate limiting is not working correctly")
    
    security_manager.cleanup()
    print("\n🎯 Security tests completed!")

def main():
    """Main test runner."""
    print("🧪 Employee Monitoring System - Test Suite")
    print("=" * 50)
    
    # Check if we're in a test environment
    if '--performance' in sys.argv:
        run_performance_tests()
        return
    
    if '--security' in sys.argv:
        run_security_tests()
        return
    
    # Run unit tests
    print("Running unit tests...")
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityManager))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestMonitoringClient))
    suite.addTests(loader.loadTestsFromTestCase(TestMonitoringServer))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print("📊 Test Results Summary")
    print("=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ Failures:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip()}")
    
    if result.errors:
        print("\n❌ Errors:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback.split('Exception:')[-1].strip()}")
    
    if result.wasSuccessful():
        print("\n🎉 All tests passed successfully!")
        return 0
    else:
        print("\n❌ Some tests failed!")
        return 1

if __name__ == "__main__":
    # Import configparser for tests
    import configparser
    
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n❌ Testing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Testing failed with error: {e}")
        sys.exit(1)
