"""
Database Module for Employee Monitoring System
Provides secure database operations with prepared statements and audit logging.
"""

import sqlite3
import logging
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import os
import platform
import uuid

# Import our custom logging system
try:
    from logging_config import get_logger
    logger = get_logger('database')
except ImportError as e:
    # Fallback to basic logging if custom system not available
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

class SecureDatabase:
    """
    Secure database manager providing prepared statements, audit logging,
    and cross-platform database operations for the monitoring system.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the secure database manager.
        
        Args:
            config: Configuration dictionary containing database parameters
        """
        self.config = config
        self.db_path = config.get('Database', 'db_path', fallback='monitoring.db')
        self.max_log_entries = config.getint('Database', 'max_log_entries', fallback=10000)
        self.log_retention_days = config.getint('Database', 'log_retention_days', fallback=90)
        
        # Initialize database connection
        import threading
        self._conn_lock = threading.Lock()
        self._init_database()
        
        # Create tables with proper schema
        self._create_tables()
        
        # Initialize security manager for field-level encryption
        try:
            from security import SecurityManager
            self.security = SecurityManager(config)
        except Exception as e:
            logger.error(f"Failed to initialize SecurityManager for DB encryption: {e}")
            self.security = None

        logger.info(f"Secure database initialized: {self.db_path}")
    
    def _init_database(self):
        """Initialize database connection with security features."""
        try:
            # Create database directory if it doesn't exist
            db_dir = os.path.dirname(self.db_path)
            if db_dir and not os.path.exists(db_dir):
                os.makedirs(db_dir, mode=0o700)  # Secure permissions
            
            # Connect to database with security features
            self.conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                check_same_thread=False
            )
            
            # Enable foreign keys and WAL mode for better security
            self.conn.execute("PRAGMA foreign_keys = ON")
            self.conn.execute("PRAGMA journal_mode = WAL")
            self.conn.execute("PRAGMA synchronous = NORMAL")
            self.conn.execute("PRAGMA cache_size = 10000")
            self.conn.execute("PRAGMA temp_store = MEMORY")
            
            # Set secure file permissions on Unix-like systems
            if isinstance(platform.system(), str) and platform.system().lower() in ['linux', 'darwin']:
                try:
                    os.chmod(self.db_path, 0o600)  # Owner read/write only
                except Exception as e:
                    logger.warning(f"Could not set secure file permissions: {e}")
            
            logger.info("Database connection established with security features")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    def _ensure_connection(self):
        """Ensure database connection is active, reconnect if necessary."""
        try:
            with self._conn_lock:
                if not hasattr(self, 'conn') or self.conn is None:
                    logger.info("Database connection lost, reconnecting...")
                    self._init_database()
                    return True
            
            # Test if connection is still valid
            try:
                self.conn.execute("SELECT 1")
                return True
            except (sqlite3.OperationalError, sqlite3.DatabaseError, AttributeError):
                logger.info("Database connection invalid, reconnecting...")
                try:
                    self.conn.close()
                except Exception as e_close:
                    logger.debug(f"Error closing DB during reconnect: {e_close}", exc_info=True)
                self._init_database()
                return True
                
        except Exception as e:
            logger.error(f"Failed to ensure database connection: {e}", exc_info=True)
            return False
    
    def _create_tables(self):
        """Create database tables with proper schema and constraints."""
        try:
            # Clients table for storing client information
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT UNIQUE NOT NULL,
                    device_label TEXT,
                    hostname TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    logged_in_user TEXT,
                    user_agent TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active',
                    version TEXT,
                    capabilities TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Sessions table for authentication and session management
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_token TEXT UNIQUE NOT NULL,
                    client_id TEXT NOT NULL,
                    user_id TEXT,
                    ip_address TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
                )
            """)
            
            # Screen captures table for storing monitoring data
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS screen_captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    capture_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    image_data BLOB,
                    image_size INTEGER,
                    compression_ratio REAL,
                    processing_time_ms INTEGER,
                    metadata TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
                )
            """)
            
            # Activity logs table for comprehensive audit trail
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    client_id TEXT,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    severity TEXT DEFAULT 'info',
                    category TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
                )
            """)
            
            # Security events table for security monitoring
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    client_id TEXT,
                    ip_address TEXT,
                    description TEXT,
                    metadata TEXT,
                    resolved BOOLEAN DEFAULT 0,
                    resolved_at TIMESTAMP,
                    resolved_by TEXT,
                    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
                )
            """)
            
            # Chat messages table for storing client-server communication
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    -- Extended message tracking
                    message_id TEXT,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    delivered_at TIMESTAMP, -- when popup is first shown on client
                    read_at TIMESTAMP,      -- when user closes popup or replies
                    awaiting_delivery INTEGER DEFAULT 0, -- queued while client offline
                    deleted INTEGER DEFAULT 0,           -- soft delete flag
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
                )
            """)
            
            # Client logs table for storing logs sent by clients
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS client_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    logger_name TEXT,
                    module TEXT,
                    function TEXT,
                    line INTEGER,
                    ip_address TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
                )
            """)

            # Exec results table
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS exec_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    command_id TEXT,
                    cmd TEXT,
                    exit_code INTEGER,
                    stdout TEXT,
                    stderr TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
                )
            """)
            
            # File operations table for storing file system operations
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS file_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients (client_id) ON DELETE CASCADE
                )
            """)
            
            # Create indexes for better performance
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_client_id ON clients(client_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_clients_ip_address ON clients(ip_address)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_client_id ON sessions(client_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_screen_captures_client_id ON screen_captures(client_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_screen_captures_timestamp ON screen_captures(capture_timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_logs_client_id ON activity_logs(client_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_client_id ON chat_messages(client_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_messages_timestamp ON chat_messages(timestamp)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_file_operations_client_id ON file_operations(client_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_file_operations_type ON file_operations(operation_type)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_client_logs_client_id ON client_logs(client_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_client_logs_created_at ON client_logs(created_at)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_exec_results_client_id ON exec_results(client_id)")
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_exec_results_cmd ON exec_results(cmd)")
            
            # Commit the table creation
            self.conn.commit()
            
            logger.info("Database tables created successfully with proper schema")
            
        except Exception as e:
            logger.error(f"Table creation failed: {e}")
            raise

        # Run lightweight migrations that add columns if they're missing (backward compatible)
        try:
            cursor = self.conn.cursor()
            # clients table migrations for new columns
            try:
                cursor.execute("PRAGMA table_info(clients)")
                client_cols = {row[1] for row in cursor.fetchall()}
                if 'device_label' not in client_cols:
                    self.conn.execute("ALTER TABLE clients ADD COLUMN device_label TEXT")
                if 'logged_in_user' not in client_cols:
                    self.conn.execute("ALTER TABLE clients ADD COLUMN logged_in_user TEXT")
                if 'uptime_seconds' not in client_cols:
                    self.conn.execute("ALTER TABLE clients ADD COLUMN uptime_seconds INTEGER")
            except Exception:
                pass
            self.conn.commit()
            cursor.execute("PRAGMA table_info(chat_messages)")
            cols = {row[1] for row in cursor.fetchall()}
            migrations: List[Tuple[str, str]] = []
            if 'message_id' not in cols:
                migrations.append((
                    'message_id',
                    "ALTER TABLE chat_messages ADD COLUMN message_id TEXT"
                ))
            if 'sent_at' not in cols:
                migrations.append((
                    'sent_at',
                    "ALTER TABLE chat_messages ADD COLUMN sent_at TIMESTAMP"
                ))
            if 'delivered_at' not in cols:
                migrations.append((
                    'delivered_at',
                    "ALTER TABLE chat_messages ADD COLUMN delivered_at TIMESTAMP"
                ))
            if 'read_at' not in cols:
                migrations.append((
                    'read_at',
                    "ALTER TABLE chat_messages ADD COLUMN read_at TIMESTAMP"
                ))
            if 'awaiting_delivery' not in cols:
                migrations.append((
                    'awaiting_delivery',
                    "ALTER TABLE chat_messages ADD COLUMN awaiting_delivery INTEGER DEFAULT 0"
                ))
            if 'deleted' not in cols:
                migrations.append((
                    'deleted',
                    "ALTER TABLE chat_messages ADD COLUMN deleted INTEGER DEFAULT 0"
                ))
            for _, stmt in migrations:
                try:
                    self.conn.execute(stmt)
                except Exception:
                    pass
            if migrations:
                self.conn.commit()
        except Exception as e:
            logger.error(f"Chat message schema migration failed: {e}")
    
    def add_client(self, client_data: Dict[str, Any]) -> bool:
        """
        Add a new client to the database using prepared statements.
        
        Args:
            client_data: Dictionary containing client information
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Prepare the SQL statement with placeholders
            sql = """
                INSERT OR REPLACE INTO clients (
                    client_id, device_label, hostname, platform, ip_address, mac_address,
                    logged_in_user, user_agent, version, capabilities, last_seen, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            # Execute with prepared statement
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                client_data.get('client_id'),
                client_data.get('device_label'),
                client_data.get('hostname'),
                client_data.get('platform'),
                client_data.get('ip_address'),
                client_data.get('mac_address'),
                client_data.get('logged_in_user'),
                client_data.get('user_agent'),
                client_data.get('version'),
                json.dumps(client_data.get('capabilities', {})),
                datetime.now(),
                datetime.now()
            ))
            
            # Log the activity
            self._log_activity(
                client_id=client_data.get('client_id'),
                action='client_registered',
                details=f"New client registered: {client_data.get('hostname')}",
                severity='info'
            )
            
            self.conn.commit()
            logger.info(f"Client added successfully: {client_data.get('client_id')}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add client: {e}")
            self.conn.rollback()
            return False
    
    def update_client_status(self, client_id: str, status: str, **kwargs) -> bool:
        """
        Update client status and information using prepared statements.
        
        Args:
            client_id: Unique identifier for the client
            status: New status for the client
            **kwargs: Additional fields to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Build dynamic update query
            update_fields = ['status = ?', 'last_seen = ?', 'updated_at = ?']
            update_values = [status, datetime.now(), datetime.now()]
            
            for key, value in kwargs.items():
                if key in ['hostname', 'platform', 'ip_address', 'version', 'capabilities']:
                    update_fields.append(f"{key} = ?")
                    if key == 'capabilities':
                        update_values.append(json.dumps(value))
                    else:
                        update_values.append(value)
            
            sql = f"UPDATE clients SET {', '.join(update_fields)} WHERE client_id = ?"
            update_values.append(client_id)
            
            # Execute with prepared statement
            cursor = self.conn.cursor()
            cursor.execute(sql, update_values)
            
            if cursor.rowcount > 0:
                # Log the activity
                self._log_activity(
                    client_id=client_id,
                    action='client_updated',
                    details=f"Client status updated to: {status}",
                    severity='info'
                )
                
                self.conn.commit()
                logger.info(f"Client status updated: {client_id} -> {status}")
                return True
            else:
                logger.warning(f"Client not found for update: {client_id}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to update client status: {e}")
            self.conn.rollback()
            return False
    
    def store_screen_capture(self, client_id: str, image_data: bytes, 
                           metadata: Dict[str, Any]) -> bool:
        """
        Store screen capture data using prepared statements.
        
        Args:
            client_id: Unique identifier for the client
            image_data: Binary image data
            metadata: Additional metadata about the capture
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Calculate image size and compression ratio
            original_size = len(image_data)
            compressed_size = len(image_data)  # Assuming data is already compressed
            
            sql = """
                INSERT INTO screen_captures (
                    client_id, image_data, image_size, compression_ratio,
                    processing_time_ms, metadata
                ) VALUES (?, ?, ?, ?, ?, ?)
            """
            
            # Execute with prepared statement
            cursor = self.conn.cursor()
            # Encrypt the image blob if security is available
            if self.security:
                enc_blob = self.security.encrypt_blob_for_db(image_data)
            else:
                enc_blob = image_data

            cursor.execute(sql, (
                client_id,
                enc_blob,
                original_size,
                compressed_size / original_size if original_size > 0 else 1.0,
                metadata.get('processing_time_ms', 0),
                json.dumps(metadata)
            ))
            
            # Clean up old captures to maintain database size
            self._cleanup_old_captures()
            
            self.conn.commit()
            logger.debug(f"Screen capture stored for client: {client_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store screen capture: {e}")
            self.conn.rollback()
            return False
    
    def create_session(self, session_token: str, client_id: str, 
                      user_id: str, ip_address: str, 
                      expires_in_hours: int = 24) -> bool:
        """
        Create a new session using prepared statements.
        
        Args:
            session_token: Secure session token
            client_id: Client identifier
            user_id: User identifier
            ip_address: IP address of the session
            expires_in_hours: Session expiration time in hours
            
        Returns:
            True if successful, False otherwise
        """
        try:
            expires_at = datetime.now() + timedelta(hours=expires_in_hours)
            
            sql = """
                INSERT INTO sessions (
                    session_token, client_id, user_id, ip_address, expires_at
                ) VALUES (?, ?, ?, ?, ?)
            """
            
            # Execute with prepared statement
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                session_token,
                client_id,
                user_id,
                ip_address,
                expires_at
            ))
            
            # Log the session creation
            self._log_activity(
                client_id=client_id,
                user_id=user_id,
                action='session_created',
                details=f"Session created, expires: {expires_at}",
                severity='info'
            )
            
            self.conn.commit()
            logger.info(f"Session created for client: {client_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            self.conn.rollback()
            return False
    
    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """
        Validate session token and return session information.
        
        Args:
            session_token: Session token to validate
            
        Returns:
            Session information if valid, None otherwise
        """
        try:
            sql = """
                SELECT s.*, c.hostname, c.platform 
                FROM sessions s
                JOIN clients c ON s.client_id = c.client_id
                WHERE s.session_token = ? AND s.is_active = 1 AND s.expires_at > ?
            """
            
            # Execute with prepared statement
            cursor = self.conn.cursor()
            cursor.execute(sql, (session_token, datetime.now()))
            
            row = cursor.fetchone()
            if row:
                # Update last activity
                self._update_session_activity(session_token)
                
                # Return session data
                columns = [description[0] for description in cursor.description]
                session_data = dict(zip(columns, row))
                
                logger.debug(f"Session validated: {session_token}")
                return session_data
            else:
                logger.warning(f"Invalid or expired session: {session_token}")
                return None
                
        except Exception as e:
            logger.error(f"Session validation failed: {e}")
            return None
    
    def _update_session_activity(self, session_token: str):
        """Update session last activity timestamp."""
        try:
            sql = "UPDATE sessions SET last_activity = ? WHERE session_token = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (datetime.now(), session_token))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to update session activity: {e}")
    
    def _log_activity(self, client_id: Optional[str] = None, 
                     user_id: Optional[str] = None, action: str = '', 
                     details: str = '', severity: str = 'info',
                     ip_address: Optional[str] = None, 
                     user_agent: Optional[str] = None,
                     category: Optional[str] = None):
        """
        Log activity using prepared statements for audit trail.
        
        Args:
            client_id: Client identifier
            user_id: User identifier
            action: Action performed
            details: Detailed description
            severity: Log severity level
            ip_address: IP address
            user_agent: User agent string
            category: Activity category
        """
        try:
            sql = """
                INSERT INTO activity_logs (
                    client_id, user_id, action, details, ip_address,
                    user_agent, severity, category
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                client_id, user_id, action, details, ip_address,
                user_agent, severity, category
            ))
            
            # Clean up old logs to maintain database size
            self._cleanup_old_logs()
            
        except Exception as e:
            logger.error(f"Failed to log activity: {e}")
    
    def log_security_event(self, event_type: str, severity: str, 
                          description: str, client_id: Optional[str] = None,
                          ip_address: Optional[str] = None,
                          metadata: Optional[Dict[str, Any]] = None):
        """
        Log security events using prepared statements.
        
        Args:
            event_type: Type of security event
            severity: Event severity
            description: Event description
            client_id: Client identifier
            ip_address: IP address
            metadata: Additional metadata
        """
        try:
            sql = """
                INSERT INTO security_events (
                    event_type, severity, client_id, ip_address,
                    description, metadata
                ) VALUES (?, ?, ?, ?, ?, ?)
            """
            
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                event_type,
                severity,
                client_id,
                ip_address,
                description,
                json.dumps(metadata) if metadata else None
            ))
            
            # Log the security event in activity logs as well
            self._log_activity(
                client_id=client_id,
                action=f'security_event_{event_type}',
                details=description,
                severity=severity,
                ip_address=ip_address,
                category='security'
            )
            
            self.conn.commit()
            logger.warning(f"Security event logged: {event_type} - {description}")
            
        except Exception as e:
            logger.error(f"Failed to log security event: {e}")
    
    def get_active_clients(self) -> List[Dict[str, Any]]:
        """
        Get list of active clients using prepared statements.
        
        Returns:
            List of active client dictionaries
        """
        try:
            if not self._ensure_connection():
                return []
                
            sql = """
                SELECT * FROM clients 
                WHERE status = 'active' 
                ORDER BY last_seen DESC
            """
            
            cursor = self.conn.cursor()
            cursor.execute(sql)
            
            columns = [description[0] for description in cursor.description]
            clients = []
            
            for row in cursor.fetchall():
                client_data = dict(zip(columns, row))
                # Parse JSON fields
                if client_data.get('capabilities'):
                    try:
                        client_data['capabilities'] = json.loads(client_data['capabilities'])
                    except:
                        client_data['capabilities'] = {}
                clients.append(client_data)
            
            return clients
            
        except Exception as e:
            logger.error(f"Failed to get active clients: {e}")
            return []
    
    def get_client_captures(self, client_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent screen captures for a specific client.
        
        Args:
            client_id: Client identifier
            limit: Maximum number of captures to return
            
        Returns:
            List of capture dictionaries
        """
        try:
            sql = """
                SELECT * FROM screen_captures 
                WHERE client_id = ? 
                ORDER BY capture_timestamp DESC 
                LIMIT ?
            """
            
            cursor = self.conn.cursor()
            cursor.execute(sql, (client_id, limit))
            
            columns = [description[0] for description in cursor.description]
            captures = []
            
            for row in cursor.fetchall():
                capture_data = dict(zip(columns, row))
                # Decrypt blob if possible
                try:
                    if capture_data.get('image_data') and self.security:
                        capture_data['image_data'] = self.security.decrypt_blob_from_db(capture_data['image_data'])
                except Exception as e:
                    logger.warning(f"Failed to decrypt image blob: {e}")
                # Parse JSON fields
                if capture_data.get('metadata'):
                    try:
                        capture_data['metadata'] = json.loads(capture_data['metadata'])
                    except:
                        capture_data['metadata'] = {}
                captures.append(capture_data)
            
            return captures
            
        except Exception as e:
            logger.error(f"Failed to get client captures: {e}")
            return []
    
    def _cleanup_old_captures(self):
        """Clean up old screen captures to maintain database size."""
        try:
            # Keep only recent captures
            cutoff_date = datetime.now() - timedelta(days=7)
            
            sql = "DELETE FROM screen_captures WHERE capture_timestamp < ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (cutoff_date,))
            
            deleted_count = cursor.rowcount
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old screen captures")
                
        except Exception as e:
            logger.error(f"Failed to cleanup old captures: {e}")
    
    def _cleanup_old_logs(self):
        """Clean up old activity logs to maintain database size."""
        try:
            # Keep only recent logs
            cutoff_date = datetime.now() - timedelta(days=self.log_retention_days)
            
            sql = "DELETE FROM activity_logs WHERE timestamp < ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (cutoff_date,))
            
            deleted_count = cursor.rowcount
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old activity logs")
                
        except Exception as e:
            logger.error(f"Failed to cleanup old logs: {e}")
    
    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get database statistics for monitoring and maintenance.
        
        Returns:
            Dictionary containing database statistics
        """
        try:
            if not self._ensure_connection():
                return {}
                
            stats = {}
            
            # Get table row counts using a whitelist and fixed queries (no dynamic SQL)
            table_queries = {
                'clients': "SELECT COUNT(*) FROM clients",
                'sessions': "SELECT COUNT(*) FROM sessions",
                'screen_captures': "SELECT COUNT(*) FROM screen_captures",
                'activity_logs': "SELECT COUNT(*) FROM activity_logs",
                'security_events': "SELECT COUNT(*) FROM security_events",
            }
            for table_name, query in table_queries.items():
                cursor = self.conn.cursor()
                cursor.execute(query)
                stats[f'{table_name}_count'] = cursor.fetchone()[0]
            
            # Get database size
            if os.path.exists(self.db_path):
                stats['database_size_mb'] = round(os.path.getsize(self.db_path) / (1024 * 1024), 2)
            
            # Get recent activity
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM activity_logs 
                WHERE timestamp > datetime('now', '-1 hour')
            """)
            stats['recent_activity_count'] = cursor.fetchone()[0]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {}
    
    def store_chat_message(self, client_id: str, message: str, timestamp: str, direction: str,
                           message_id: Optional[str] = None,
                           awaiting_delivery: bool = False) -> str:
        """
        Store a chat message in the database.
        
        Args:
            client_id: ID of the client
            message: The message content
            timestamp: Message timestamp
            direction: 'server_to_client' or 'client_to_server'
            message_id: Optional unique message id to correlate status updates
            awaiting_delivery: If True, marks message as queued until client is online
        
        Returns:
            message_id used for this row (generated if not provided)
        """
        try:
            if not self._ensure_connection():
                return message_id or ""
                
            sql = """
                INSERT INTO chat_messages (
                    client_id, message, timestamp, direction,
                    message_id, sent_at, delivered_at, read_at,
                    awaiting_delivery, deleted, created_at
                ) VALUES (
                    ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, NULL, NULL, ?, 0, CURRENT_TIMESTAMP
                )
            """
            # Encrypt message text for at-rest protection
            enc_message = self.security.encrypt_for_db(message) if self.security else message
            cursor = self.conn.cursor()
            mid = message_id or str(uuid.uuid4())
            cursor.execute(sql, (
                client_id, enc_message, timestamp, direction,
                mid,
                1 if awaiting_delivery else 0
            ))
            self.conn.commit()
            
            logger.info(f"Chat message stored for client {client_id}: {direction}")
            return mid

        except Exception as e:
            logger.error(f"Failed to store chat message: {e}")
            return message_id or ""

    def store_client_log(self, client_id: str, level: str, message: str,
                         logger_name: Optional[str] = None,
                         timestamp: Optional[str] = None,
                         module: Optional[str] = None,
                         function: Optional[str] = None,
                         line: Optional[int] = None,
                         ip_address: Optional[str] = None) -> bool:
        """Store a client-originated log record securely using prepared statements."""
        try:
            if not self._ensure_connection():
                return False
            sql = (
                "INSERT INTO client_logs (client_id, level, message, logger_name, module, function, line, ip_address, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))"
            )
            enc_message = self.security.encrypt_for_db(message) if self.security else message
            self.conn.execute(sql, (
                client_id, level, enc_message[:2000], logger_name, module, function,
                int(line) if isinstance(line, int) else None, ip_address, timestamp
            ))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to store client log: {e}")
            return False

    def mark_message_delivered(self, message_id: str) -> None:
        """Mark a message as delivered (popup shown on client)."""
        try:
            if not self._ensure_connection():
                return
            sql = "UPDATE chat_messages SET delivered_at = ?, awaiting_delivery = 0 WHERE message_id = ? AND deleted = 0"
            self.conn.execute(sql, (datetime.now().isoformat(), message_id))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to mark message delivered: {e}")

    def mark_message_read(self, message_id: str) -> None:
        """Mark a message as read by the user."""
        try:
            if not self._ensure_connection():
                return
            sql = "UPDATE chat_messages SET read_at = ? WHERE message_id = ? AND deleted = 0"
            self.conn.execute(sql, (datetime.now().isoformat(), message_id))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to mark message read: {e}")

    def soft_delete_message(self, message_id: str) -> None:
        """Soft-delete a message by setting deleted=1."""
        try:
            if not self._ensure_connection():
                return
            self.conn.execute("UPDATE chat_messages SET deleted = 1 WHERE message_id = ?", (message_id,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to soft delete message: {e}")

    def get_undelivered_messages(self, client_id: str) -> List[Dict[str, Any]]:
        """Fetch server->client messages that have not been delivered yet (for offline queue)."""
        try:
            if not self._ensure_connection():
                return []
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT message_id, message, timestamp
                FROM chat_messages
                WHERE client_id = ? AND direction = 'server_to_client'
                  AND (delivered_at IS NULL OR awaiting_delivery = 1)
                  AND deleted = 0
                ORDER BY id ASC
                """,
                (client_id,)
            )
            rows = cursor.fetchall()
            result: List[Dict[str, Any]] = []
            for mid, enc_message, ts in rows:
                try:
                    dec_message = self.security.decrypt_from_db(enc_message) if self.security else enc_message
                except Exception:
                    dec_message = enc_message
                result.append({'message_id': mid, 'message': dec_message, 'timestamp': ts})
            return result
        except Exception as e:
            logger.error(f"Failed to get undelivered messages: {e}")
            return []
    
    def store_file_list_response(self, client_id: str, directory_path: str, files: list, directories: list):
        """
        Store file list response in the database.
        
        Args:
            client_id: ID of the client
            directory_path: Path of the directory
            files: List of file information
            directories: List of directory names
        """
        try:
            if not self._ensure_connection():
                return
                
            sql = """
                INSERT INTO file_operations (client_id, operation_type, file_path, details, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """
            details = json.dumps({
                'files': files,
                'directories': directories,
                'total_files': len(files),
                'total_directories': len(directories)
            })
            cursor = self.conn.cursor()
            cursor.execute(sql, (client_id, 'list_directory', directory_path, details))
            self.conn.commit()
            
            logger.info(f"File list response stored for client {client_id}: {directory_path}")
            
        except Exception as e:
            logger.error(f"Failed to store file list response: {e}")
    
    def store_file_content_response(self, client_id: str, file_path: str, content: str, file_size: int, is_binary: bool):
        """
        Store file content response in the database.
        
        Args:
            client_id: ID of the client
            file_path: Path of the file
            content: File content (base64 encoded for binary files)
            file_size: Size of the file in bytes
            is_binary: Whether the file is binary
        """
        try:
            if not self._ensure_connection():
                return
                
            sql = """
                INSERT INTO file_operations (client_id, operation_type, file_path, details, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """
            details = json.dumps({
                'file_size': file_size,
                'is_binary': is_binary,
                'content_preview': content[:1000] if not is_binary else '[Binary Content]'
            })
            cursor = self.conn.cursor()
            cursor.execute(sql, (client_id, 'view_file', file_path, details))
            self.conn.commit()
            
            logger.info(f"File content response stored for client {client_id}: {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to store file content response: {e}")
    
    def store_file_operation_response(self, client_id: str, operation: str, file_path: str, status: str, message: str):
        """
        Store file operation response in the database.
        
        Args:
            client_id: ID of the client
            operation: Type of operation performed
            file_path: Path of the file
            status: Status of the operation
            message: Additional message or error details
        """
        try:
            if not self._ensure_connection():
                return
                
            sql = """
                INSERT INTO file_operations (client_id, operation_type, file_path, details, created_at)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """
            details = json.dumps({
                'status': status,
                'message': message,
                'operation': operation
            })
            cursor = self.conn.cursor()
            cursor.execute(sql, (client_id, operation, file_path, details))
            self.conn.commit()
            
            logger.info(f"File operation response stored for client {client_id}: {operation} on {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to store file operation response: {e}")

    def store_exec_result(self, client_id: str, command_id: str, exit_code: int, stdout: str, stderr: str, cmd: str, timestamp: Optional[str] = None) -> bool:
        """Store exec results from a client with prepared statements and encryption for outputs."""
        try:
            if not self._ensure_connection():
                return False
            sql = (
                "INSERT INTO exec_results (client_id, command_id, cmd, exit_code, stdout, stderr, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))"
            )
            enc_out = self.security.encrypt_for_db(stdout) if self.security else stdout
            enc_err = self.security.encrypt_for_db(stderr) if self.security else stderr
            self.conn.execute(sql, (client_id, command_id, cmd, int(exit_code), enc_out[:200000], enc_err[:200000], timestamp))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to store exec result: {e}")
            return False
    
    # Database Viewer Methods
    def get_all_clients(self) -> List[Dict[str, Any]]:
        """Get all clients from the database."""
        try:
            if not self._ensure_connection():
                return []
                
            sql = """
                SELECT client_id, hostname, platform, status, last_seen, ip_address,
                       logged_in_user, mac_address, uptime_seconds
                FROM clients
                ORDER BY last_seen DESC
            """
            cursor = self.conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            clients = []
            for row in rows:
                clients.append({
                    'client_id': row[0],
                    'hostname': row[1],
                    'platform': row[2],
                    'status': row[3],
                    'last_seen': row[4],
                    'ip_address': row[5],
                    'logged_in_user': row[6],
                    'mac_address': row[7],
                    'uptime_seconds': row[8]
                })
            
            return clients
            
        except Exception as e:
            logger.error(f"Failed to get all clients: {e}")
            return []
    
    def get_all_sessions(self) -> List[Dict[str, Any]]:
        """Get all sessions from the database."""
        try:
            if not self._ensure_connection():
                return []
                
            sql = """
                SELECT id, session_token, client_id, created_at, expires_at, last_activity
                FROM sessions
                ORDER BY created_at DESC
            """
            cursor = self.conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            sessions = []
            for row in rows:
                sessions.append({
                    'id': row[0],
                    'session_token': row[1],
                    'client_id': row[2],
                    'created_at': row[3],
                    'expires_at': row[4],
                    'last_activity': row[5]
                })
            
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get all sessions: {e}")
            return []
    
    def get_all_screen_captures(self) -> List[Dict[str, Any]]:
        """Get all screen captures from the database."""
        try:
            if not self._ensure_connection():
                return []
                
            sql = """
                SELECT id, client_id, capture_timestamp, image_size, compression_ratio, processing_time_ms, metadata
                FROM screen_captures
                ORDER BY capture_timestamp DESC
            """
            cursor = self.conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            captures = []
            for row in rows:
                captures.append({
                    'id': row[0],
                    'client_id': row[1],
                    'capture_timestamp': row[2],
                    'image_size': row[3],
                    'compression_ratio': row[4],
                    'processing_time_ms': row[5],
                    'metadata': row[6]
                })
            
            return captures
            
        except Exception as e:
            logger.error(f"Failed to get all screen captures: {e}")
            return []
    
    def get_all_chat_messages(self) -> List[Dict[str, Any]]:
        """Get all chat messages from the database."""
        try:
            if not self._ensure_connection():
                return []
                
            sql = """
                SELECT id, client_id, direction, message, timestamp
                FROM chat_messages
                ORDER BY timestamp DESC
            """
            cursor = self.conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            messages = []
            for row in rows:
                msg = row[3]
                if self.security:
                    try:
                        msg = self.security.decrypt_from_db(msg)
                    except Exception as e:
                        logger.warning(f"Failed to decrypt chat message id={row[0]}: {e}")
                messages.append({
                    'id': row[0],
                    'client_id': row[1],
                    'direction': row[2],
                    'message': msg,
                    'timestamp': row[4]
                })
            
            return messages
            
        except Exception as e:
            logger.error(f"Failed to get all chat messages: {e}")
            return []
    
    def get_all_file_operations(self) -> List[Dict[str, Any]]:
        """Get all file operations from the database."""
        try:
            if not self._ensure_connection():
                return []
                
            sql = """
                SELECT id, client_id, operation_type, file_path, details, created_at
                FROM file_operations
                ORDER BY created_at DESC
            """
            cursor = self.conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            operations = []
            for row in rows:
                details = json.loads(row[4]) if row[4] else {}
                operations.append({
                    'id': row[0],
                    'client_id': row[1],
                    'operation_type': row[2],
                    'file_path': row[3],
                    'details': details.get('status', 'unknown') if isinstance(details, dict) else str(details),
                    'created_at': row[5]
                })
            
            return operations
            
        except Exception as e:
            logger.error(f"Failed to get all file operations: {e}")
            return []
    
    def get_all_security_logs(self) -> List[Dict[str, Any]]:
        """Get all security logs from the database."""
        try:
            sql = """
                SELECT id, event_type, client_id, description, timestamp
                FROM security_events
                ORDER BY timestamp DESC
            """
            cursor = self.conn.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            logs = []
            for row in rows:
                logs.append({
                    'id': row[0],
                    'event_type': row[1],
                    'client_id': row[2],
                    'description': row[3],
                    'timestamp': row[4]
                })
            
            return logs
            
        except Exception as e:
            logger.error(f"Failed to get all security logs: {e}")
            return []
    
    def get_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific client by ID."""
        try:
            if not self._ensure_connection():
                return None
                
            sql = "SELECT client_id, hostname, platform, status, last_seen, ip_address FROM clients WHERE client_id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (client_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'client_id': row[0],
                    'hostname': row[1],
                    'platform': row[2],
                    'status': row[3],
                    'last_seen': row[4],
                    'ip_address': row[5]
                }
            return None
            
        except Exception as e:
            logger.error(f"Failed to get client {client_id}: {e}")
            return None
    
    def get_screen_capture(self, capture_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific screen capture by ID."""
        try:
            if not self._ensure_connection():
                return None
                
            sql = "SELECT id, client_id, capture_timestamp, image_size, compression_ratio, processing_time_ms, metadata FROM screen_captures WHERE id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (capture_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'client_id': row[1],
                    'capture_timestamp': row[2],
                    'image_size': row[3],
                    'compression_ratio': row[4],
                    'processing_time_ms': row[5],
                    'metadata': row[6]
                }
            return None
            
        except Exception as e:
            logger.error(f"Failed to get screen capture {capture_id}: {e}")
            return None
    
    def get_screen_capture_image(self, capture_id: str) -> Optional[bytes]:
        """Get raw image bytes for a specific screen capture ID.

        Decrypts using SecurityManager if the blob is encrypted (DBV1 prefix),
        otherwise returns the stored bytes as-is.
        """
        try:
            if not self._ensure_connection():
                return None
            sql = "SELECT image_data FROM screen_captures WHERE id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (capture_id,))
            row = cursor.fetchone()
            if not row:
                return None
            enc = row[0]
            if enc is None:
                return None
            try:
                if self.security:
                    return self.security.decrypt_blob_from_db(enc)
            except Exception:
                # Fall through to plaintext
                pass
            return enc if isinstance(enc, (bytes, bytearray)) else bytes(enc)
        except Exception as e:
            logger.error(f"Failed to get screen capture image {capture_id}: {e}")
            return None

    def get_security_log(self, log_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific security log by ID."""
        try:
            if not self._ensure_connection():
                return None
                
            sql = "SELECT id, event_type, client_id, description, timestamp FROM security_events WHERE id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (log_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'event_type': row[1],
                    'client_id': row[2],
                    'description': row[3],
                    'timestamp': row[4]
                }
            return None
            
        except Exception as e:
            logger.error(f"Failed to get security log {log_id}: {e}")
            return None
    

    
    def add_session(self, session_data: Dict[str, Any]) -> bool:
        """Add a new session to the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = """
                INSERT INTO sessions (session_token, client_id, user_id, ip_address, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                session_data['session_token'],
                session_data['client_id'],
                session_data['user_id'],
                session_data['ip_address'],
                session_data['expires_at']
            ))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add session: {e}")
            return False
    
    def add_chat_message(self, message_data: Dict[str, Any]) -> bool:
        """Add a new chat message to the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = """
                INSERT INTO chat_messages (client_id, direction, message, timestamp)
                VALUES (?, ?, ?, ?)
            """
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                message_data['client_id'],
                message_data['direction'],
                message_data['message'],
                message_data['timestamp']
            ))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add chat message: {e}")
            return False
    
    def add_file_operation(self, operation_data: Dict[str, Any]) -> bool:
        """Add a new file operation to the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = """
                INSERT INTO file_operations (client_id, operation_type, file_path, details)
                VALUES (?, ?, ?, ?)
            """
            details = json.dumps({
                'status': operation_data['status'],
                'timestamp': operation_data['timestamp']
            })
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                operation_data['client_id'],
                operation_data['operation'],
                operation_data['file_path'],
                details
            ))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add file operation: {e}")
            return False
    
    def update_client(self, client_id: str, update_data: Dict[str, Any]) -> bool:
        """Update a client in the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = """
                UPDATE clients 
                SET hostname = ?, platform = ?, status = ?, ip_address = ?, updated_at = CURRENT_TIMESTAMP
                WHERE client_id = ?
            """
            cursor = self.conn.cursor()
            cursor.execute(sql, (
                update_data['hostname'],
                update_data['platform'],
                update_data['status'],
                update_data['ip_address'],
                client_id
            ))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to update client {client_id}: {e}")
            return False
    
    def delete_client(self, client_id: str) -> bool:
        """Delete a client from the database."""
        try:
            if not self._ensure_connection():
                return False
                
            cursor = self.conn.cursor()

            # Manual cascade to support existing DBs created without ON DELETE CASCADE
            # Delete dependents in correct order
            cursor.execute("DELETE FROM sessions WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM screen_captures WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM chat_messages WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM file_operations WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM activity_logs WHERE client_id = ?", (client_id,))
            cursor.execute("DELETE FROM security_events WHERE client_id = ?", (client_id,))

            # Finally, delete the client
            cursor.execute("DELETE FROM clients WHERE client_id = ?", (client_id,))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete client {client_id}: {e}")
            return False
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a session from the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = "DELETE FROM sessions WHERE id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (session_id,))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete session {session_id}: {e}")
            return False
    
    def delete_screen_capture(self, capture_id: str) -> bool:
        """Delete a screen capture from the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = "DELETE FROM screen_captures WHERE id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (capture_id,))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete screen capture {capture_id}: {e}")
            return False
    
    def delete_chat_message(self, message_id: str) -> bool:
        """Delete a chat message from the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = "DELETE FROM chat_messages WHERE id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (message_id,))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete chat message {message_id}: {e}")
            return False
    
    def delete_file_operation(self, operation_id: str) -> bool:
        """Delete a file operation from the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = "DELETE FROM file_operations WHERE id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (operation_id,))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete file operation {operation_id}: {e}")
            return False
    
    def delete_security_log(self, log_id: str) -> bool:
        """Delete a security log from the database."""
        try:
            if not self._ensure_connection():
                return False
                
            sql = "DELETE FROM security_events WHERE id = ?"
            cursor = self.conn.cursor()
            cursor.execute(sql, (log_id,))
            self.conn.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete security log {log_id}: {e}")
            return False
    
    def close(self):
        """Close database connection and cleanup resources."""
        try:
            if hasattr(self, 'conn'):
                try:
                    self._conn_lock.acquire()
                except Exception:
                    pass
                self.conn.close()
            logger.info("Database connection closed")
        except Exception as e:
            logger.error(f"Failed to close database: {e}", exc_info=True)
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
