#!/usr/bin/env python3
"""
Comprehensive Logging Configuration for Employee Monitoring System
Provides structured logging with separate files for each component, timestamped and organized.
"""

import os
import logging
import logging.handlers
from datetime import datetime
from typing import Optional
import platform

class MonitoringLogger:
    """Centralized logging manager for the monitoring system."""
    
    def __init__(self, component_name: str, log_dir: str = "logs"):
        """
        Initialize logger for a specific component.
        
        Args:
            component_name: Name of the component (e.g., 'server', 'client', 'client_gui')
            log_dir: Directory to store log files
        """
        self.component_name = component_name
        self.log_dir = log_dir
        self.logger = None
        
        # Create log directory structure
        self._create_log_directories()
        
        # Initialize the logger
        self._setup_logger()
    
    def _create_log_directories(self):
        """Create organized log directory structure."""
        try:
            # Main logs directory
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir, mode=0o755)
            
            # Component-specific subdirectories
            component_dir = os.path.join(self.log_dir, self.component_name)
            if not os.path.exists(component_dir):
                os.makedirs(component_dir, mode=0o755)
            
            # Create subdirectories for different views
            subdirs = ['errors', 'info', 'debug', 'security', 'database', 'network']
            for subdir in subdirs:
                subdir_path = os.path.join(component_dir, subdir)
                if not os.path.exists(subdir_path):
                    os.makedirs(subdir_path, mode=0o755)
                    
        except Exception as e:
            print(f"Failed to create log directories: {e}")
    
    def _setup_logger(self):
        """Setup the logger with multiple handlers and formatters."""
        try:
            # Create logger
            self.logger = logging.getLogger(self.component_name)
            self.logger.setLevel(logging.DEBUG)
            
            # Prevent duplicate handlers
            if self.logger.handlers:
                return
            
            # Create timestamp for log files
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Main log file handler (all levels)
            main_log_file = os.path.join(
                self.log_dir, 
                self.component_name, 
                f"{self.component_name}_{timestamp}.log"
            )
            main_handler = logging.handlers.RotatingFileHandler(
                main_log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            main_handler.setLevel(logging.DEBUG)
            
            # Error log file handler (errors only)
            error_log_file = os.path.join(
                self.log_dir, 
                self.component_name, 
                'errors',
                f"{self.component_name}_errors_{timestamp}.log"
            )
            error_handler = logging.handlers.RotatingFileHandler(
                error_log_file,
                maxBytes=5*1024*1024,  # 5MB
                backupCount=3,
                encoding='utf-8'
            )
            error_handler.setLevel(logging.ERROR)
            
            # Security log file handler
            security_log_file = os.path.join(
                self.log_dir, 
                self.component_name, 
                'security',
                f"{self.component_name}_security_{timestamp}.log"
            )
            security_handler = logging.handlers.RotatingFileHandler(
                security_log_file,
                maxBytes=5*1024*1024,  # 5MB
                backupCount=3,
                encoding='utf-8'
            )
            security_handler.setLevel(logging.WARNING)
            
            # Database log file handler
            db_log_file = os.path.join(
                self.log_dir, 
                self.component_name, 
                'database',
                f"{self.component_name}_database_{timestamp}.log"
            )
            db_handler = logging.handlers.RotatingFileHandler(
                db_log_file,
                maxBytes=5*1024*1024,  # 5MB
                backupCount=3,
                encoding='utf-8'
            )
            db_handler.setLevel(logging.INFO)
            
            # Network log file handler
            network_log_file = os.path.join(
                self.log_dir, 
                self.component_name, 
                'network',
                f"{self.component_name}_network_{timestamp}.log"
            )
            network_handler = logging.handlers.RotatingFileHandler(
                network_log_file,
                maxBytes=5*1024*1024,  # 5MB
                backupCount=3,
                encoding='utf-8'
            )
            network_handler.setLevel(logging.INFO)
            
            # Console handler for immediate feedback
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            
            # Create formatters
            detailed_formatter = logging.Formatter(
                fmt='%(asctime)s | %(levelname)-8s | %(filename)s:%(lineno)d | %(funcName)s() | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            simple_formatter = logging.Formatter(
                fmt='%(asctime)s | %(levelname)-8s | %(message)s',
                datefmt='%H:%M:%S'
            )
            
            # Apply formatters
            main_handler.setFormatter(detailed_formatter)
            error_handler.setFormatter(detailed_formatter)
            security_handler.setFormatter(detailed_formatter)
            db_handler.setFormatter(detailed_formatter)
            network_handler.setFormatter(detailed_formatter)
            console_handler.setFormatter(simple_formatter)
            
            # Add filters for specific handlers
            error_handler.addFilter(lambda record: record.levelno >= logging.ERROR)
            security_handler.addFilter(lambda record: 'security' in record.getMessage().lower() or 
                                                   record.levelno >= logging.WARNING)
            db_handler.addFilter(lambda record: 'database' in record.getMessage().lower() or 
                               'db' in record.getMessage().lower())
            network_handler.addFilter(lambda record: 'network' in record.getMessage().lower() or 
                                    'socket' in record.getMessage().lower() or 
                                    'connection' in record.getMessage().lower())
            
            # Add handlers to logger
            self.logger.addHandler(main_handler)
            self.logger.addHandler(error_handler)
            self.logger.addHandler(security_handler)
            self.logger.addHandler(db_handler)
            self.logger.addHandler(network_handler)
            self.logger.addHandler(console_handler)
            
            # Log initialization
            self.logger.info(f"Logger initialized for component: {self.component_name}")
            self.logger.info(f"Log files created in: {os.path.join(self.log_dir, self.component_name)}")
            
        except Exception as e:
            print(f"Failed to setup logger for {self.component_name}: {e}")
    
    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance."""
        return self.logger
    
    def log_error(self, message: str, error: Optional[Exception] = None, context: str = ""):
        """Log an error with context and optional exception details."""
        if error:
            self.logger.error(f"{context}: {message} - Exception: {type(error).__name__}: {error}")
        else:
            self.logger.error(f"{context}: {message}")
    
    def log_security(self, message: str, level: str = "info"):
        """Log security-related messages."""
        if level.lower() == "warning":
            self.logger.warning(f"[SECURITY] {message}")
        elif level.lower() == "error":
            self.logger.error(f"[SECURITY] {message}")
        else:
            self.logger.info(f"[SECURITY] {message}")
    
    def log_database(self, message: str, level: str = "info"):
        """Log database-related messages."""
        if level.lower() == "warning":
            self.logger.warning(f"[DATABASE] {message}")
        elif level.lower() == "error":
            self.logger.error(f"[DATABASE] {message}")
        else:
            self.logger.info(f"[DATABASE] {message}")
    
    def log_network(self, message: str, level: str = "info"):
        """Log network-related messages."""
        if level.lower() == "warning":
            self.logger.warning(f"[NETWORK] {message}")
        elif level.lower() == "error":
            self.logger.error(f"[NETWORK] {message}")
        else:
            self.logger.info(f"[NETWORK] {message}")

def get_logger(component_name: str) -> logging.Logger:
    """Get a logger instance for a specific component."""
    logger_manager = MonitoringLogger(component_name)
    return logger_manager.get_logger()

def get_logger_manager(component_name: str) -> MonitoringLogger:
    """Get a logger manager instance for a specific component."""
    return MonitoringLogger(component_name)
