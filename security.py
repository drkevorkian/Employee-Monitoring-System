"""
Security Module for Employee Monitoring System
Provides encryption, authentication, and security utilities for cross-platform compatibility.
"""

import os
import hashlib
import hmac
import secrets
import base64
import platform
import logging
import time
import threading
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import psutil

# Optional dependencies
try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHash
except Exception:
    PasswordHasher = None
    VerifyMismatchError = InvalidHash = None

try:
    import redis  # type: ignore
except Exception:
    redis = None

# Configure logging for security events
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityManager:
    """
    Comprehensive security manager providing encryption, authentication,
    and cross-platform security features for the monitoring system.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the security manager with configuration settings.
        
        Args:
            config: Configuration dictionary containing security parameters
        """
        self.config = config
        self.encryption_key_size = config.getint('Security', 'encryption_key_size', fallback=256)
        self.max_login_attempts = config.getint('Security', 'max_login_attempts', fallback=3)
        self.session_timeout = config.getint('Security', 'session_timeout', fallback=3600)
        self.enable_legacy_cbc = config.getboolean('Security', 'enable_legacy_cbc', fallback=False)
        self.enable_rsa = config.getboolean('Security', 'enable_rsa', fallback=False)
        self.derivation_salt = (
            os.getenv('SECURITY_DERIVATION_SALT')
            or config.get('Security', 'derivation_salt', fallback='')
        )
        self.allow_plaintext_passthrough = self.config.getboolean(
            'Security', 'allow_plaintext_passthrough', fallback=True
        )
        
        # Initialize platform-specific security features
        self._init_platform_security()
        
        # Generate or load encryption keys
        self._init_encryption_keys()
        
        # Initialize rate limiting
        self._init_rate_limiting()
        
        logger.info(f"Security manager initialized for {platform.system()}")
    
    def _init_platform_security(self):
        """Initialize platform-specific security features."""
        try:
            system = platform.system()
            if isinstance(system, str):
                system = system.lower()
            else:
                logger.warning(f"Unexpected platform system type: {type(system)}, value: {system}")
                system = "unknown"
            
            if system == "windows":
                self._init_windows_security()
            elif system == "linux":
                self._init_linux_security()
            elif system == "darwin":  # macOS
                self._init_macos_security()
            else:  # Unix variants
                self._init_unix_security()
        except Exception as e:
            logger.error(f"Error initializing platform security: {e}")
            self._init_unix_security()  # Fallback to generic Unix
    
    def _init_windows_security(self):
        """Initialize Windows-specific security features."""
        try:
            import win32security
            import win32api
            # Enable Windows security features
            self.windows_secure_desktop = True
            logger.info("Windows security features enabled")
        except ImportError:
            self.windows_secure_desktop = False
            logger.warning("Windows security features not available")
    
    def _init_linux_security(self):
        """Initialize Linux-specific security features."""
        try:
            # Check for systemd and security modules
            if os.path.exists("/etc/systemd"):
                self.linux_systemd = True
                logger.info("Linux systemd security features enabled")
            else:
                self.linux_systemd = False
        except Exception as e:
            logger.warning(f"Linux security features not available: {e}")
    
    def _init_macos_security(self):
        """Initialize macOS-specific security features."""
        try:
            # Check for macOS security framework
            if os.path.exists("/System/Library/Frameworks/Security.framework"):
                self.macos_security = True
                logger.info("macOS security framework enabled")
            else:
                self.macos_security = False
        except Exception as e:
            logger.warning(f"macOS security features not available: {e}")
    
    def _init_unix_security(self):
        """Initialize generic Unix security features."""
        self.unix_generic = True
        logger.info("Generic Unix security features enabled")
    
    def _init_encryption_keys(self):
        """Initialize encryption keys for secure communication and data encryption."""
        try:
            # Optional RSA generation (disabled by default)
            if self.enable_rsa:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                self.public_key = self.private_key.public_key()

            # Master key: load from secure file or create
            self.master_key = self._load_or_create_master_key()

            # Per-deployment derivation salt for HKDF domain separation
            if isinstance(self.derivation_salt, str) and self.derivation_salt:
                hkdf_salt = self.derivation_salt.encode('utf-8')
            else:
                hkdf_salt = self._load_or_create_derivation_salt(self.master_key_path)

            # Derive independent keys for different purposes using HKDF
            self.db_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=hkdf_salt,
                info=b"db-aead-v1",
                backend=default_backend(),
            ).derive(self.master_key)
            self.db_aead = AESGCM(self.db_key)

            self.app_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=hkdf_salt,
                info=b"app-aead-v1",
                backend=default_backend(),
            ).derive(self.master_key)
            self.app_aead = AESGCM(self.app_key)

            # Legacy CBC/HMAC keys for migration only
            self.legacy_cbc_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=hkdf_salt,
                info=b"legacy-cbc-enc-v1",
                backend=default_backend(),
            ).derive(self.master_key)
            self.legacy_hmac_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=hkdf_salt,
                info=b"legacy-cbc-hmac-v1",
                backend=default_backend(),
            ).derive(self.master_key)

            # Backwards-compatibility placeholders for removed legacy attributes
            self.symmetric_key = None
            self.cipher_suite = None

            logger.info("Encryption keys initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize encryption keys: {e}")
            raise

    def _load_or_create_master_key(self) -> bytes:
        """Load a 256-bit master key from a deterministic absolute path or create it.

        Respects env var SECURITY_MASTER_KEY_PATH or config 'Security.master_key_path'.
        Fails closed on read/permission errors. Creates the file if it does not exist.
        """
        # Resolve deterministic absolute path
        env_path = os.getenv('SECURITY_MASTER_KEY_PATH')
        cfg_path = self.config.get('Security', 'master_key_path', fallback='') if hasattr(self, 'config') else ''
        key_path: str
        if env_path:
            key_path = env_path
        elif cfg_path:
            key_path = cfg_path
        else:
            system = platform.system().lower() if isinstance(platform.system(), str) else 'unknown'
            if system == 'windows':
                base_dir = os.getenv('APPDATA') or os.path.expanduser('~')
                key_path = os.path.join(base_dir, 'Project Asteroid miner', 'keys', 'master.key')
            elif system == 'darwin':
                base_dir = os.path.join(os.path.expanduser('~'), 'Library', 'Application Support')
                key_path = os.path.join(base_dir, 'Project Asteroid miner', 'keys', 'master.key')
            else:
                base_dir = os.path.join(os.path.expanduser('~'), '.config')
                key_path = os.path.join(base_dir, 'Project Asteroid miner', 'keys', 'master.key')

        key_dir = os.path.dirname(key_path)
        try:
            os.makedirs(key_dir, exist_ok=True)
            if os.path.exists(key_path):
                with open(key_path, 'rb') as f:
                    key = f.read()
                if len(key) != 32:
                    raise ValueError('Invalid master key length')
                self.master_key_path = key_path
                return key
            # Create new key
            key = os.urandom(32)
            tmp = key_path + '.tmp'
            with open(tmp, 'wb') as f:
                f.write(key)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, key_path)
            try:
                os.chmod(key_path, 0o600)
            except Exception:
                pass
            self.master_key_path = key_path
            return key
        except Exception as e:
            logger.error(f"Failed to load or create master key at {key_path}: {e}")
            raise

    def _load_or_create_derivation_salt(self, key_path: str) -> bytes:
        """Load or atomically create a per-deployment HKDF salt next to the master key."""
        try:
            salt_path = os.path.join(os.path.dirname(key_path), "master.salt")
            if os.path.exists(salt_path):
                with open(salt_path, 'rb') as f:
                    return f.read()
            salt = os.urandom(32)
            tmp = salt_path + '.tmp'
            with open(tmp, 'wb') as f:
                f.write(salt)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, salt_path)
            try:
                os.chmod(salt_path, 0o600)
            except Exception:
                pass
            return salt
        except Exception as e:
            logger.error(f"Failed to load or create derivation salt: {e}")
            # As a fallback use a static label; not ideal but preserves operation
            return b'MonitoringSystem-DefaultSalt'
    
    def _init_rate_limiting(self):
        """Initialize rate limiting using a token bucket with monotonic time.

        Optionally uses Redis if configured. Defaults to in-memory, bounded state.
        """
        self.rate_limit_requests = self.config.getint('Security', 'rate_limit_requests', fallback=100)
        self.rate_limit_window = self.config.getint('Security', 'rate_limit_window', fallback=60)
        capacity = max(1, self.rate_limit_requests)
        refill_period = max(1, self.rate_limit_window)
        backend = self.config.get('Security', 'rate_limit_backend', fallback='memory').lower()
        redis_url = os.getenv('REDIS_URL') or self.config.get('Security', 'redis_url', fallback='')

        if backend == 'redis' and redis and redis_url:
            try:
                self._redis_client = redis.Redis.from_url(redis_url, decode_responses=False)
                self._rate_limiter = _RedisTokenBucket(self._redis_client, capacity=capacity, refill_period_seconds=refill_period)
                return
            except Exception as e:
                logger.warning(f"Redis rate limiter unavailable, falling back to memory: {e}")

        self._rate_limiter = _InMemoryTokenBucket(capacity=capacity, refill_period_seconds=refill_period)
    
    def encrypt_data(self, data: bytes) -> Tuple[bytes, bytes]:
        """
        Deprecated: Legacy AES-256-CBC encryption. Disabled by default.
        Migration-only: if 'enable_legacy_cbc' is True, applies AES-CBC with HMAC-SHA256 over iv||ct.

        Returns (ciphertext||tag, iv).
        """
        if not self.enable_legacy_cbc:
            raise RuntimeError("Legacy AES-CBC is disabled. Use encrypt_for_db/encrypt_for_app (AEAD).")
        try:
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(self.legacy_cbc_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            padded_data = self._pad_data(data)
            ct = encryptor.update(padded_data) + encryptor.finalize()
            tag = hmac.new(self.legacy_hmac_key, iv + ct, hashlib.sha256).digest()
            return ct + tag, iv
        except Exception as e:
            logger.error(f"Legacy encryption failed: {e}")
            raise
    
    def decrypt_data(self, encrypted_data: bytes, iv: bytes) -> bytes:
        """
        Deprecated: Legacy AES-256-CBC decryption. Disabled by default.
        Migration-only: verifies HMAC-SHA256 over iv||ct, then decrypts and performs strict PKCS#7 validation.
        """
        if not self.enable_legacy_cbc:
            raise RuntimeError("Legacy AES-CBC is disabled. Use decrypt_from_db/decrypt_for_app (AEAD).")
        try:
            if len(encrypted_data) < 16 + 32:
                raise ValueError("Invalid legacy ciphertext")
            ct, tag = encrypted_data[:-32], encrypted_data[-32:]
            expected_tag = hmac.new(self.legacy_hmac_key, iv + ct, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Legacy HMAC verification failed")
            cipher = Cipher(
                algorithms.AES(self.legacy_cbc_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            return self._unpad_data(padded)
        except Exception as e:
            logger.error(f"Legacy decryption failed: {e}")
            raise
    
    def _pad_data(self, data: bytes) -> bytes:
        """Pad data to AES block size (16 bytes) using PKCS#7."""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, data: bytes) -> bytes:
        """Strict PKCS#7 unpadding with constant-time validation of padding bytes."""
        if not data:
            raise ValueError("Invalid padding: empty input")
        padding_length = data[-1]
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid padding length")
        padding = data[-padding_length:]
        mismatch = 0
        for b in padding:
            mismatch |= (b ^ padding_length)
        if mismatch != 0:
            raise ValueError("Invalid padding bytes")
        return data[:-padding_length]

    # --- New high-level helpers for encrypting application/DB data (AES-GCM) ---
    def encrypt_for_db(self, value: Any, aad_context: Optional[str] = None) -> str:
        """Encrypt JSON-serializable value for storage in TEXT columns (AES-GCM).

        Returns versioned string: 'v1:<b64(nonce||ciphertext||tag)>'.
        AAD binds context: default b'DBv1'; if aad_context provided, uses b'DBv1|'<ctx>.
        """
        try:
            if value is None:
                return None
            if isinstance(value, (bytes, bytearray)):
                data = bytes(value)
            else:
                import json
                data = json.dumps(value).encode("utf-8")
            nonce = os.urandom(12)
            aad = b"DBv1" if not aad_context else (b"DBv1|" + aad_context.encode("utf-8"))
            ct = self.db_aead.encrypt(nonce, data, aad)
            token = base64.urlsafe_b64encode(nonce + ct).decode("utf-8")
            return f"v1:{token}"
        except Exception as e:
            logger.error(f"encrypt_for_db failed: {e}")
            raise

    def decrypt_from_db(self, token: str, aad_context: Optional[str] = None) -> Any:
        """Decrypt value produced by encrypt_for_db.
        If encryption used an AAD context, the same context must be provided.
        """
        try:
            if token is None:
                return None
            if isinstance(token, (bytes, bytearray)):
                token = token.decode("utf-8", errors="ignore")
            if not token.startswith("v1:"):
                if self.allow_plaintext_passthrough:
                    return token
                raise ValueError("unexpected plaintext token")
            raw = base64.urlsafe_b64decode(token[3:].encode("utf-8"))
            nonce, ct = raw[:12], raw[12:]
            aad = b"DBv1" if not aad_context else (b"DBv1|" + aad_context.encode("utf-8"))
            data = self.db_aead.decrypt(nonce, ct, aad)
            import json
            try:
                return json.loads(data.decode("utf-8"))
            except Exception:
                return data.decode("utf-8", errors="ignore")
        except Exception as e:
            logger.error(f"decrypt_from_db failed: {e}")
            raise

    def encrypt_blob_for_db(self, data: bytes, aad_context: Optional[str] = None) -> bytes:
        """Encrypt binary data for storage in BLOB columns (AES-GCM)."""
        try:
            if data is None:
                return None
            nonce = os.urandom(12)
            aad = b"DBv1" if not aad_context else (b"DBv1|" + aad_context.encode("utf-8"))
            ct = self.db_aead.encrypt(nonce, data, aad)
            return b"DBV1" + nonce + ct
        except Exception as e:
            logger.error(f"encrypt_blob_for_db failed: {e}")
            raise

    def decrypt_blob_from_db(self, enc: bytes, aad_context: Optional[str] = None) -> bytes:
        """Decrypt BLOB produced by encrypt_blob_for_db."""
        try:
            if enc is None:
                return None
            if not enc.startswith(b"DBV1"):
                if self.allow_plaintext_passthrough:
                    return enc
                raise ValueError("unexpected plaintext blob")
            enc = enc[4:]
            nonce, ct = enc[:12], enc[12:]
            aad = b"DBv1" if not aad_context else (b"DBv1|" + aad_context.encode("utf-8"))
            return self.db_aead.decrypt(nonce, ct, aad)
        except Exception as e:
            logger.error(f"decrypt_blob_from_db failed: {e}")
            raise

    # --- Application-level AEAD helpers (AES-GCM) ---
    def encrypt_for_app(self, data: bytes, aad_context: str) -> bytes:
        """Encrypt arbitrary bytes for general app data with contextual AAD.

        Returns bytes with prefix b'APV1' + nonce + ciphertext||tag
        """
        try:
            if data is None:
                return None
            nonce = os.urandom(12)
            aad = b"APPv1|" + aad_context.encode("utf-8")
            ct = self.app_aead.encrypt(nonce, data, aad)
            return b"APV1" + nonce + ct
        except Exception as e:
            logger.error(f"encrypt_for_app failed: {e}")
            raise

    def decrypt_for_app(self, enc: bytes, aad_context: str) -> bytes:
        """Decrypt bytes produced by encrypt_for_app."""
        try:
            if enc is None:
                return None
            if not enc.startswith(b"APV1"):
                if self.allow_plaintext_passthrough:
                    return enc
                raise ValueError("unexpected plaintext blob")
            raw = enc[4:]
            nonce, ct = raw[:12], raw[12:]
            aad = b"APPv1|" + aad_context.encode("utf-8")
            return self.app_aead.decrypt(nonce, ct, aad)
        except Exception as e:
            logger.error(f"decrypt_for_app failed: {e}")
            raise
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.
        
        Args:
            length: Length of the token in bytes
            
        Returns:
            URL-safe Base64 token (no padding)
        """
        try:
            token = secrets.token_bytes(length)
            return base64.urlsafe_b64encode(token).decode('utf-8').rstrip('=')
        except Exception as e:
            logger.error(f"Token generation failed: {e}")
            raise
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash password using Argon2id if available, else PBKDF2-SHA256 with strong params.

        Returns (encoded_hash, salt_or_empty). For Argon2, salt is embedded, so second value is ''.
        """
        try:
            if PasswordHasher is not None:
                hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16)
                encoded = hasher.hash(password)
                return encoded, ''
            # Fallback: PBKDF2-SHA256 with >= 310k iterations
            if salt is None:
                salt = secrets.token_hex(16)
            key = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                310000,
                dklen=32
            )
            encoded = f"pbkdf2_sha256$310000${salt}${base64.b64encode(key).decode('utf-8')}"
            return encoded, salt
        except Exception as e:
            logger.error(f"Password hashing failed: {e}")
            raise
    
    def verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verify password against stored hash supporting Argon2id, new PBKDF2 format, and legacy PBKDF2(100k) + separate salt."""
        try:
            if stored_hash.startswith('$argon2') and PasswordHasher is not None:
                hasher = PasswordHasher()
                try:
                    return hasher.verify(stored_hash, password)
                except VerifyMismatchError:
                    return False
                except InvalidHash:
                    return False
            if stored_hash.startswith('pbkdf2_sha256$'):
                try:
                    parts = stored_hash.split('$')
                    if len(parts) != 4:
                        return False
                    _, iters_str, salt_val, b64_digest = parts
                    iters = int(iters_str)
                    dk = hashlib.pbkdf2_hmac(
                        'sha256', password.encode('utf-8'), salt_val.encode('utf-8'), iters, dklen=32
                    )
                    return hmac.compare_digest(base64.b64encode(dk).decode('utf-8'), b64_digest)
                except Exception:
                    return False
            # Backward compatibility: old tuple format (base64 digest, separate salt) using 100k iterations
            if salt:
                try:
                    dk = hashlib.pbkdf2_hmac(
                        'sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000, dklen=32
                    )
                    return hmac.compare_digest(base64.b64encode(dk).decode('utf-8'), stored_hash)
                except Exception:
                    return False
            return False
        except Exception as e:
            logger.error(f"Password verification failed: {e}")
            return False
    
    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client has exceeded rate limits using a token bucket algorithm."""
        try:
            allowed = self._rate_limiter.allow(client_ip)
            if not allowed:
                logger.warning(f"Rate limit exceeded for {client_ip}")
            return allowed
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """
        Get system information for security auditing.
        
        Returns:
            Dictionary containing system security information
        """
        try:
            info = {
                'platform': platform.system() if isinstance(platform.system(), str) else str(platform.system()),
                'platform_version': platform.version(),
                'architecture': platform.architecture(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'security_features': {}
            }
            
            # Add platform-specific security features
            if hasattr(self, 'windows_secure_desktop'):
                info['security_features']['windows_secure_desktop'] = self.windows_secure_desktop
            
            if hasattr(self, 'linux_systemd'):
                info['security_features']['linux_systemd'] = self.linux_systemd
            
            if hasattr(self, 'macos_security'):
                info['security_features']['macos_security'] = self.macos_security
            
            if hasattr(self, 'unix_generic'):
                info['security_features']['unix_generic'] = self.unix_generic
            
            # Add process security information
            try:
                process = psutil.Process()
                info['process_security'] = {
                    'user_id': process.uids().real if hasattr(process, 'uids') else None,
                    'group_id': process.gids().real if hasattr(process, 'gids') else None,
                    'memory_protection': self._check_memory_protection()
                }
            except Exception as e:
                logger.warning(f"Could not get process security info: {e}")
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get system info: {e}")
            return {}
    
    def _check_memory_protection(self) -> Dict[str, bool]:
        """Check memory protection features available on the system."""
        protection = {
            'aslr': False,  # Address Space Layout Randomization
            'dep': False,   # Data Execution Prevention
            'stack_canary': False
        }
        
        try:
            # Check for ASLR (simplified check)
            if isinstance(platform.system(), str) and platform.system().lower() == "linux":
                with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                    protection['aslr'] = f.read().strip() != '0'
            elif isinstance(platform.system(), str) and platform.system().lower() == "windows":
                protection['aslr'] = True  # Windows 10+ has ASLR by default
            
            # Check for DEP (simplified check)
            if isinstance(platform.system(), str) and platform.system().lower() == "windows":
                protection['dep'] = True  # Windows has DEP by default
            
            # Stack canary check would require more complex analysis
            protection['stack_canary'] = False
            
        except Exception as e:
            logger.debug(f"Memory protection check failed: {e}")
        
        return protection
    
    def cleanup(self):
        """Clean up security resources."""
        try:
            # Clear sensitive data from memory
            if hasattr(self, 'private_key'):
                self.private_key = None
            if hasattr(self, 'public_key'):
                self.public_key = None
            if hasattr(self, 'db_key'):
                self.db_key = None
            if hasattr(self, 'app_key'):
                self.app_key = None
            if hasattr(self, 'legacy_cbc_key'):
                self.legacy_cbc_key = None
            if hasattr(self, 'legacy_hmac_key'):
                self.legacy_hmac_key = None
            
            # Clear rate limiting data (memory backend)
            if hasattr(self, '_rate_limiter') and isinstance(self._rate_limiter, _InMemoryTokenBucket):
                self._rate_limiter.clear()
            
            logger.info("Security manager cleaned up successfully")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")


# -----------------------
# Rate limiter utilities
# -----------------------

class _InMemoryTokenBucket:
    """Simple in-memory token bucket rate limiter using monotonic clock.

    Not process-safe. Suitable for single-process deployments or per-instance limiting.
    """

    def __init__(self, capacity: int, refill_period_seconds: int, max_clients: int = 10000):
        self.capacity = float(capacity)
        self.refill_rate = float(capacity) / float(refill_period_seconds)
        self.max_clients = max(1000, int(max_clients))
        self._tokens: Dict[str, float] = {}
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _refill(self, key: str, now: float) -> None:
        last = self._last.get(key, now)
        elapsed = max(0.0, now - last)
        new_tokens = self._tokens.get(key, self.capacity)
        new_tokens = min(self.capacity, new_tokens + elapsed * self.refill_rate)
        self._tokens[key] = new_tokens
        self._last[key] = now

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if key not in self._tokens and len(self._tokens) >= self.max_clients:
                # Simple bounded memory: evict an arbitrary key (not strictly LRU for simplicity)
                try:
                    evict_key = next(iter(self._tokens))
                    self._tokens.pop(evict_key, None)
                    self._last.pop(evict_key, None)
                except StopIteration:
                    pass
            self._refill(key, now)
            if self._tokens.get(key, self.capacity) >= 1.0:
                self._tokens[key] -= 1.0
                return True
            return False

    def clear(self) -> None:
        self._tokens.clear()
        self._last.clear()


class _RedisTokenBucket:
    """Best-effort Redis-backed token bucket. Requires Redis; uses simple Lua-less updates.

    For strict guarantees under concurrency, prefer a Lua script. This implementation is pragmatic.
    """

    def __init__(self, client: 'redis.Redis', capacity: int, refill_period_seconds: int, prefix: str = 'rl:tb:'):
        self.client = client
        self.capacity = float(capacity)
        self.refill_rate = float(capacity) / float(refill_period_seconds)
        self.prefix = prefix

    def allow(self, key: str) -> bool:
        try:
            redis_key = f"{self.prefix}{key}".encode('utf-8')
            now_ms = int(time.time() * 1000)
            pipe = self.client.pipeline()
            pipe.hget(redis_key, b'tokens')
            pipe.hget(redis_key, b'last')
            tokens_b, last_b = pipe.execute()
            if tokens_b is None or last_b is None:
                # Initialize bucket
                pipe.hset(redis_key, mapping={b'tokens': str(self.capacity - 1.0).encode('ascii'), b'last': str(now_ms).encode('ascii')})
                pipe.pexpire(redis_key, max(1000, int((self.capacity / self.refill_rate) * 1000)))
                pipe.execute()
                return True
            try:
                tokens = float(tokens_b.decode('ascii'))
                last_ms = float(last_b.decode('ascii'))
            except Exception:
                tokens = self.capacity
                last_ms = now_ms
            elapsed = max(0.0, (now_ms - last_ms) / 1000.0)
            tokens = min(self.capacity, tokens + elapsed * self.refill_rate)
            if tokens >= 1.0:
                tokens -= 1.0
                # Update state
                pipe.hset(redis_key, mapping={b'tokens': str(tokens).encode('ascii'), b'last': str(now_ms).encode('ascii')})
                pipe.pexpire(redis_key, max(1000, int((self.capacity / self.refill_rate) * 1000)))
                pipe.execute()
                return True
            else:
                # Update last seen to advance time on next attempt
                pipe.hset(redis_key, mapping={b'tokens': str(tokens).encode('ascii'), b'last': str(now_ms).encode('ascii')})
                pipe.pexpire(redis_key, max(1000, int((self.capacity / self.refill_rate) * 1000)))
                pipe.execute()
                return False
        except Exception:
            # On Redis error, deny to be safe
            return False
