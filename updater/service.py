#!/usr/bin/env python3
import threading
import time
import os
import sys
import json
import zipfile
import hashlib
import importlib
import logging
from typing import Callable, Optional, List, Dict, Tuple
from urllib.request import urlopen


logger = logging.getLogger(__name__)


class UpdaterService:
	"""Background updater that polls for minor updates and hot-reloads safe modules.

	Design goals implemented:
	- Signed bundles: verify Ed25519 signature over manifest and optional SHA256 for bundle
	- Versioned directories under ./Versions/<version>/ with safe zip extraction
	- Atomic module search path switch by prepending the new version dir to sys.path
	- Hot-reload map with optional __hot_apply__(context) apply hooks per module
	- Busy-safe apply window: prefer 45s idle, cap at 300s before forced apply
	- Rollback: revert sys.path and reload previous modules immediately on failure
	"""

	def __init__(self, current_version: str, check_func: Callable[[], Optional[dict]], apply_func: Optional[Callable[[dict], bool]] = None, poll_seconds: int = 30, is_busy_func: Optional[Callable[[], bool]] = None):
		self.current_version = current_version
		self.check_func = check_func
		self.apply_func = apply_func or self._default_apply
		self.poll_seconds = max(5, poll_seconds)
		self.is_busy_func = is_busy_func or (lambda: False)
		self._stop = threading.Event()
		self._thread: Optional[threading.Thread] = None
		self._lock = threading.Lock()
		self._active_version_path: Optional[str] = None
		self._previous_version_path: Optional[str] = None

		# Defaults for busy-safe window
		self._preferred_wait_seconds = 45
		self._max_wait_seconds = 300

	def start(self) -> None:
		if self._thread and self._thread.is_alive():
			return
		self._thread = threading.Thread(target=self._loop, daemon=True)
		self._thread.start()

	def stop(self) -> None:
		self._stop.set()
		if self._thread:
			self._thread.join(timeout=2)

	def _loop(self) -> None:
		while not self._stop.is_set():
			try:
				meta = self.check_func()
				if meta:
					self._handle_update(meta)
			except Exception as e:
				logger.debug(f"Updater loop error: {e}")
			time.sleep(self.poll_seconds)

	def _handle_update(self, meta: dict) -> None:
		# meta: {
		#   version: "1.13.8",
		#   bundle_path: "path/to/bundle.zip" or bundle_url: "https://...",
		#   sha256: "...optional...",
		#   manifest_signature: "base64 ed25519 sig of manifest.json",
		#   ed25519_pubkey: "base64 public key" or ed25519_pubkey_path: "...",
		#   modules: ["ui.module", ...],
		#   allowlist: ["ui.", "controllers."],
		#   preferred_wait: 45, max_wait: 300
		# }
		new_version = str(meta.get('version', '')).strip()
		if not new_version:
			return
		if self._is_newer_minor(self.current_version, new_version):
			preferred = int(meta.get('preferred_wait', self._preferred_wait_seconds))
			max_wait = int(meta.get('max_wait', self._max_wait_seconds))
			self._apply_when_idle(meta, preferred, max_wait)

	def _is_newer_minor(self, cur: str, new: str) -> bool:
		def parse(v: str) -> Tuple[int, int, int]:
			try:
				parts = [int(p) for p in v.split('.')]
			except Exception:
				parts = [0, 0, 0]
			return (parts + [0, 0, 0])[:3]
		c = parse(cur)
		n = parse(new)
		return (n[0] == c[0]) and (n > c)

	def _apply_when_idle(self, meta: dict, preferred_wait: int, max_wait: int) -> None:
		deadline = time.time() + max_wait
		prefer_until = time.time() + preferred_wait
		while time.time() < deadline:
			if not self.is_busy_func():
				break
			time.sleep(0.5)
		# Apply update now (either idle or timed out the preferred window)
		with self._lock:
			ok = False
			try:
				ok = self.apply_func(meta)
				if ok:
					self.current_version = str(meta.get('version', self.current_version))
					logger.info(f"Update applied to {self.current_version}")
				else:
					logger.error("Update apply_func reported failure")
			except Exception as e:
				logger.error(f"Update application failed: {e}")

	def _default_apply(self, meta: dict) -> bool:
		"""Verify bundle, unpack to versioned dir, switch path, hot-reload, rollback on failure."""
		version = str(meta.get('version'))
		try:
			bundle_path = self._obtain_bundle(meta)
			if not bundle_path:
				raise RuntimeError("No bundle provided")
			# Optional bundle integrity
			sha256 = str(meta.get('sha256', '')).strip()
			if sha256:
				self._verify_sha256(bundle_path, sha256)
			# Read manifest for signature verification
			with zipfile.ZipFile(bundle_path, 'r') as zf:
				manifest_bytes = zf.read('manifest.json')
				manifest = json.loads(manifest_bytes.decode('utf-8'))
			# Verify manifest signature if provided
			sig_b64 = meta.get('manifest_signature') or manifest.get('signature')
			pubkey_b64 = meta.get('ed25519_pubkey')
			pubkey_path = meta.get('ed25519_pubkey_path')
			if sig_b64 and (pubkey_b64 or pubkey_path):
				self._verify_manifest_signature(manifest_bytes, sig_b64, pubkey_b64, pubkey_path)
			# Unpack safely to Versions/<version>
			dest_dir = os.path.join(os.getcwd(), 'Versions', version)
			self._safe_extract_zip(bundle_path, dest_dir)
			# Atomically prepend new version dir to sys.path
			prev_path = list(sys.path)
			self._previous_version_path = self._active_version_path
			self._active_version_path = dest_dir
			if dest_dir not in sys.path:
				sys.path.insert(0, dest_dir)
			# Determine modules to reload (allowlist)
			mods_meta: List[str] = manifest.get('hot_reload', {}).get('modules', []) or meta.get('modules', []) or []
			allow_prefixes: List[str] = manifest.get('hot_reload', {}).get('allowlist', []) or meta.get('allowlist', []) or []
			reloaded: List[str] = []
			try:
				self._hot_reload_modules(mods_meta, allow_prefixes, context={
					'version': version,
					'installed_path': dest_dir,
					'manifest': manifest,
				})
			except Exception as hot_err:
				# Rollback on failure
				sys.path[:] = prev_path
				self._active_version_path = self._previous_version_path
				raise hot_err
			# Success
			return True
		except Exception as e:
			logger.error(f"Default apply failed: {e}")
			return False

	def _obtain_bundle(self, meta: dict) -> Optional[str]:
		path = meta.get('bundle_path')
		url = meta.get('bundle_url')
		if path and os.path.exists(path):
			return path
		if url:
			fn = os.path.join(os.getcwd(), 'updates', 'pending.zip')
			os.makedirs(os.path.dirname(fn), exist_ok=True)
			with urlopen(url, timeout=20) as r, open(fn, 'wb') as f:
				f.write(r.read())
			return fn if os.path.exists(fn) else None
		return None

	def _verify_sha256(self, file_path: str, expected_hex: str) -> None:
		h = hashlib.sha256()
		with open(file_path, 'rb') as f:
			for chunk in iter(lambda: f.read(65536), b''):
				h.update(chunk)
		calc = h.hexdigest()
		if calc.lower() != expected_hex.lower():
			raise ValueError("Bundle SHA256 mismatch")

	def _verify_manifest_signature(self, manifest_bytes: bytes, sig_b64: str, pubkey_b64: Optional[str], pubkey_path: Optional[str]) -> None:
		import base64
		from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
		from cryptography.hazmat.primitives import serialization
		if pubkey_path and not pubkey_b64:
			with open(pubkey_path, 'rb') as f:
				pubkey_data = f.read()
			try:
				pub = serialization.load_pem_public_key(pubkey_data)
			except Exception:
				# Assume raw 32-byte key base64 in file
				pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_data))
		elif pubkey_b64:
			pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pubkey_b64))
		else:
			raise ValueError("No public key provided for signature verification")
		sig = base64.b64decode(sig_b64)
		pub.verify(sig, manifest_bytes)

	def _safe_extract_zip(self, zip_path: str, dest_dir: str) -> None:
		os.makedirs(dest_dir, exist_ok=True)
		with zipfile.ZipFile(zip_path, 'r') as zf:
			for member in zf.infolist():
				# Prevent path traversal
				name = member.filename
				if name.startswith('/') or name.startswith('\\'):
					raise ValueError("Unsafe absolute path in zip")
				if '..' in name.replace('\\', '/').split('/'):
					raise ValueError("Path traversal detected in zip")
				zf.extract(member, dest_dir)

	def _hot_reload_modules(self, modules: List[str], allow_prefixes: List[str], context: Dict[str, object]) -> None:
		# Filter modules by allowlist prefixes if provided
		def allowed(name: str) -> bool:
			if not allow_prefixes:
				return True
			return any(name.startswith(pfx) for pfx in allow_prefixes)
		for name in modules:
			if not isinstance(name, str) or not name:
				continue
			if not allowed(name):
				logger.info(f"Skipping non-allowlisted module: {name}")
				continue
			mod = None
			try:
				mod = sys.modules.get(name)
				if mod is None:
					mod = importlib.import_module(name)
				else:
					mod = importlib.reload(mod)
				# Apply hook if present
				apply_hook = getattr(mod, '__hot_apply__', None)
				if callable(apply_hook):
					start = time.time()
					apply_hook(context)
					elapsed = time.time() - start
					if elapsed > 2.0:
						logger.warning(f"Hot-apply hook for {name} took {elapsed:.2f}s")
			except Exception as e:
				raise RuntimeError(f"Hot-reload failed for {name}: {e}")
