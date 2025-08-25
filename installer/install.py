#!/usr/bin/env python3
"""
Installer for Employee Monitoring System
Sets up the system with proper dependencies and cross-platform support.
"""

import os
import sys
import subprocess
import platform
import shutil
import json
from pathlib import Path
import tempfile
import urllib.request

def print_banner():
    """Print installation banner."""
    print("=" * 60)
    print("    Employee Monitoring System - Installer")
    print("=" * 60)
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()}")
    print(f"Architecture: {platform.architecture()[0]}")
    print("=" * 60)

def check_python_version():
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ is required")
        print(f"Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print(f"✅ Python version: {version.major}.{version.minor}.{version.micro}")
    return True

def is_linux():
    """Return True if running on Linux."""
    return platform.system().lower() == "linux"

def is_root() -> bool:
    """Return True if running with root privileges (Unix)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def in_virtualenv() -> bool:
    """Detect if running inside a virtual environment."""
    return hasattr(sys, "real_prefix") or getattr(sys, "base_prefix", sys.prefix) != sys.prefix

def command_exists(command: str) -> bool:
    """Check if a command exists on PATH."""
    return shutil.which(command) is not None

def run_quiet(cmd):
    """Run a command, suppressing stdout/stderr, return True on success."""
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def install_pip_via_pkg_manager() -> bool:
    """Attempt to install pip using the system package manager on Linux."""
    if not is_linux():
        return False

    sudo_prefix = []
    if not is_root() and command_exists("sudo"):
        sudo_prefix = ["sudo", "-n"]

    # Debian/Ubuntu
    if command_exists("apt-get"):
        print("   - Using apt-get to install python3-pip")
        # Update indexes (best-effort)
        run_quiet(sudo_prefix + ["apt-get", "update"])
        # Install pip and venv so we can isolate installs
        return run_quiet(sudo_prefix + [
            "env", "DEBIAN_FRONTEND=noninteractive",
            "apt-get", "install", "-y", "python3-pip", "python3-venv"
        ])

    # Fedora/RHEL/CentOS (dnf/yum)
    if command_exists("dnf"):
        print("   - Using dnf to install python3-pip")
        return run_quiet(sudo_prefix + ["dnf", "install", "-y", "python3-pip"])
    if command_exists("microdnf"):
        print("   - Using microdnf to install python3-pip")
        return run_quiet(sudo_prefix + ["microdnf", "install", "-y", "python3-pip"])
    if command_exists("yum"):
        print("   - Using yum to install python3-pip")
        # Try common names
        if run_quiet(sudo_prefix + ["yum", "install", "-y", "python3-pip"]):
            return True
        return run_quiet(sudo_prefix + ["yum", "install", "-y", "python36-pip"])

    # openSUSE/SLES
    if command_exists("zypper"):
        print("   - Using zypper to install python3-pip")
        return run_quiet(sudo_prefix + ["zypper", "-n", "install", "python3-pip"])

    # Arch/Manjaro
    if command_exists("pacman"):
        print("   - Using pacman to install python-pip")
        run_quiet(sudo_prefix + ["pacman", "-Sy"])
        return run_quiet(sudo_prefix + ["pacman", "-S", "--noconfirm", "python-pip"])

    # Alpine
    if command_exists("apk"):
        print("   - Using apk to install py3-pip")
        return run_quiet(sudo_prefix + ["apk", "add", "--no-cache", "py3-pip"])

    # Solus
    if command_exists("eopkg"):
        print("   - Using eopkg to install python3-pip")
        return run_quiet(sudo_prefix + ["eopkg", "-y", "install", "python3-pip"])

    # Void Linux
    if command_exists("xbps-install"):
        print("   - Using xbps-install to install python3-pip")
        run_quiet(sudo_prefix + ["xbps-install", "-S"])
        return run_quiet(sudo_prefix + ["xbps-install", "-y", "python3-pip"])

    # Gentoo
    if command_exists("emerge"):
        print("   - Using emerge to install pip")
        return run_quiet(sudo_prefix + ["emerge", "--ask=n", "dev-python/pip"])

    return False

def ensure_linux_build_dependencies() -> None:
    """On apt-based distros, install Python 3.12, venv, pip and build deps.

    Installs: python3.12, python3.12-venv (or python3-venv), python3-pip,
    build-essential, libffi-dev, libssl-dev, pkg-config.
    """
    if not is_linux() or not command_exists("apt-get"):
        return

    sudo_prefix = []
    if not is_root() and command_exists("sudo"):
        sudo_prefix = ["sudo", "-n"]

    # update indexes
    run_quiet(sudo_prefix + ["apt-get", "update"])

    # Try version-specific Python first
    common_env = ["env", "DEBIAN_FRONTEND=noninteractive"]
    pkgs_312 = [
        "python3.12", "python3.12-venv", "python3-pip",
        "build-essential", "libffi-dev", "libssl-dev", "pkg-config"
    ]
    ok = run_quiet(sudo_prefix + common_env + ["apt-get", "install", "-y"] + pkgs_312)
    if not ok:
        # Fallback to generic python3 and venv
        pkgs_generic = [
            "python3", "python3-venv", "python3-pip",
            "build-essential", "libffi-dev", "libssl-dev", "pkg-config"
        ]
        run_quiet(sudo_prefix + common_env + ["apt-get", "install", "-y"] + pkgs_generic)


def install_venv_via_pkg_manager() -> bool:
    """Attempt to install Python venv/virtualenv via system package manager on Linux."""
    if not is_linux():
        return False

    sudo_prefix = []
    if not is_root() and command_exists("sudo"):
        sudo_prefix = ["sudo", "-n"]

    # Debian/Ubuntu
    if command_exists("apt-get"):
        print("   - Using apt-get to install venv tooling")
        run_quiet(sudo_prefix + ["apt-get", "update"])  # best-effort
        version_pkg = f"python{sys.version_info.major}.{sys.version_info.minor}-venv"
        # Try version-specific first (e.g. python3.12-venv), then generic
        if run_quiet(sudo_prefix + [
            "env", "DEBIAN_FRONTEND=noninteractive",
            "apt-get", "install", "-y", version_pkg
        ]):
            # Also try to ensure virtualenv is available
            run_quiet(sudo_prefix + [
                "env", "DEBIAN_FRONTEND=noninteractive",
                "apt-get", "install", "-y", "python3-virtualenv"
            ])
            return True
        if run_quiet(sudo_prefix + [
            "env", "DEBIAN_FRONTEND=noninteractive",
            "apt-get", "install", "-y", "python3-venv"
        ]):
            run_quiet(sudo_prefix + [
                "env", "DEBIAN_FRONTEND=noninteractive",
                "apt-get", "install", "-y", "python3-virtualenv"
            ])
            return True
        return False

    # Fedora/RHEL/CentOS (dnf/yum)
    if command_exists("dnf"):
        print("   - Using dnf to ensure venv/virtualenv support")
        if run_quiet(sudo_prefix + ["dnf", "install", "-y", "python3-virtualenv"]):
            return True
        return run_quiet(sudo_prefix + ["dnf", "install", "-y", "python3"])  # provides venv module
    if command_exists("microdnf"):
        print("   - Using microdnf to install python3-virtualenv")
        return run_quiet(sudo_prefix + ["microdnf", "install", "-y", "python3-virtualenv"])
    if command_exists("yum"):
        print("   - Using yum to ensure venv/virtualenv support")
        if run_quiet(sudo_prefix + ["yum", "install", "-y", "python3-virtualenv"]):
            return True
        return run_quiet(sudo_prefix + ["yum", "install", "-y", "python3"])  # provides venv module

    # openSUSE/SLES
    if command_exists("zypper"):
        print("   - Using zypper to install python3-virtualenv")
        return run_quiet(sudo_prefix + ["zypper", "-n", "install", "python3-virtualenv"])

    # Arch/Manjaro
    if command_exists("pacman"):
        print("   - Using pacman to install python-virtualenv")
        run_quiet(sudo_prefix + ["pacman", "-Sy"])  # best-effort
        return run_quiet(sudo_prefix + ["pacman", "-S", "--noconfirm", "python-virtualenv"])

    # Alpine
    if command_exists("apk"):
        print("   - Using apk to install py3-virtualenv")
        return run_quiet(sudo_prefix + ["apk", "add", "--no-cache", "py3-virtualenv"])

    # Solus
    if command_exists("eopkg"):
        print("   - Using eopkg to install python3-virtualenv")
        return run_quiet(sudo_prefix + ["eopkg", "-y", "install", "python3-virtualenv"])

    # Void Linux
    if command_exists("xbps-install"):
        print("   - Using xbps-install to install python3-virtualenv")
        run_quiet(sudo_prefix + ["xbps-install", "-S"])  # best-effort
        return run_quiet(sudo_prefix + ["xbps-install", "-y", "python3-virtualenv"])

    return False

def bootstrap_pip_for_executable(python_executable: str) -> bool:
    """Install pip for the given Python interpreter using get-pip.py."""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            get_pip_path = os.path.join(tmpdir, "get-pip.py")
            url = "https://bootstrap.pypa.io/get-pip.py"
            try:
                with urllib.request.urlopen(url) as resp, open(get_pip_path, "wb") as f:
                    f.write(resp.read())
            except Exception:
                if command_exists("curl"):
                    subprocess.check_call(["curl", "-fsSL", url, "-o", get_pip_path])
                elif command_exists("wget"):
                    subprocess.check_call(["wget", "-qO", get_pip_path, url])
                else:
                    raise
            subprocess.check_call([python_executable, get_pip_path])
            subprocess.check_call([python_executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
    except Exception:
        return False

def create_compat_requirements(original_path: str) -> str:
    """Create a compatibility-adjusted requirements file.

    - For Python >= 3.12: bump numpy to a wheel-supported version to avoid sdist builds.
    Returns the path to the adjusted requirements file (requirements.compat.txt).
    """
    try:
        original = Path(original_path)
        if not original.exists():
            return original_path
        text = original.read_text(encoding="utf-8").splitlines()
        updated_lines = []
        py_maj, py_min = sys.version_info[:2]
        for line in text:
            fixed = line
            if py_maj >= 3 and py_min >= 12:
                # Replace known problematic numpy pin for Py 3.12
                if line.strip().startswith("numpy==1.24.3"):
                    fixed = "numpy==1.26.4"
            updated_lines.append(fixed)
        compat_path = Path(os.getcwd()) / "requirements.compat.txt"
        compat_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
        return str(compat_path)
    except Exception:
        return original_path

def get_venv_python_path(venv_dir: str) -> str:
    """Return the path to the venv's python interpreter for current OS."""
    if platform.system().lower() == "windows":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")

def create_virtualenv(venv_dir: str) -> str:
    """Create a virtual environment and return its python path. Raises on failure."""
    print("🧰 Creating isolated virtual environment at venv/.venv...")
    # Ensure parent exists
    os.makedirs(venv_dir, exist_ok=True)
    # Pre-clean partial venvs
    candidate_python = get_venv_python_path(venv_dir)
    if os.path.isdir(venv_dir) and not os.path.exists(candidate_python):
        print("♻️  Removing incomplete virtual environment at .venv...")
        shutil.rmtree(venv_dir, ignore_errors=True)
    # Create venv
    try:
        # Prefer system's python3.12 for Ubuntu 24.04 if available
        preferred_py = shutil.which("python3.12") or sys.executable
        subprocess.check_call([preferred_py, "-m", "venv", venv_dir])
    except Exception as e:
        print(f"⚠️ python -m venv failed: {e}")
        if is_linux():
            print("🛠 Attempting to install venv support via package manager (including version-specific package)...")
            if install_venv_via_pkg_manager():
                try:
                    subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
                except Exception as e2:
                    print(f"⚠️ venv still failing after install: {e2}")
            else:
                print("⚠️ Could not install venv support via package manager")
        # Fallback to virtualenv
        print("🔁 Falling back to virtualenv module to create environment...")
        # Ensure pip for current python
        if not ensure_pip_installed():
            raise RuntimeError("pip is not available to install virtualenv")
        pip_cmd = [sys.executable, "-m", "pip", "install", "virtualenv"]
        if is_linux() and not in_virtualenv() and not is_root():
            pip_cmd.append("--user")
        try:
            subprocess.check_call(pip_cmd)
        except subprocess.CalledProcessError:
            if is_linux() and not in_virtualenv():
                print("⚠️ Retrying virtualenv install with --break-system-packages...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--break-system-packages", "virtualenv"])
            else:
                raise
        subprocess.check_call([sys.executable, "-m", "virtualenv", venv_dir])

    venv_python = get_venv_python_path(venv_dir)
    if not os.path.exists(venv_python):
        raise RuntimeError(f"Virtual environment created but Python interpreter not found at {venv_python}")
    # Try to ensure pip inside venv
    pip_ok = False
    try:
        subprocess.check_call([venv_python, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pip_ok = True
    except Exception:
        # try ensurepip
        try:
            subprocess.check_call([venv_python, "-m", "ensurepip", "--upgrade"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call([venv_python, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pip_ok = True
        except Exception:
            # fallback to get-pip for venv
            pip_ok = bootstrap_pip_for_executable(venv_python)
    # Upgrade pip in venv (best-effort)
    if pip_ok:
        try:
            subprocess.check_call([venv_python, "-m", "pip", "install", "--upgrade", "pip"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    return venv_python

def ensure_pip_installed() -> bool:
    """Ensure pip is available for the current interpreter.

    Strategy:
      1) Try python -m pip --version
      2) Try python -m ensurepip --upgrade
      3) On Linux, try system package managers to install python3-pip
      4) Fallback to get-pip.py (user-level if not root)
    """
    print("\n🔎 Checking pip availability...")

    # 1) Already available?
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ pip is available")
        return True
    except Exception:
        pass

    # 2) Try ensurepip (may be disabled by distro)
    try:
        print("📦 Bootstrapping pip with ensurepip...")
        subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"])  # show output in case of prompts/errors
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("✅ pip installed via ensurepip")
        return True
    except Exception as e:
        print(f"⚠️ ensurepip failed or unavailable: {e}")

    # 3) Linux package managers
    if is_linux():
        print("🛠 Attempting to install python3-pip via system package manager...")
        if install_pip_via_pkg_manager():
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("✅ pip installed via system package manager")
                return True
            except Exception:
                print("⚠️ pip still not available after package manager install")

    # 4) Fallback to get-pip.py
    print("🌐 Falling back to get-pip.py...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            get_pip_path = os.path.join(tmpdir, "get-pip.py")
            url = "https://bootstrap.pypa.io/get-pip.py"
            try:
                with urllib.request.urlopen(url) as resp, open(get_pip_path, "wb") as f:
                    f.write(resp.read())
            except Exception as e:
                print(f"⚠️ Python urllib download failed: {e}")
                if command_exists("curl"):
                    subprocess.check_call(["curl", "-fsSL", url, "-o", get_pip_path])
                elif command_exists("wget"):
                    subprocess.check_call(["wget", "-qO", get_pip_path, url])
                else:
                    raise RuntimeError("Neither curl nor wget available to fetch get-pip.py")

            install_cmd = [sys.executable, get_pip_path]
            if not is_root() and not in_virtualenv():
                install_cmd.append("--user")
            subprocess.check_call(install_cmd)
            subprocess.check_call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("✅ pip installed via get-pip.py")
            return True
    except Exception as e:
        print(f"❌ Failed to bootstrap pip: {e}")
        return False

def install_dependencies():
    """Install required Python packages."""
    print("\n📦 Installing Python dependencies...")
    
    try:
        # Ensure requirements file exists
        if not os.path.exists("requirements.txt"):
            print("❌ requirements.txt not found")
            return False

        # Adjust requirements for Python 3.12+ compatibility (e.g., numpy)
        requirements_path = create_compat_requirements("requirements.txt")

        # On Linux, proactively use a local virtualenv to avoid PEP 668 issues
        if is_linux() and not in_virtualenv():
            try:
                # Ensure build deps on apt-based systems
                ensure_linux_build_dependencies()
                # Prefer 'venv' name for compatibility with user expectations
                venv_dir = os.path.join(os.getcwd(), "venv")
                venv_python = create_virtualenv(venv_dir)
                # Preinstall essential build tools to avoid sdist issues
                try:
                    subprocess.check_call([venv_python, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
                # Ensure build deps for numpy if building from source is needed
                try:
                    subprocess.check_call([venv_python, "-m", "pip", "install", "Cython"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
                # Install baseline core deps requested
                baseline = [
                    "fastapi",
                    "uvicorn[standard]",
                    "cryptography>=42.0.0",
                    "pyopenssl",
                    "pynacl"
                ]
                subprocess.check_call([venv_python, "-m", "pip", "install"] + baseline)
                subprocess.check_call([venv_python, "-m", "pip", "install", "-r", requirements_path])
                print("✅ Dependencies installed inside virtual environment (.venv)")
                return True
            except Exception as ve:
                print(f"⚠️ Virtual environment install failed: {ve}")
                print("⚠️ Falling back to system pip with PEP 668 handling...")

        # Non-Linux or fallback path: use system/user pip with safeguards
        if not ensure_pip_installed():
            print("❌ pip is not available and could not be installed")
            return False

        # Build base pip command; use --user when not root and not in a venv
        pip_base_cmd = [sys.executable, "-m", "pip", "install"]
        use_user = not is_root() and not in_virtualenv()
        if use_user:
            pip_base_cmd.append("--user")

        # Upgrade pip (best-effort; avoid PEP 668 noise on Linux root environments)
        try:
            if is_linux() and not in_virtualenv() and is_root():
                print("ℹ️ Skipping pip upgrade in system-wide Linux environment to avoid PEP 668 conflicts")
            else:
                upgrade_cmd = pip_base_cmd + ["--upgrade", "pip"]
                subprocess.check_call(upgrade_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print("⚠️ Failed to upgrade pip; proceeding with current version")

        # Install requirements with fallback for PEP 668
        try:
            # Preinstall basic build tools to reduce sdist issues
            try:
                subprocess.check_call(pip_base_cmd + ["--upgrade", "setuptools", "wheel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
            subprocess.check_call(pip_base_cmd + ["-r", requirements_path])
        except subprocess.CalledProcessError:
            if is_linux() and not in_virtualenv():
                print("⚠️ Retrying with --break-system-packages due to externally managed environment...")
                pip_bsp_cmd = [sys.executable, "-m", "pip", "install", "--break-system-packages"]
                if use_user:
                    pip_bsp_cmd.append("--user")
                subprocess.check_call(pip_bsp_cmd + ["-r", requirements_path]) 
            else:
                raise
        print("✅ Dependencies installed successfully")
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False
    
    return True

def create_directories():
    """Create necessary directories."""
    print("\n📁 Creating directories...")
    
    directories = [
        "logs",
        "data",
        "exports",
        "config"
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"✅ Created directory: {directory}")
        except Exception as e:
            print(f"❌ Failed to create directory {directory}: {e}")
            return False
    
    return True

def setup_platform_specific():
    """Setup platform-specific configurations."""
    system = platform.system().lower()
    print(f"\n🔧 Setting up {system}-specific configurations...")
    
    try:
        if system == "windows":
            setup_windows()
        elif system == "linux":
            setup_linux()
        elif system == "darwin":  # macOS
            setup_macos()
        else:
            setup_unix()
            
        print("✅ Platform-specific setup completed")
        return True
        
    except Exception as e:
        print(f"❌ Platform-specific setup failed: {e}")
        return False

def setup_windows():
    """Setup Windows-specific configurations."""
    try:
        # Create Windows service configuration
        service_config = {
            "service_name": "EmployeeMonitoring",
            "display_name": "Employee Monitoring System",
            "description": "Secure employee monitoring service",
            "start_type": "automatic"
        }
        
        with open("config/windows_service.json", "w") as f:
            json.dump(service_config, f, indent=2)
        
        # Create batch files for easy startup
        with open("start_server.bat", "w") as f:
            f.write("@echo off\n")
            f.write("cd /d %~dp0\n")
            f.write("python apps\\server\\main.py\n")
            f.write("pause\n")
        
        with open("start_client.bat", "w") as f:
            f.write("@echo off\n")
            f.write("cd /d %~dp0\n")
            f.write("python apps\\client\\main.py\n")
            f.write("pause\n")
        
        print("✅ Windows configurations created")
        
    except Exception as e:
        print(f"❌ Windows setup failed: {e}")

def setup_linux():
    """Setup Linux-specific configurations."""
    try:
        # Create startup script with venv preference
        launcher = """#!/bin/bash
set -e
cd "$(dirname "$0")"
PY="{py}"
if [ -x "./venv/bin/python" ]; then
    PY="./venv/bin/python"
elif [ -x "./.venv/bin/python" ]; then
    PY="./.venv/bin/python"
fi
exec "$PY" apps/server/main.py
""".format(py=sys.executable)

        with open("start_server.sh", "w") as f:
            f.write(launcher)

        with open("start_client.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("set -e\n")
            f.write("cd \"$(dirname \"$0\")\"\n")
            f.write(f"PY=\"{sys.executable}\"\n")
            f.write("if [ -x \"./venv/bin/python\" ]; then\n    PY=\"./venv/bin/python\"\nelif [ -x \"./.venv/bin/python\" ]; then\n    PY=\"./.venv/bin/python\"\nfi\n")
            f.write("exec \"$PY\" apps/client/main.py\n")

        # Make scripts executable
        os.chmod("start_server.sh", 0o755)
        os.chmod("start_client.sh", 0o755)

        # Create systemd service file that uses the launcher
        service_content = """[Unit]
Description=Employee Monitoring System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={wd}
ExecStart={wd}/start_server.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
""".format(wd=os.getcwd())
        
        with open("config/employee-monitoring.service", "w") as f:
            f.write(service_content)
        
        print("✅ Linux configurations created")
        
    except Exception as e:
        print(f"❌ Linux setup failed: {e}")

def setup_macos():
    """Setup macOS-specific configurations."""
    try:
        # Create launchd plist file
        plist_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.employeemonitoring.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>apps/server/main.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
""".format(sys.executable, os.getcwd())
        
        with open("config/com.employeemonitoring.server.plist", "w") as f:
            f.write(plist_content)
        
        # Create startup scripts
        with open("start_server.command", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("set -e\n")
            f.write("cd \"$(dirname \"$0\")\"\n")
            f.write("PY=\"{}\"\n".format(sys.executable))
            f.write("if [ -x \"./venv/bin/python\" ]; then\n    PY=\"./venv/bin/python\"\nelif [ -x \"./.venv/bin/python\" ]; then\n    PY=\"./.venv/bin/python\"\nfi\n")
            f.write("exec \"$PY\" apps/server/main.py\n")
        
        with open("start_client.command", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("set -e\n")
            f.write("cd \"$(dirname \"$0\")\"\n")
            f.write("PY=\"{}\"\n".format(sys.executable))
            f.write("if [ -x \"./venv/bin/python\" ]; then\n    PY=\"./venv/bin/python\"\nelif [ -x \"./.venv/bin/python\" ]; then\n    PY=\"./.venv/bin/python\"\nfi\n")
            f.write("exec \"$PY\" apps/client/main.py\n")
        
        # Make scripts executable
        os.chmod("start_server.command", 0o755)
        os.chmod("start_client.command", 0o755)
        
        print("✅ macOS configurations created")
        
    except Exception as e:
        print(f"❌ macOS setup failed: {e}")

def setup_unix():
    """Setup generic Unix configurations."""
    try:
        # Create startup scripts
        with open("start_server.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("cd \"$(dirname \"$0\")\"\n")
            f.write("PY=\"{}\"\n".format(sys.executable))
            f.write("if [ -x \"./venv/bin/python\" ]; then\n    PY=\"./venv/bin/python\"\nelif [ -x \"./.venv/bin/python\" ]; then\n    PY=\"./.venv/bin/python\"\nfi\n")
            f.write("exec \"$PY\" apps/server/main.py\n")
        
        with open("start_client.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("cd \"$(dirname \"$0\")\"\n")
            f.write("PY=\"{}\"\n".format(sys.executable))
            f.write("if [ -x \"./venv/bin/python\" ]; then\n    PY=\"./venv/bin/python\"\nelif [ -x \"./.venv/bin/python\" ]; then\n    PY=\"./.venv/bin/python\"\nfi\n")
            f.write("exec \"$PY\" apps/client/main.py\n")
        
        # Make scripts executable
        os.chmod("start_server.sh", 0o755)
        os.chmod("start_client.sh", 0o755)
        
        print("✅ Unix configurations created")
        
    except Exception as e:
        print(f"❌ Unix setup failed: {e}")

def create_config_files():
    """Create configuration files if they don't exist."""
    print("\n⚙️  Setting up configuration files...")
    
    try:
        # Create default config.ini if it doesn't exist
        if not os.path.exists("config.ini"):
            default_config = """[Server]
host = 0.0.0.0
port = 8080
max_clients = 250
max_connections_per_ip = 10
connection_timeout = 30
heartbeat_interval = 10

[Security]
encryption_key_size = 256
authentication_required = true
max_login_attempts = 3
session_timeout = 3600
rate_limit_requests = 100
rate_limit_window = 60

[Client]
screen_capture_interval = 1.0
image_quality = 85
compression_level = 6
max_image_size = 1920x1080
auto_reconnect = true
reconnect_delay = 5

[Database]
db_type = sqlite
db_path = data/monitoring.db
max_log_entries = 10000
log_retention_days = 90

[Logging]
log_level = INFO
log_file = logs/monitoring.log
max_log_size = 10MB
log_backup_count = 5

[GUI]
theme = dark
refresh_rate = 30
thumbnail_size = 200x150
grid_columns = 8
auto_arrange = true
"""
            
            with open("config.ini", "w") as f:
                f.write(default_config)
            
            print("✅ Created default config.ini")
        
        # Create logging configuration
        log_config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                }
            },
            "handlers": {
                "default": {
                    "level": "INFO",
                    "formatter": "standard",
                    "class": "logging.handlers.RotatingFileHandler",
                    "filename": "logs/monitoring.log",
                    "maxBytes": 10485760,
                    "backupCount": 5
                }
            },
            "loggers": {
                "": {
                    "handlers": ["default"],
                    "level": "INFO",
                    "propagate": True
                }
            }
        }
        
        with open("config/logging.json", "w") as f:
            json.dump(log_config, f, indent=2)
        
        print("✅ Created logging configuration")
        
    except Exception as e:
        print(f"❌ Failed to create configuration files: {e}")
        return False
    
    return True

def create_desktop_shortcuts():
    """Create desktop shortcuts for easy access."""
    print("\n🖥️  Creating desktop shortcuts...")
    
    try:
        system = platform.system().lower()
        
        if system == "windows":
            create_windows_shortcuts()
        elif system == "linux":
            create_linux_shortcuts()
        elif system == "darwin":
            create_macos_shortcuts()
        
        print("✅ Desktop shortcuts created")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create desktop shortcuts: {e}")
        return False

def create_windows_shortcuts():
    """Create Windows desktop shortcuts."""
    try:
        import winshell
        from win32com.client import Dispatch
        
        desktop = winshell.desktop()
        
        # Server shortcut
        server_shortcut = os.path.join(desktop, "Employee Monitoring Server.lnk")
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(server_shortcut)
        shortcut.Targetpath = sys.executable
        shortcut.Arguments = f'"{os.path.join(os.getcwd(), "server.py")}"'
        shortcut.WorkingDirectory = os.getcwd()
        shortcut.IconLocation = sys.executable
        shortcut.save()
        
        # Client shortcut
        client_shortcut = os.path.join(desktop, "Employee Monitoring Client.lnk")
        shortcut = shell.CreateShortCut(client_shortcut)
        shortcut.Targetpath = sys.executable
        shortcut.Arguments = f'"{os.path.join(os.getcwd(), "client.py")}"'
        shortcut.WorkingDirectory = os.getcwd()
        shortcut.IconLocation = sys.executable
        shortcut.save()
        
    except ImportError:
        print("⚠️  Windows shortcuts require pywin32 and winshell packages")

def create_linux_shortcuts():
    """Create Linux desktop shortcuts."""
    try:
        desktop = os.path.expanduser("~/Desktop")
        
        # Server shortcut
        server_desktop = os.path.join(desktop, "Employee Monitoring Server.desktop")
        with open(server_desktop, "w") as f:
            f.write("""[Desktop Entry]
Version=1.0
Type=Application
Name=Employee Monitoring Server
Comment=Start the monitoring server
Exec={}
Icon=utilities-terminal
Terminal=true
Categories=System;Monitor;
""".format(os.path.join(os.getcwd(), "start_server.sh")))
        
        # Client shortcut
        client_desktop = os.path.join(desktop, "Employee Monitoring Client.desktop")
        with open(client_desktop, "w") as f:
            f.write("""[Desktop Entry]
Version=1.0
Type=Application
Name=Employee Monitoring Client
Comment=Start the monitoring client
Exec={}
Icon=utilities-terminal
Terminal=true
Categories=System;Monitor;
""".format(os.path.join(os.getcwd(), "start_client.sh")))
        
        # Make shortcuts executable
        os.chmod(server_desktop, 0o755)
        os.chmod(client_desktop, 0o755)
        
    except Exception as e:
        print(f"⚠️  Linux shortcuts creation failed: {e}")

def create_macos_shortcuts():
    """Create macOS application shortcuts."""
    try:
        # Create Applications folder shortcut
        apps_dir = "/Applications"
        
        # Server app
        server_app = os.path.join(apps_dir, "Employee Monitoring Server.app")
        if not os.path.exists(server_app):
            os.makedirs(server_app + "/Contents/MacOS", exist_ok=True)
            
            # Create Info.plist
            info_plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>server_launcher</string>
    <key>CFBundleIdentifier</key>
    <string>com.employeemonitoring.server</string>
    <key>CFBundleName</key>
    <string>Employee Monitoring Server</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
</dict>
</plist>"""
            
            with open(server_app + "/Contents/Info.plist", "w") as f:
                f.write(info_plist)
            
            # Create launcher script
            launcher_script = f"""#!/bin/bash
cd "{os.getcwd()}"
{sys.executable} server.py
"""
            
            with open(server_app + "/Contents/MacOS/server_launcher", "w") as f:
                f.write(launcher_script)
            
            os.chmod(server_app + "/Contents/MacOS/server_launcher", 0o755)
        
    except Exception as e:
        print(f"⚠️  macOS shortcuts creation failed: {e}")

def run_tests():
    """Run basic tests to verify installation."""
    print("\n🧪 Running installation tests...")
    
    try:
        # Headless environment detection
        system = platform.system().lower()
        is_headless = False
        if system == 'linux':
            if not os.environ.get('DISPLAY') and not os.environ.get('WAYLAND_DISPLAY'):
                is_headless = True
                # Make Qt run without a display
                os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        
        # Test imports (conditionally skip GUI/input libs in headless)
        test_imports = [
            "cryptography",
            "PIL",
            "psutil",
            "numpy"
        ]
        # PySide6 can import offscreen
        test_imports.insert(0, "PySide6.QtWidgets")
        
        for module in test_imports:
            try:
                __import__(module)
                print(f"✅ {module} imported successfully")
            except ImportError:
                print(f"❌ {module} import failed")
                return False
        
        # Only test pyautogui when we have a display to avoid 'DISPLAY' errors
        if not is_headless:
            try:
                __import__("pyautogui")
                print("✅ pyautogui imported successfully")
            except ImportError:
                print("⚠️ pyautogui import skipped/failed (non-critical)")
        else:
            print("ℹ️ Headless environment detected; skipping pyautogui test")
        
        # Test file creation
        test_file = "test_installation.tmp"
        with open(test_file, "w") as f:
            f.write("test")
        
        if os.path.exists(test_file):
            os.remove(test_file)
            print("✅ File operations working")
        else:
            print("❌ File operations failed")
            return False
        
        print("✅ All tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Tests failed: {e}")
        return False

def print_usage_instructions():
    """Print usage instructions."""
    print("\n" + "=" * 60)
    print("🎉 Installation completed successfully!")
    print("=" * 60)
    
    system = platform.system().lower()
    
    print("\n📋 Usage Instructions:")
    print("\n1. Start the Server:")
    if system == "windows":
        print("   - Double-click 'start_server.bat'")
        print("   - Or run: python server.py")
    elif system == "linux":
        print("   - Run: ./start_server.sh")
        print("   - Or run: python3 server.py")
    elif system == "darwin":
        print("   - Run: ./start_server.command")
        print("   - Or run: python3 server.py")
    else:
        print("   - Run: python3 server.py")
    
    print("\n2. Start the Client (on employee machines):")
    if system == "windows":
        print("   - Double-click 'start_client.bat'")
        print("   - Or run: python client.py")
    elif system == "linux":
        print("   - Run: ./start_client.sh")
        print("   - Or run: python3 client.py")
    elif system == "darwin":
        print("   - Run: ./start_client.command")
        print("   - Or run: python3 client.py")
    else:
        print("   - Run: python3 client.py")
    
    print("\n3. Access the Server GUI:")
    print("   - The server will open a GUI window automatically")
    print("   - Click 'Start Server' to begin monitoring")
    
    print("\n4. Configuration:")
    print("   - Edit 'config.ini' to customize settings")
    print("   - Logs are stored in the 'logs' directory")
    print("   - Data is stored in the 'data' directory")
    
    print("\n🔒 Security Features:")
    print("   - End-to-end encryption (AES-256)")
    print("   - Authentication and session management")
    print("   - Rate limiting and abuse prevention")
    print("   - Audit logging and monitoring")
    print("   - Cross-platform security features")
    
    print("\n📁 Directory Structure:")
    print("   - logs/          : Application logs")
    print("   - data/          : Database and data files")
    print("   - exports/       : Exported monitoring data")
    print("   - config/        : Configuration files")
    
    print("\n⚠️  Important Notes:")
    print("   - Ensure firewall allows connections on port 8080")
    print("   - Run server with appropriate permissions")
    print("   - Monitor logs for security events")
    print("   - Regular backups of the data directory")
    
    print("\n" + "=" * 60)

def main():
    """Main installation function."""
    print_banner()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Installation failed at dependency installation step")
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        print("\n❌ Installation failed at directory creation step")
        sys.exit(1)
    
    # Setup platform-specific configurations
    if not setup_platform_specific():
        print("\n❌ Installation failed at platform-specific setup step")
        sys.exit(1)
    
    # Create configuration files
    if not create_config_files():
        print("\n❌ Installation failed at configuration creation step")
        sys.exit(1)
    
    # Create desktop shortcuts
    create_desktop_shortcuts()
    
    # Run tests
    if not run_tests():
        print("\n❌ Installation failed at testing step")
        sys.exit(1)
    
    # Print usage instructions
    print_usage_instructions()
    
    print("\n🎯 Installation completed successfully!")
    print("You can now start using the Employee Monitoring System.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n❌ Installation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Installation failed with error: {e}")
        sys.exit(1)
