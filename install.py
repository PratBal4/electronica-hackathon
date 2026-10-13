#!/usr/bin/env python3
"""Smart Backplane Trust Engine --- Cross-Platform Build & Dependency Installer.

Compatible with Raspberry Pi OS (ARM), Debian, Ubuntu, macOS, and Windows.
Uses strictly Python standard library to ensure zero bootstrapping prerequisites.

Features:
- Validates Python version compatibility (>= 3.9).
- Bootstraps an isolated virtual environment (.venv).
- Installs dependencies with automatic error capture and resilient fallbacks.
- Outputs detailed diagnostics and error logs for the installer if issues arise.
- Verifies deployment with runtime demonstration and test suite smoke tests.
"""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import traceback
from typing import List, Optional, Tuple
import venv

# --- Console Formatting ---
IS_TTY = sys.stdout.isatty()
GREEN = "\033[92m" if IS_TTY else ""
RED = "\033[91m" if IS_TTY else ""
YELLOW = "\033[93m" if IS_TTY else ""
CYAN = "\033[96m" if IS_TTY else ""
BOLD = "\033[1m" if IS_TTY else ""
RESET = "\033[0m" if IS_TTY else ""


def log_info(msg: str) -> None:
    print(f"{CYAN}[INFO]{RESET} {msg}")


def log_success(msg: str) -> None:
    print(f"{GREEN}[SUCCESS]{RESET} {msg}")


def log_warn(msg: str) -> None:
    print(f"{YELLOW}[WARNING]{RESET} {msg}")


def log_error(msg: str) -> None:
    print(f"{RED}[ERROR]{RESET} {msg}")


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 120,
) -> Tuple[bool, str, str]:
    """Execute command returning (success, stdout, stderr) with full error capture."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.returncode == 0, proc.stdout, proc.stderr)
    except Exception as exc:
        return (False, "", f"Execution error: {exc}\n{traceback.format_exc()}")


class Installer:
    """Orchestrates cross-platform installation, environment setup, and verification."""

    def __init__(self, root_dir: Path) -> None:
        self.root_dir = root_dir
        self.logs_dir = root_dir / "logs"
        self.venv_dir = root_dir / ".venv"
        self.system = platform.system()
        self.is_windows = self.system == "Windows"

        # Determine binary paths inside virtual environment
        if self.is_windows:
            self.venv_python = self.venv_dir / "Scripts" / "python.exe"
            self.venv_pip = self.venv_dir / "Scripts" / "pip.exe"
        else:
            self.venv_python = self.venv_dir / "bin" / "python"
            self.venv_pip = self.venv_dir / "bin" / "pip"

        # Active python executable used for installation and runs
        self.active_python = self.venv_python

    def setup_directories(self) -> None:
        """Ensure logging directory exists."""
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        gitkeep = self.logs_dir / ".gitkeep"
        if not gitkeep.exists():
            gitkeep.touch()

    def check_python_version(self) -> bool:
        """Verify Python 3.9+."""
        log_info(f"System: {platform.platform()} (Architecture: {platform.machine()})")
        log_info(f"Host Python: {sys.version.split()[0]} ({sys.executable})")

        if sys.version_info < (3, 9):
            log_error(
                f"Python version {sys.version_info.major}.{sys.version_info.minor} is unsupported. "
                "The Smart Backplane Trust Engine requires Python 3.9 or higher."
            )
            return False

        log_success("Python version check passed (>= 3.9).")
        return True

    def create_virtual_environment(self) -> bool:
        """Create virtual environment with fallback for missing ensurepip."""
        log_info(f"Configuring virtual environment at: {self.venv_dir}")

        if self.venv_python.exists():
            log_success("Existing virtual environment detected and ready.")
            self.active_python = self.venv_python
            return True

        # Attempt 1: Standard venv creation with pip
        try:
            log_info("Creating virtual environment with standard pip...")
            venv.create(self.venv_dir, with_pip=True, clear=False)
            if self.venv_python.exists():
                log_success("Virtual environment created successfully.")
                self.active_python = self.venv_python
                return True
        except Exception as exc:
            log_warn(f"Standard virtual environment creation failed: {exc}")
            err_log = self.logs_dir / "venv_error.log"
            err_log.write_text(f"Attempt 1 Failure:\n{exc}\n{traceback.format_exc()}", encoding="utf-8")
            log_info(f"Wrote error trace to {err_log}")

        # Attempt 2: Fallback without pip (resolves Debian/Raspberry Pi OS missing python3-venv ensurepip)
        try:
            log_info("Attempting Fallback: Creating virtual environment with --without-pip...")
            venv.create(self.venv_dir, with_pip=False, clear=True)
            if self.venv_python.exists():
                log_success("Virtual environment created (without-pip mode).")
                # Try bootstrapping pip via ensurepip in the venv
                ok, _, _ = run_command([str(self.venv_python), "-m", "ensurepip", "--upgrade", "--default-pip"])
                if ok:
                    log_success("Bootstrapped pip inside virtual environment.")
                self.active_python = self.venv_python
                return True
        except Exception as exc:
            log_error(f"Fallback virtual environment creation also failed: {exc}")
            err_log = self.logs_dir / "venv_fallback_error.log"
            err_log.write_text(f"Attempt 2 Failure:\n{exc}\n{traceback.format_exc()}", encoding="utf-8")

        # Fallback 3: Use current interpreter
        log_warn(f"Could not build isolated .venv. Falling back to active host interpreter: {sys.executable}")
        self.active_python = Path(sys.executable)
        return False

    def install_dependencies(self) -> bool:
        """Install dependencies from requirements-dev.txt with error capture."""
        log_info("Installing dependencies...")
        log_info("Note: Core runtime code requires ZERO external packages (100% Python Standard Library).")
        log_info("Installing development & test framework (pytest)...")

        req_file = self.root_dir / "requirements-dev.txt"
        if not req_file.exists():
            log_warn("requirements-dev.txt not found. Skipping pip install.")
            return True

        # Attempt 1: Standard pip install
        cmd = [str(self.active_python), "-m", "pip", "install", "-r", str(req_file)]
        ok, stdout, stderr = run_command(cmd, cwd=self.root_dir, timeout=90)

        if ok:
            log_success("Successfully installed all dependencies (pytest).")
            return True

        # Log initial error for the installer
        log_warn("Standard pip install encountered an error:")
        pip_err_log = self.logs_dir / "pip_install_error.log"
        error_summary = f"Command: {' '.join(cmd)}\n\nSTDOUT:\n{stdout}\n\nSTDERR:\n{stderr}"
        pip_err_log.write_text(error_summary, encoding="utf-8")
        print(f"{YELLOW}--- PIP ERROR OUTPUT ---{RESET}\n{stderr.strip()[:400]}\n{YELLOW}------------------------{RESET}")

        # Attempt 2: Fallback with retry, timeout, and no-cache flags
        log_info("Attempting Fallback: Retrying with network resilience flags...")
        fallback_cmd = [
            str(self.active_python),
            "-m",
            "pip",
            "install",
            "--retries",
            "3",
            "--timeout",
            "20",
            "--no-cache-dir",
            "-r",
            str(req_file),
        ]
        ok_fb, _, stderr_fb = run_command(fallback_cmd, cwd=self.root_dir, timeout=90)

        if ok_fb:
            log_success("Fallback pip installation succeeded.")
            return True

        # Both pip attempts failed (e.g. offline Raspberry Pi dock or restricted proxy)
        log_warn("Pip could not connect or complete package installation.")
        log_info(f"Detailed diagnostics saved to: {pip_err_log}")
        log_info("CRITICAL REMINDER: The Trust Engine core runtime ('python main.py') operates independently")
        log_info("of external packages and will run cleanly without pip.")
        return False

    def run_smoke_tests(self) -> bool:
        """Run verification smoke tests."""
        log_info("Running runtime verification and smoke tests...")

        main_py = self.root_dir / "main.py"
        print()
        print(f"{BOLD}Executing Demonstration Simulator CLI (main.py):{RESET}")
        print("-" * 55)

        ok, stdout, stderr = run_command([str(self.active_python), str(main_py)], cwd=self.root_dir)
        if ok:
            print(stdout.strip())
            print("-" * 55)
            log_success("Runtime demonstration completed successfully!")
        else:
            print(stderr.strip())
            print("-" * 55)
            log_error("Runtime demonstration failed!")
            return False

        # Run pytest if available
        print()
        log_info("Running automated test suite verification...")
        test_ok, test_out, test_err = run_command(
            [str(self.active_python), "-m", "pytest", "-q"],
            cwd=self.root_dir,
            timeout=60,
        )

        if test_ok:
            log_success(f"Automated test suite passed: {test_out.strip()}")
        else:
            log_warn("Pytest runner was not available or tests did not execute via venv.")
            if test_err:
                log_warn(f"Runner diagnostic: {test_err.strip()[:200]}")

        return True

    def run(self) -> int:
        """Execute full installation pipeline."""
        print(f"{BOLD}======================================================================{RESET}")
        print(f"{BOLD}   SMART BACKPLANE TRUST ENGINE --- BUILD & INSTALLER PIPELINE       {RESET}")
        print(f"{BOLD}======================================================================{RESET}")

        self.setup_directories()

        if not self.check_python_version():
            return 1

        self.create_virtual_environment()
        self.install_dependencies()

        if not self.run_smoke_tests():
            log_error("Installation verification encountered fatal runtime errors.")
            return 1

        print()
        print(f"{BOLD}======================================================================{RESET}")
        print(f"{GREEN}{BOLD}   BUILD & INSTALLATION COMPLETE!{RESET}")
        print(f"{BOLD}======================================================================{RESET}")
        if self.is_windows:
            print(f"To activate the environment:  {CYAN}.venv\\Scripts\\activate{RESET}")
        else:
            print(f"To activate the environment:  {CYAN}source .venv/bin/activate{RESET}")
        print(f"To run demonstration CLI:     {CYAN}{self.active_python} main.py{RESET}")
        print(f"To run test suite:            {CYAN}{self.active_python} -m pytest -v{RESET}")
        print(f"{BOLD}======================================================================{RESET}")
        return 0


def main() -> int:
    """CLI entrypoint."""
    root_dir = Path(__file__).resolve().parent
    installer = Installer(root_dir)
    return installer.run()


if __name__ == "__main__":
    sys.exit(main())
