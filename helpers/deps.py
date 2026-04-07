"""Dependency verification and auto-install for the OpenBao secrets plugin.

MED-05: Pinned exact versions for reproducible installs. Missing deps are
auto-installed via ``pip install`` on first call.
LOW-01: Thread-safe via threading.Lock().

To install dependencies manually:
    pip install -r requirements.txt
"""
import importlib
import logging
import subprocess
import sys
import threading

logger = logging.getLogger(__name__)

# MED-05: Pinned exact versions — must match requirements.txt
_REQUIRED = [
    ("hvac", "hvac==2.1.0"),
    ("tenacity", "tenacity==8.2.0"),
    ("circuitbreaker", "circuitbreaker==2.0.0"),
    ("aiohttp", "aiohttp==3.10.11"),
]

_installed = False
_lock = threading.Lock()  # LOW-01: thread-safe guard


def ensure_dependencies() -> bool:
    """Check that all required dependencies are available, auto-installing any that are missing.

    Returns True if all dependencies are importable (either already present or
    successfully installed).  Returns False if any dependency could not be
    installed or imported after installation.

    MED-05: Auto-installs missing deps using pinned specs from _REQUIRED.
    LOW-01: Thread-safe via module-level lock; idempotent after first success.
    """
    global _installed

    if _installed:
        return True

    with _lock:  # LOW-01
        if _installed:
            return True

        # Fast path — check if everything is already importable
        missing = []
        for import_name, pinned_spec in _REQUIRED:
            try:
                importlib.import_module(import_name)
            except ImportError:
                missing.append((import_name, pinned_spec))

        if not missing:
            _installed = True
            return True

        # Auto-install missing packages one at a time
        logger.info(
            "OpenBao plugin: auto-installing missing dependencies: %s",
            ", ".join(spec for _, spec in missing),
        )

        failed = []
        for import_name, pinned_spec in missing:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--quiet", pinned_spec],
                )
            except subprocess.CalledProcessError as exc:
                logger.warning(
                    "OpenBao plugin: pip install %s failed: %s", pinned_spec, exc,
                )
                failed.append(pinned_spec)
                continue

            # Re-check the import after install
            try:
                importlib.import_module(import_name)
            except ImportError:
                logger.warning(
                    "OpenBao plugin: %s still not importable after pip install",
                    import_name,
                )
                failed.append(pinned_spec)

        if failed:
            logger.error(
                "OpenBao plugin: failed to install dependencies: %s. "
                "Install manually with: pip install -r requirements.txt",
                ", ".join(failed),
            )
            return False

        _installed = True
        logger.info("OpenBao plugin: all dependencies installed successfully.")
        return True
