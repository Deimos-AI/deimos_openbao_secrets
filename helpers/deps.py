"""Dependency verification for the OpenBao secrets plugin.

MED-05: Replaced runtime auto-install with a startup check that fails loudly
with clear install instructions. All versions are pinned in requirements.txt.
LOW-01: Thread-safe via threading.Lock().

To install dependencies:
    pip install -r requirements.txt
"""
import importlib
import logging
import threading

logger = logging.getLogger(__name__)

# MED-05: Pinned exact versions — must match requirements.txt
_REQUIRED = [
    ("hvac", "hvac==2.1.0"),
    ("tenacity", "tenacity==8.2.0"),
    ("circuitbreaker", "circuitbreaker==2.0.0"),
    ("aiohttp", "aiohttp==3.9.0"),
]

_installed = False
_lock = threading.Lock()  # LOW-01: thread-safe guard


def ensure_dependencies() -> bool:
    """Check that all required dependencies are available.

    Returns True if all dependencies are importable. Returns False and logs
    a clear install instruction if any dependency is missing.

    MED-05: No longer auto-installs — fails loudly with instructions instead.
    LOW-01: Thread-safe via module-level lock.
    """
    global _installed

    if _installed:
        return True

    with _lock:  # LOW-01
        if _installed:
            return True

        missing = []
        for import_name, pinned_spec in _REQUIRED:
            try:
                importlib.import_module(import_name)
            except ImportError:
                missing.append(pinned_spec)

        if not missing:
            _installed = True
            return True

        # MED-05: Fail loudly with clear install instructions
        logger.error(
            "OpenBao plugin dependencies not installed: %s. "
            "Install with: pip install -r requirements.txt "
            "(from the deimos_openbao_secrets plugin directory)",
            ", ".join(missing),
        )
        return False
