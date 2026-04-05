"""pytest configuration — wires sys.modules aliases required for the plugin
to be importable outside the A0 runtime.

BOOTSTRAP ORDER IS CRITICAL — each step depends on the previous:

    Step 1: sys.path  — plugin root on path
    Step 2: helpers.config imported, registered as sys.modules['openbao_config']
    Step 3: helpers.openbao_client imported (needs openbao_config already registered)
    Step 4: registered as sys.modules['openbao_client']
    Step 5: helpers.secrets mock registered (needed by openbao_secrets_manager)

The plugin's helpers/openbao_secrets_manager.py uses three bare-name imports
that are only present in sys.modules when loaded via factory_common at runtime:

    from helpers.secrets import ...   (A0 core module — mocked here)
    from openbao_config import ...    (helpers/config.py, alias set by factory_common)
    from openbao_client import ...    (helpers/openbao_client.py, alias set by factory_common)
"""
from __future__ import annotations

import os
import sys
import threading
from unittest.mock import MagicMock

# ── Step 1: Ensure plugin root is on sys.path ──────────────────────────────
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.dirname(_TESTS_DIR)
if _PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, _PLUGIN_ROOT)

# ── Step 2: Import helpers.config and register as 'openbao_config' ────────
# MUST happen before importing helpers.openbao_client (which does
# `from openbao_config import OpenBaoConfig` at module level).
import helpers.config as _config_mod  # noqa: E402
sys.modules["openbao_config"] = _config_mod

# ── Step 3+4: Now import helpers.openbao_client (openbao_config ready) ────
import helpers.openbao_client as _client_mod  # noqa: E402
sys.modules.setdefault("openbao_client", _client_mod)

# ── Step 5: Mock helpers.secrets (A0 core — absent outside A0 runtime) ────
# openbao_secrets_manager.py does `from helpers.secrets import SecretsManager, ...`
# We provide a minimal compatible stand-in.  The test_openbao_manager.py
# fixture-level mocks remain in control of specific behaviour under test.


class _MockSecretsManager:
    """Minimal stand-in for python.helpers.secrets.SecretsManager."""

    PLACEHOLDER_PATTERN = r"dummy"
    MASK_VALUE = "***"
    _instances: dict = {}

    def __init__(self, *files: str) -> None:
        self._lock = threading.RLock()
        self._files = tuple(files) if files else ("usr/secrets.env",)
        self._raw_snapshots: dict = {}
        self._secrets_cache = None
        self._last_raw_text = None

    @classmethod
    def get_instance(cls, *files: str) -> "_MockSecretsManager":
        key = tuple(files)
        if key not in cls._instances:
            cls._instances[key] = cls(*files)
        return cls._instances[key]

    def load_secrets(self) -> dict:
        """Return a single fallback secret so .env-fallback tests work."""
        return {"FALLBACK_KEY": "fallback-value"}

    def get_keys(self) -> list:
        return list(self.load_secrets().keys())

    def get_secrets_for_prompt(self) -> str:
        return ""

    def save_secrets(self, secrets_content: str) -> None:  # noqa: ARG002
        raise NotImplementedError("read-only mock")

    def save_secrets_with_merge(self, submitted_content: str) -> None:  # noqa: ARG002
        raise NotImplementedError("read-only mock")

    def clear_cache(self) -> None:
        self._secrets_cache = None
        self._raw_snapshots = {}
        self._last_raw_text = None

    @classmethod
    def _invalidate_all_caches(cls) -> None:
        for inst in cls._instances.values():
            inst.clear_cache()


# LOW-06: Intentional format divergence from production.
# Production alias_for_key uses "⟦key⟧" format with Unicode brackets.
# Mock uses "secret_alias(KEY)" — simpler format avoids Unicode handling
# in test assertions while still exercising the key→alias mapping logic.
# If production format changes, update this mock to match.
def _mock_alias_for_key(key: str, placeholder: str = "secret_alias({key})") -> str:
    return placeholder.format(key=key.upper())


_mock_secrets_mod = MagicMock()
_mock_secrets_mod.SecretsManager = _MockSecretsManager
_mock_secrets_mod.alias_for_key = _mock_alias_for_key
_mock_secrets_mod.DEFAULT_SECRETS_FILE = "usr/secrets.env"

# Register under the bare key used by openbao_secrets_manager.py AND the
# dotted keys used by test_openbao_manager.py's own setdefault() calls.
sys.modules.setdefault("helpers.secrets", _mock_secrets_mod)
sys.modules.setdefault("python", MagicMock())
sys.modules.setdefault("python.helpers", MagicMock())
sys.modules.setdefault("python.helpers.secrets", _mock_secrets_mod)
