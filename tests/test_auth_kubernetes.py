"""tests/test_auth_kubernetes.py

E-05: Kubernetes auth method — pod service account JWT exchange.

Covers:
  AC-01 — kubernetes auth_method routes to _auth_kubernetes()
  AC-02 — _auth_kubernetes() reads JWT and calls hvac kubernetes login
  AC-03 — missing JWT file -> graceful degradation (client=None, no exception)
  AC-04 — empty k8s_role raises RuntimeError
  AC-05 — OpenBaoConfig has 3 new K8s fields with correct defaults
  AC-06 — _FIELD_TO_ENV has K8S_ROLE, K8S_JWT_PATH, K8S_MOUNT_PATH
  AC-07 — auth_method Literal accepts 'kubernetes'
  AC-08 — default_config.yaml contains k8s_role commented example
  AC-10 — JWT content never logged; only role prefix logged

Satisfies: E-05 AC-11
"""
import importlib.util
import os
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

_PLUGIN_DIR = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Module loaders
# ---------------------------------------------------------------------------

def _load_config_module():
    spec = importlib.util.spec_from_file_location(
        "deimos_openbao_secrets_config_k8s_test",
        _PLUGIN_DIR / "helpers" / "config.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["deimos_openbao_secrets_config_k8s_test"] = mod  # register before exec (circular import guard)
    spec.loader.exec_module(mod)
    return mod


def _load_client_module():
    """Load openbao_client.py with openbao_config injected into sys.modules."""
    config_mod = _load_config_module()
    sys.modules["openbao_config"] = config_mod
    spec = importlib.util.spec_from_file_location(
        "openbao_client_k8s_test",
        _PLUGIN_DIR / "helpers" / "openbao_client.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_k8s_config(config_mod, **overrides):
    """Return an OpenBaoConfig with kubernetes auth_method and test defaults."""
    defaults = dict(
        enabled=True,
        url="http://127.0.0.1:8200",
        auth_method="kubernetes",
        k8s_role="agent-zero-role",
        k8s_jwt_path="/var/run/secrets/kubernetes.io/serviceaccount/token",
        k8s_mount_path="kubernetes",
    )
    defaults.update(overrides)
    return config_mod.OpenBaoConfig(**defaults)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_env(monkeypatch):
    """Remove all OPENBAO_* env vars before each test."""
    for key in list(os.environ):
        if key.startswith("OPENBAO_"):
            monkeypatch.delenv(key, raising=False)
    yield


# ---------------------------------------------------------------------------
# AC-05, AC-06, AC-07: Config dataclass and _FIELD_TO_ENV
# ---------------------------------------------------------------------------

class TestOpenBaoConfigK8sFields:
    """AC-05, AC-06, AC-07: New K8s config fields."""

    def test_k8s_fields_exist_with_correct_defaults(self):
        """AC-05: three new K8s fields present with expected defaults."""
        mod = _load_config_module()
        cfg = mod.OpenBaoConfig()
        assert cfg.k8s_role == ""  # AC-05
        assert cfg.k8s_jwt_path == "/var/run/secrets/kubernetes.io/serviceaccount/token"  # AC-05
        assert cfg.k8s_mount_path == "kubernetes"  # AC-05

    def test_field_to_env_has_k8s_entries(self):
        """AC-06: _FIELD_TO_ENV includes K8S_ROLE, K8S_JWT_PATH, K8S_MOUNT_PATH."""
        mod = _load_config_module()
        assert mod._FIELD_TO_ENV.get("k8s_role") == "K8S_ROLE"        # AC-06
        assert mod._FIELD_TO_ENV.get("k8s_jwt_path") == "K8S_JWT_PATH"   # AC-06
        assert mod._FIELD_TO_ENV.get("k8s_mount_path") == "K8S_MOUNT_PATH"  # AC-06

    def test_auth_method_literal_accepts_kubernetes(self):
        """AC-07: auth_method='kubernetes' is valid (no TypeError or ValueError)."""
        mod = _load_config_module()
        cfg = mod.OpenBaoConfig(auth_method="kubernetes")
        assert cfg.auth_method == "kubernetes"  # AC-07

    def test_k8s_env_vars_loaded_by_load_config(self, tmp_path, clean_env):
        """AC-06: OPENBAO_K8S_* env vars are loaded via _FIELD_TO_ENV loop."""
        with patch.dict(os.environ, {
            "OPENBAO_K8S_ROLE": "my-cluster-role",
            "OPENBAO_K8S_MOUNT_PATH": "custom-k8s",
        }):
            cfg = _load_config_module().load_config(str(tmp_path))
        assert cfg.k8s_role == "my-cluster-role"   # AC-06: env var loaded
        assert cfg.k8s_mount_path == "custom-k8s"  # AC-06: env var loaded

    def test_k8s_env_vars_tracked_in_sources(self, tmp_path, clean_env):
        """AC-06/E-04: K8s env vars auto-tracked in _sources."""
        with patch.dict(os.environ, {
            "OPENBAO_K8S_ROLE": "my-role",
            "OPENBAO_K8S_MOUNT_PATH": "custom-k8s",
        }):
            cfg = _load_config_module().load_config(str(tmp_path))
        assert cfg._sources.get("k8s_role") == "env"         # AC-06: source tracked
        assert cfg._sources.get("k8s_mount_path") == "env"   # AC-06: source tracked


# ---------------------------------------------------------------------------
# AC-08: default_config.yaml contains K8s example block
# ---------------------------------------------------------------------------

def test_default_config_yaml_has_k8s_example():
    """AC-08: default_config.yaml contains the K8s auth comment block."""
    yaml_path = _PLUGIN_DIR / "default_config.yaml"
    content = yaml_path.read_text()
    assert "k8s_role" in content          # AC-08: k8s_role present
    assert "k8s_jwt_path" in content      # AC-08: k8s_jwt_path present
    assert "k8s_mount_path" in content    # AC-08: k8s_mount_path present
    assert "kubernetes" in content        # AC-08: kubernetes auth_method shown


# ---------------------------------------------------------------------------
# AC-01, AC-02, AC-03, AC-04, AC-10: _auth_kubernetes() behaviour
# ---------------------------------------------------------------------------

class TestAuthKubernetesMethod:
    """AC-01, AC-02, AC-03, AC-04, AC-10."""

    def _make_mock_hvac_client(self):
        mock_client = MagicMock()
        mock_client.auth.kubernetes.login.return_value = {
            "auth": {"client_token": "s.test-vault-token"}
        }
        return mock_client

    def _make_k8s_openbao_client(self, mod, config_mod, cfg):
        """Build an OpenBaoClient instance bypassing _connect()."""
        c = object.__new__(mod.OpenBaoClient)
        c._config = cfg
        c._client = self._make_mock_hvac_client()
        c._cache = MagicMock()
        c._lock = threading.RLock()
        c._token_expiry = 0.0
        c._reconnect_at = 0.0
        c._is_sealed = False
        c._init_attempted = False
        return c

    def test_auth_kubernetes_reads_jwt_and_calls_login(self, tmp_path):
        """AC-02: _auth_kubernetes() reads JWT file and calls hvac kubernetes login."""
        mod = _load_client_module()
        config_mod = _load_config_module()
        jwt_file = tmp_path / "sa.token"
        jwt_file.write_text("eyJhbGciOiJSUzI1NiJ9.test-jwt-payload")
        cfg = _make_k8s_config(config_mod, k8s_jwt_path=str(jwt_file))

        c = self._make_k8s_openbao_client(mod, config_mod, cfg)
        c._auth_kubernetes()  # AC-02

        c._client.auth.kubernetes.login.assert_called_once_with(
            role="agent-zero-role",
            jwt="eyJhbGciOiJSUzI1NiJ9.test-jwt-payload",
            mount_point="kubernetes",
        )  # AC-02
        assert c._client.token == "s.test-vault-token"  # AC-02: token set in memory

    def test_auth_kubernetes_missing_jwt_sets_client_none(self, tmp_path):
        """AC-03: absent JWT file -> client set to None, no exception."""
        mod = _load_client_module()
        config_mod = _load_config_module()
        cfg = _make_k8s_config(
            config_mod,
            k8s_jwt_path=str(tmp_path / "nonexistent.token")
        )
        c = self._make_k8s_openbao_client(mod, config_mod, cfg)
        # AC-03: must not raise
        c._auth_kubernetes()
        assert c._client is None  # AC-03: graceful degradation

    def test_auth_kubernetes_empty_role_raises_runtime_error(self, tmp_path):
        """AC-04: empty k8s_role raises RuntimeError directing operator."""
        mod = _load_client_module()
        config_mod = _load_config_module()
        jwt_file = tmp_path / "sa.token"
        jwt_file.write_text("test-jwt")
        cfg = _make_k8s_config(config_mod, k8s_role="", k8s_jwt_path=str(jwt_file))

        c = self._make_k8s_openbao_client(mod, config_mod, cfg)
        with pytest.raises(RuntimeError) as exc_info:
            c._auth_kubernetes()  # AC-04
        assert "k8s_role" in str(exc_info.value).lower() or \
               "kubernetes" in str(exc_info.value).lower()  # AC-04

    def test_auth_kubernetes_uses_configured_mount_path(self, tmp_path):
        """AC-02: _auth_kubernetes() uses config.k8s_mount_path for hvac login."""
        mod = _load_client_module()
        config_mod = _load_config_module()
        jwt_file = tmp_path / "sa.token"
        jwt_file.write_text("eyJ0.test")
        cfg = _make_k8s_config(
            config_mod,
            k8s_jwt_path=str(jwt_file),
            k8s_mount_path="custom-k8s-mount",
        )
        c = self._make_k8s_openbao_client(mod, config_mod, cfg)
        c._auth_kubernetes()

        call_kwargs = c._client.auth.kubernetes.login.call_args[1]
        assert call_kwargs["mount_point"] == "custom-k8s-mount"  # AC-02

    def test_auth_kubernetes_jwt_not_logged(self, tmp_path, caplog):
        """AC-10: JWT content never appears in log output."""
        import logging
        mod = _load_client_module()
        config_mod = _load_config_module()
        jwt_file = tmp_path / "sa.token"
        secret_jwt = "eyJhbGciOiJSUzI1NiJ9.SUPER-SECRET-PAYLOAD"
        jwt_file.write_text(secret_jwt)
        cfg = _make_k8s_config(config_mod, k8s_jwt_path=str(jwt_file))

        c = self._make_k8s_openbao_client(mod, config_mod, cfg)
        with caplog.at_level(logging.DEBUG):
            c._auth_kubernetes()

        for record in caplog.records:
            assert secret_jwt not in record.getMessage()  # AC-10: JWT never logged

    def test_connect_dispatches_kubernetes_auth(self, tmp_path, clean_env):
        """AC-01: _connect() elif branch calls _auth_kubernetes for 'kubernetes' auth."""
        mod = _load_client_module()
        config_mod = _load_config_module()
        cfg = _make_k8s_config(config_mod)

        mock_hvac = MagicMock()
        mock_instance = mock_hvac.return_value
        mock_instance.is_authenticated.return_value = True
        mock_instance.sys.read_health_status.return_value = {"initialized": True}

        with patch.dict(sys.modules, {"hvac": mock_hvac}), \
             patch.object(mod.OpenBaoClient, "_auth_kubernetes") as mock_k8s, \
             patch.object(mod.OpenBaoClient, "_update_token_expiry"), \
             patch.object(mod.OpenBaoClient, "_reconnect"):
            mock_k8s.return_value = None
            c = object.__new__(mod.OpenBaoClient)
            c._config = cfg
            c._client = None
            c._cache = MagicMock()
            c._lock = threading.RLock()
            c._token_expiry = 0.0
            c._reconnect_at = 0.0
            c._is_sealed = False
            c._init_attempted = False
            with patch.object(mod, "hvac", mock_hvac):
                c._connect()

        mock_k8s.assert_called_once()  # AC-01: kubernetes branch dispatched

    def test_kubernetes_auth_not_called_for_approle(self, tmp_path, clean_env):
        """AC-01: _auth_kubernetes NOT called when auth_method=approle."""
        mod = _load_client_module()
        config_mod = _load_config_module()
        cfg = config_mod.OpenBaoConfig(
            enabled=True,
            url="http://127.0.0.1:8200",
            auth_method="approle",
            role_id="test-role",
            secret_id="test-secret",
        )
        with patch.object(mod.OpenBaoClient, "_auth_kubernetes") as mock_k8s, \
             patch.object(mod.OpenBaoClient, "_auth_approle"), \
             patch.object(mod.OpenBaoClient, "_update_token_expiry"), \
             patch.object(mod.OpenBaoClient, "_reconnect"):
            c = object.__new__(mod.OpenBaoClient)
            c._config = cfg
            c._client = MagicMock()
            c._client.is_authenticated.return_value = True
            c._client.sys.read_health_status.return_value = {"initialized": True}
            c._cache = MagicMock()
            c._lock = threading.RLock()
            c._token_expiry = 0.0
            c._reconnect_at = 0.0
            c._is_sealed = False
            c._init_attempted = False
            with patch.object(mod, "hvac", MagicMock()):
                c._connect()

        mock_k8s.assert_not_called()  # AC-01: kubernetes NOT dispatched for approle
