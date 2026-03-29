#!/usr/bin/env python3
# Copyright 2026 Deimos AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Verification: deimos_openbao_secrets secret prevention architecture."""
import importlib.util
import os
import socket
import sys
from urllib.parse import urlparse

# ── Bootstrap ────────────────────────────────────────────────────────────────
sys.path.insert(0, "/a0")

PLUGIN_DIR = "/a0/usr/plugins/deimos_openbao_secrets"
FC_MODULE_NAME = "openbao_secrets_factory_common"
PASS = "✅ PASS"
FAIL = "❌ FAIL"
results = []

def _load_module(name, path):
    """Load a python file as a named module, cache in sys.modules."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None:
        raise ImportError(f"Cannot load spec from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

# ── Module bootstrap ─────────────────────────────────────────────────────────
print("=" * 64)
print("BOOTSTRAP")
print("=" * 64)

fc = _load_module(FC_MODULE_NAME,
                  os.path.join(PLUGIN_DIR, "helpers", "factory_common.py"))
print("  factory_common : loaded")

proxy_mod = _load_module("openbao_auth_proxy",
                         os.path.join(PLUGIN_DIR, "helpers", "auth_proxy.py"))
print("  auth_proxy     : loaded")

print("  Starting AuthProxy (binds 127.0.0.1:0)...")
proxy = proxy_mod.AuthProxy()
port = proxy.start()
print(f"  AuthProxy      : listening on port {port}")

fc._inject_proxy_env(port)
fc._proxy_instance = proxy
print(f"  _inject_proxy_env({port}) : called")

print("  Initializing OpenBao manager...")
manager = fc.get_openbao_manager()
if manager is None:
    print("  ⚠️  manager     : None (OpenBao disabled/unreachable/config error)")
else:
    avail = manager.is_available()
    print(f"  manager        : {manager.__class__.__name__}  available={avail}")

print()

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 1 — Proxy injects dummy env vars
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 64)
print("CHECK 1 — Proxy starts and injects dummy env vars")
print("=" * 64)

CHECK1_KEYS = {
    "OPENAI_API_KEY":     "proxy-a0",
    "OPENAI_API_BASE":    "http://127.0.0.1",
    "ANTHROPIC_API_KEY":  "proxy-a0",
    "ANTHROPIC_BASE_URL": "http://127.0.0.1",
}

v1_pass = True
for key, must_contain in CHECK1_KEYS.items():
    val = os.environ.get(key, "<NOT SET>")
    ok  = must_contain in val
    print(f"  {'✅' if ok else '❌'}  {key}")
    print(f"       value   : {val!r}")
    print(f"       expect  : contains {must_contain!r}")
    if not ok:
        v1_pass = False

results.append(("V1 — Proxy env injection", v1_pass))
print(f"\n  RESULT: {PASS if v1_pass else FAIL}\n")

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 2 — Real keys NOT in os.environ
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 64)
print("CHECK 2 — Real keys NOT in os.environ")
print("=" * 64)

if manager is None:
    print(f"  {FAIL} manager is None — cannot load secrets")
    results.append(("V2 — Real keys not in env", False))
else:
    secrets = manager.load_secrets()
    if not secrets:
        print(f"  {FAIL} load_secrets() returned empty dict")
        results.append(("V2 — Real keys not in env", False))
    else:
        print(f"  Loaded {len(secrets)} secrets from OpenBao.")
        v2_pass = True
        leaks = []
        for key, real_val in sorted(secrets.items()):
            if not real_val or real_val in ("None", "NA", ""):
                continue
            env_val = os.environ.get(key, "")
            leaked  = (env_val == real_val)
            short_real = real_val[:4] + "..." + real_val[-4:] if len(real_val) > 8 else "****"
            short_env  = env_val[:20] + "..." if len(env_val) > 20 else repr(env_val)
            if leaked:
                print(f"  {FAIL}  LEAK: {key}  env=real={short_real!r}")
                leaks.append(key)
                v2_pass = False
            else:
                print(f"  ✅   {key:35s}  env={short_env}")
        if v2_pass:
            print(f"\n  {PASS} — No real secret values present in os.environ.")
        else:
            print(f"\n  {FAIL} — {len(leaks)} key(s) leaked: {leaks}")
        results.append(("V2 — Real keys not in env", v2_pass))

print()

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 3 — get_api_key() still returns real values
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 64)
print("CHECK 3 — get_api_key() returns real values (via manager)")
print("=" * 64)

if manager is None:
    print(f"  {FAIL} manager is None")
    results.append(("V3 — get_api_key() real values", False))
else:
    secrets = manager.load_secrets()
    v3_pass = True

    def resolve_api_key(service: str):
        """Mirrors _10_openbao_api_key.py lookup logic."""
        su = service.upper()
        return (
            secrets.get(f"API_KEY_{su}") or
            secrets.get(f"{su}_API_KEY") or
            secrets.get(f"{su}_API_TOKEN")
        )

    for service in ("openai", "anthropic"):
        key = resolve_api_key(service)
        su = service.upper()
        if key is None:
            print(f"  {FAIL}  {service}: None — key missing from OpenBao")
            print(f"         (tried API_KEY_{su}, {su}_API_KEY, {su}_API_TOKEN)")
            v3_pass = False
        elif key in ("proxy-a0", "", "None", "NA"):
            print(f"  {FAIL}  {service}: returned sentinel/dummy {key!r}")
            v3_pass = False
        else:
            masked = key[:4] + "..." + key[-4:] if len(key) > 8 else "****"
            print(f"  {PASS}  {service}: real key retrieved  ({masked}, len={len(key)})")

    results.append(("V3 — get_api_key() real values", v3_pass))

print(f"\n  RESULT: {PASS if v3_pass else FAIL}\n")

# ─────────────────────────────────────────────────────────────────────────────
# CHECK 4 — Proxy port is actually listening
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 64)
print("CHECK 4 — Proxy port is actually listening (socket check)")
print("=" * 64)

api_base = os.environ.get("OPENAI_API_BASE", "")
print(f"  OPENAI_API_BASE = {api_base!r}")

v4_pass = False
if not api_base:
    print(f"  {FAIL}  OPENAI_API_BASE not set in os.environ")
else:
    parsed   = urlparse(api_base)
    chk_host = parsed.hostname or "127.0.0.1"
    chk_port = parsed.port or 80
    print(f"  Parsed  host={chk_host!r}  port={chk_port}")
    print(f"  socket.connect({chk_host!r}, {chk_port})...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((chk_host, chk_port))
        s.close()
        print(f"  {PASS}  Connection succeeded — proxy IS listening")
        v4_pass = True
    except ConnectionRefusedError:
        print(f"  {FAIL}  Connection refused — proxy NOT listening on {chk_host}:{chk_port}")
    except OSError as exc:
        print(f"  {FAIL}  Socket error: {exc}")

results.append(("V4 — Proxy port listening", v4_pass))
print(f"\n  RESULT: {PASS if v4_pass else FAIL}\n")

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print("=" * 64)
print("SUMMARY")
print("=" * 64)
all_pass = True
for name, passed in results:
    sym = "✅" if passed else "❌"
    print(f"  {sym}  {name}")
    if not passed:
        all_pass = False
print()
if all_pass:
    print("🎉  ALL 4 CHECKS PASSED")
else:
    failed = [n for n, p in results if not p]
    print(f"⚠️   FAILED: {', '.join(failed)}")

# Graceful shutdown
proxy.stop()
