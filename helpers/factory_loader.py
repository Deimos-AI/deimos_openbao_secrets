# Copyright 2026 deimosAI
# Licensed under the Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
"""
factory_loader.py — Shared OpenBao manager loader for factory extension files.

Provides the single canonical _get_openbao_manager() implementation shared
by all four factory extension files. Extracted from duplicated instance methods
as part of COR-01 / COD-01 remediation (REM-001).

Design note: Uses importlib dynamic loading + sys.modules caching rather than
a direct import of factory_common, because extension files may run in contexts
where the plugin root is not on sys.path. The find_plugin_dir() approach resolves
the plugin directory at runtime regardless of import environment.
"""
import importlib.util
import os
import sys

_FC_MODULE_NAME = "openbao_secrets_factory_common"


def _get_openbao_manager():
    """Lazily load and return the OpenBao manager singleton.

    Uses sys.modules caching to prevent re-execution of factory_common on
    repeated calls (which would reset the singleton). Registers the module
    in sys.modules *before* exec_module() to handle circular import scenarios.

    Returns:
        OpenBaoSecretsManager instance if OpenBao is configured and reachable.
        None if the plugin directory cannot be found, factory_common is missing,
        or any error occurs during initialisation.
    """
    # Use cached module if already loaded — prevents re-exec and singleton reset
    if _FC_MODULE_NAME in sys.modules:
        return sys.modules[_FC_MODULE_NAME].get_openbao_manager()

    # Deferred import: find_plugin_dir lives in A0's helpers.plugins, which is
    # only resolvable inside the A0 runtime. Importing lazily here avoids an
    # ImportError when factory_loader is imported in test or standalone contexts.
    from helpers.plugins import find_plugin_dir  # noqa: PLC0415

    plugin_dir = find_plugin_dir("deimos_openbao_secrets")
    if not plugin_dir:
        return None

    fc_path = os.path.join(plugin_dir, "helpers", "factory_common.py")
    if not os.path.exists(fc_path):
        return None

    spec = importlib.util.spec_from_file_location(_FC_MODULE_NAME, fc_path)
    fc_mod = importlib.util.module_from_spec(spec)
    sys.modules[_FC_MODULE_NAME] = fc_mod  # cache before exec to handle circular imports
    spec.loader.exec_module(fc_mod)

    return fc_mod.get_openbao_manager()
