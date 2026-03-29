# Copyright 2024 Deimos AI
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
"""Lightweight async reverse proxy that injects real API credentials at request time.

Purpose
-------
Rather than placing live API keys in os.environ (where they become visible to
subprocesses, shell history, and the LLM message history), AuthProxy binds a
loopback-only HTTP server and intercepts every outbound API call made by the
Agent Zero framework.

At request time it:
    1. Identifies the upstream provider from the URL path prefix.
    2. Fetches the real credential from OpenBao (via get_openbao_manager()).
    3. Rewrites the Authorization / x-api-key header with the live value.
    4. Forwards the (now authorised) request to the real upstream.
    5. Streams the response back to the caller, preserving SSE / chunked transfer.

Binding
-------
The proxy ALWAYS binds to 127.0.0.1 (loopback only -- never 0.0.0.0).  Port 0
is requested so the OS assigns a free ephemeral port, which is then returned by
start() for injection into os.environ via _inject_proxy_env().

Provider registry
-----------------
Four providers are registered by default:

    openai      -> https://api.openai.com
    anthropic   -> https://api.anthropic.com
    openrouter  -> https://openrouter.ai/api
    github      -> https://api.github.com

Route pattern: /proxy/{provider}/*
    The "/proxy/{provider}" prefix is stripped and the remainder of the path is
    appended to the provider's upstream base URL.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

#: Maps provider slug -> proxy configuration dict.
#:
#:  upstream    - base URL of the real API (no trailing slash)
#:  auth_header - HTTP header name to set with the credential
#:  format      - Python str.format template; {key} is replaced with the real
#:                secret value fetched from OpenBao
#:  secret_key  - Name of the key in the OpenBao / SecretsManager secrets dict
PROVIDER_REGISTRY: Dict[str, Dict[str, str]] = {
    "openai": {
        "upstream": "https://api.openai.com",
        "auth_header": "Authorization",
        "format": "Bearer {key}",
        "secret_key": "API_KEY_OPENAI",
    },
    "anthropic": {
        "upstream": "https://api.anthropic.com",
        "auth_header": "x-api-key",
        "format": "{key}",
        "secret_key": "ANTHROPIC_API_KEY",
    },
    "openrouter": {
        "upstream": "https://openrouter.ai/api",
        "auth_header": "Authorization",
        "format": "Bearer {key}",
        "secret_key": "OPENROUTER_API_KEY",
    },
    "github": {
        "upstream": "https://api.github.com",
        "auth_header": "Authorization",
        "format": "Bearer {key}",
        "secret_key": "GH_TOKEN",
    },
}


# ---------------------------------------------------------------------------
# AuthProxy class
# ---------------------------------------------------------------------------

class AuthProxy:
    """Loopback-only aiohttp reverse proxy for API credential injection.

    Lifecycle
    ---------
    proxy = AuthProxy()
    port  = proxy.start()   # binds 127.0.0.1:0, returns assigned port
    ...                     # framework makes API calls through the proxy
    proxy.stop()            # graceful shutdown
    """

    def __init__(self) -> None:
        self._port: Optional[int] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._runner: Optional[Any] = None  # aiohttp.web.AppRunner
        self._thread: Optional[threading.Thread] = None
        self._started = threading.Event()
        self._start_error: Optional[Exception] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> int:
        """Start the proxy daemon thread and return the bound port.

        Blocks until the aiohttp server is listening and ready to accept
        connections (or raises if startup fails).
        """
        if self._port is not None:
            logger.debug("AuthProxy already running on port %d", self._port)
            return self._port

        self._thread = threading.Thread(
            target=self._run_loop,
            name="auth-proxy-loop",
            daemon=True,
        )
        self._thread.start()
        # Block until the server is up (or failed)
        self._started.wait(timeout=15)
        if self._start_error is not None:
            raise self._start_error
        if self._port is None:
            raise RuntimeError("AuthProxy failed to bind within 15 seconds")
        logger.info("AuthProxy listening on 127.0.0.1:%d", self._port)
        return self._port

    def stop(self) -> None:
        """Gracefully shut down the proxy.

        Safe to call multiple times or when the proxy was never started.
        """
        if self._loop is None or not self._loop.is_running():
            return
        future = asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop)
        try:
            future.result(timeout=10)
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("AuthProxy shutdown error: %s", exc)
        self._port = None
        logger.debug("AuthProxy stopped")

    @property
    def port(self) -> Optional[int]:
        """Return the bound port, or None if not started."""
        return self._port

    # ------------------------------------------------------------------
    # Internal: event-loop thread
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Entry point for the daemon thread; owns the event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._serve())
        except Exception as exc:  # pylint: disable=broad-except
            self._start_error = exc
            self._started.set()
        finally:
            self._loop.close()

    async def _serve(self) -> None:
        """Create the aiohttp app, bind, and run until cancelled."""
        try:
            import aiohttp.web as web
        except ImportError as exc:
            raise RuntimeError(
                "aiohttp is required for AuthProxy.  "
                "Add aiohttp>=3.9.0 to requirements.txt and re-install."
            ) from exc

        app = web.Application()
        app.router.add_route("*", "/proxy/{provider}/{path_suffix:.*}", self._handle)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(
            self._runner,
            host="127.0.0.1",  # loopback only -- NEVER 0.0.0.0
            port=0,            # OS assigns a free ephemeral port
        )
        await site.start()

        # Retrieve the assigned port from the server socket
        sockets = site._server.sockets  # type: ignore[attr-defined]
        if sockets:
            self._port = sockets[0].getsockname()[1]
        else:
            raise RuntimeError("AuthProxy: no sockets after site.start()")

        self._started.set()  # signal start() that we are ready

        # Yield control back to the loop; run until _shutdown() cancels us
        try:
            await asyncio.Future()  # run forever
        except asyncio.CancelledError:
            pass
        finally:
            if self._runner:
                await self._runner.cleanup()

    async def _shutdown(self) -> None:
        """Cancel the running Future so _serve() exits cleanly."""
        tasks = [
            t for t in asyncio.all_tasks(self._loop)
            if t is not asyncio.current_task()
        ]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ------------------------------------------------------------------
    # Internal: request handler
    # ------------------------------------------------------------------

    async def _handle(self, request: Any) -> Any:
        """Proxy handler: authenticate and forward to upstream provider."""
        import aiohttp
        import aiohttp.web as web

        provider = request.match_info["provider"]
        path_suffix = request.match_info.get("path_suffix", "")

        config = PROVIDER_REGISTRY.get(provider)
        if config is None:
            return web.Response(
                status=404,
                text=f"Unknown provider '{provider}'. "
                     f"Registered: {', '.join(PROVIDER_REGISTRY)}",
            )

        # Resolve the real credential from OpenBao
        real_key = self._get_secret(config["secret_key"])
        if not real_key:
            logger.warning(
                "AuthProxy: no secret found for provider '%s' (key '%s') -- "
                "forwarding without auth header",
                provider,
                config["secret_key"],
            )
            auth_value = ""
        else:
            auth_value = config["format"].format(key=real_key)

        # Build the upstream URL
        upstream_base = config["upstream"].rstrip("/")
        upstream_url = f"{upstream_base}/{path_suffix}" if path_suffix else upstream_base
        if request.query_string:
            upstream_url = f"{upstream_url}?{request.query_string}"

        # Build outbound headers -- start from the inbound set, then
        # remove hop-by-hop headers and overwrite the auth header.
        HOP_BY_HOP = {
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailers", "transfer-encoding",
            "upgrade", "host",
        }
        outbound_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in HOP_BY_HOP
        }
        if auth_value:
            outbound_headers[config["auth_header"]] = auth_value
        # Strip any proxy-a0 sentinel values left by _inject_proxy_env
        for hdr in ("Authorization", "x-api-key"):
            if outbound_headers.get(hdr, "").lower() in (
                "bearer proxy-a0", "proxy-a0"
            ):
                if auth_value:
                    outbound_headers[hdr] = auth_value
                else:
                    outbound_headers.pop(hdr, None)

        # Read the request body (may be empty for GET/HEAD)
        body = await request.read()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=request.method,
                    url=upstream_url,
                    headers=outbound_headers,
                    data=body or None,
                    allow_redirects=False,
                    ssl=True,
                ) as upstream_resp:
                    # Prepare response headers (strip hop-by-hop)
                    resp_headers = {
                        k: v for k, v in upstream_resp.headers.items()
                        if k.lower() not in HOP_BY_HOP
                    }

                    response = web.StreamResponse(
                        status=upstream_resp.status,
                        reason=upstream_resp.reason,
                        headers=resp_headers,
                    )
                    await response.prepare(request)

                    # Stream body chunk by chunk (SSE-compatible)
                    async for chunk in upstream_resp.content.iter_any():
                        await response.write(chunk)

                    await response.write_eof()
                    return response

        except aiohttp.ClientError as exc:
            logger.error(
                "AuthProxy upstream error for provider '%s': %s", provider, exc
            )
            return web.Response(status=502, text=f"Upstream error: {exc}")
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("AuthProxy unexpected error: %s", exc)
            return web.Response(status=500, text=f"Proxy error: {exc}")

    # ------------------------------------------------------------------
    # Internal: secret resolution
    # ------------------------------------------------------------------

    def _get_secret(self, key: str) -> Optional[str]:
        """Resolve a secret value from the OpenBao manager.

        Falls back gracefully to None if the manager is unavailable.
        The key lookup is case-insensitive (normalises to upper-case).
        """
        try:
            # Import factory_common via sys.modules cache to reuse singleton
            import sys as _sys
            fc = _sys.modules.get("openbao_secrets_factory_common")
            if fc is None:
                # Try direct import path (framework runtime)
                from helpers import plugins as _plugins
                import importlib.util as _ilu
                import os as _os
                plugin_dir = _plugins.find_plugin_dir("deimos_openbao_secrets")
                if not plugin_dir:
                    return None
                fc_path = _os.path.join(plugin_dir, "helpers", "factory_common.py")
                spec = _ilu.spec_from_file_location(
                    "openbao_secrets_factory_common", fc_path
                )
                if spec is None:
                    return None
                fc = _ilu.module_from_spec(spec)
                _sys.modules[spec.name] = fc
                spec.loader.exec_module(fc)  # type: ignore[union-attr]

            manager = fc.get_openbao_manager()
            if manager is None:
                return None

            secrets = manager.load_secrets()
            if not secrets:
                return None

            # Try exact key first, then upper-case variant
            return secrets.get(key) or secrets.get(key.upper())

        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("AuthProxy._get_secret(%s) error: %s", key, exc)
            return None
