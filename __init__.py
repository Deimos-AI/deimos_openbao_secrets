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
"""Public API surface for the deimos_openbao_secrets plugin.

Re-exports the resolve_secret helper at the package root so consumers
can import from a stable path without knowledge of internal module layout.
"""

from deimos_openbao_secrets.helpers.factory_common import resolve_secret  # noqa: F401

__all__ = ['resolve_secret']
