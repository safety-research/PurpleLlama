# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
AutoPatch Benchmark Agent.

This agent performs vulnerability patching using LLM-generated fixes,
consistent with the autopatch benchmark methodology.
"""

from .agent import AutoPatchBenchAgent

__all__ = ["AutoPatchBenchAgent"]
