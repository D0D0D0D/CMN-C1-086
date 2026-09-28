"""Load and validate CMN-C1-086 runtime configuration."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from src.nodes.pre_process_node import MAX_LOG_BYTES

RUNTIME_CONFIG_PATH = Path(__file__).parents[1] / "config" / "config.yaml"

_DEFAULTS: dict[str, Any] = {
    "max_retry": 3,
    "max_log_bytes": MAX_LOG_BYTES,
    "memory_enabled": False,
    "hitl": {"enabled": False},
}
_ALLOWED_KEYS = frozenset(_DEFAULTS)
_ALLOWED_HITL_KEYS = frozenset({"enabled", "max_hitl"})


def load_runtime_config(path: Path = RUNTIME_CONFIG_PATH) -> dict[str, Any]:
    """Return validated settings, preserving documented defaults if absent."""

    values = deepcopy(_DEFAULTS)
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError("runtime configuration must be a YAML mapping")
        unknown = set(loaded) - _ALLOWED_KEYS
        if unknown:
            raise ValueError(f"unknown runtime configuration keys: {sorted(unknown)}")
        values.update(loaded)

    _validate(values)
    return values


def _validate(values: dict[str, Any]) -> None:
    max_retry = values["max_retry"]
    if isinstance(max_retry, bool) or not isinstance(max_retry, int) or max_retry < 0:
        raise ValueError("max_retry must be a non-negative integer")

    max_log_bytes = values["max_log_bytes"]
    if isinstance(max_log_bytes, bool) or not isinstance(max_log_bytes, int) or max_log_bytes <= 0:
        raise ValueError("max_log_bytes must be a positive integer")

    memory_enabled = values["memory_enabled"]
    if not isinstance(memory_enabled, bool):
        raise ValueError("memory_enabled must be a boolean")

    hitl = values["hitl"]
    if not isinstance(hitl, dict):
        raise ValueError("hitl must be a mapping")
    unknown_hitl = set(hitl) - _ALLOWED_HITL_KEYS
    if unknown_hitl:
        raise ValueError(f"unknown hitl configuration keys: {sorted(unknown_hitl)}")
    if not isinstance(hitl.get("enabled", False), bool):
        raise ValueError("hitl.enabled must be a boolean")
    max_hitl = hitl.get("max_hitl")
    if max_hitl is not None and (
        isinstance(max_hitl, bool) or not isinstance(max_hitl, int) or max_hitl < 1
    ):
        raise ValueError("hitl.max_hitl must be a positive integer")
    if hitl.get("enabled") and not memory_enabled:
        raise ValueError("memory_enabled must be true when hitl.enabled is true")
