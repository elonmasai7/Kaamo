from __future__ import annotations

from collections.abc import Sequence


def offline_network_policy() -> dict[str, object]:
    return {
        "mode": "offline",
        "dns": [],
        "allow_egress": [],
        "deny_private_ranges": True,
    }


def hybrid_network_policy(allow_hosts: Sequence[str]) -> dict[str, object]:
    return {
        "mode": "hybrid",
        "dns": list(allow_hosts),
        "allow_egress": list(allow_hosts),
        "deny_private_ranges": True,
    }

