from __future__ import annotations

from kaamo.sandbox.seccomp import generate_seccomp_profile


def test_seccomp_profile_blocks_obvious_escape_syscalls() -> None:
    profile = generate_seccomp_profile()
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    serialized = str(profile)
    assert "ptrace" not in serialized
    assert "mount" not in serialized
    assert "execve" not in serialized

