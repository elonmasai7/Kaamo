from __future__ import annotations

try:
    import keyring
except ImportError:  # pragma: no cover - fallback for minimal environments
    keyring = None  # type: ignore[assignment]

_SECRETS: dict[tuple[str, str], str] = {}


def set_secret(service: str, username: str, secret: str) -> None:
    if keyring is None:
        _SECRETS[(service, username)] = secret
        return
    keyring.set_password(service, username, secret)


def get_secret(service: str, username: str) -> str | None:
    if keyring is None:
        return _SECRETS.get((service, username))
    return keyring.get_password(service, username)
