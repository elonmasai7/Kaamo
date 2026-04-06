from __future__ import annotations

import hashlib

import pytest

from kaamo.models.gemma_manager import ModelVerificationError, verify_model


def test_model_verification_accepts_valid_hash(tmp_path) -> None:
    file_path = tmp_path / "model.gguf"
    file_path.write_bytes(b"hello world")
    expected = hashlib.sha256(b"hello world").hexdigest()
    assert verify_model(file_path, expected) is True


def test_model_verification_rejects_corrupted_file(tmp_path) -> None:
    file_path = tmp_path / "model.gguf"
    file_path.write_bytes(b"hello world")
    expected = hashlib.sha256(b"goodbye").hexdigest()
    assert verify_model(file_path, expected) is False


def test_model_verification_rejects_placeholder_hash(tmp_path) -> None:
    file_path = tmp_path / "model.gguf"
    file_path.write_bytes(b"hello world")
    with pytest.raises(ModelVerificationError):
        verify_model(file_path, "REPLACE_WITH_OFFICIAL_SHA256")

