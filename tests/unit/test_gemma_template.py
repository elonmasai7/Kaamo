from __future__ import annotations

from kaamo.inference.backends.llamacpp_backend import LlamaCppBackend


def test_gemma_template_matches_expected_format() -> None:
    rendered = LlamaCppBackend._apply_gemma3_template(
        [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "world"},
        ]
    )
    assert rendered == (
        "<start_of_turn>user\nhello<end_of_turn>\n"
        "<start_of_turn>model\nworld<end_of_turn>\n"
        "<start_of_turn>model\n"
    )

