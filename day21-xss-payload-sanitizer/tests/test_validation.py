from scanner.validation import validate_payload, validate_payloads


def test_script_payload_passes_validation():
    result = validate_payload("<script>alert(1)</script>")

    assert result.passed is True
    assert result.neutralized is True
    assert "SCRIPT_TAG" in result.detected_tokens


def test_event_handler_passes_validation():
    result = validate_payload('<img src="x" onerror="alert(1)">')

    assert result.passed is True
    assert "EVENT_HANDLER" in result.detected_tokens


def test_plain_text_passes_validation():
    result = validate_payload("ordinary user input")

    assert result.passed is True
    assert result.detected_tokens == []


def test_multiple_payloads_are_supported():
    results = validate_payloads(
        [
            "<script>alert(1)</script>",
            "ordinary text",
            "javascript:alert(1)",
        ]
    )

    assert len(results) == 3
    assert all(result.passed for result in results)


def test_validation_preserves_sanitized_output():
    payload = "<script>alert(1)</script>"

    result = validate_payload(payload)

    assert result.sanitized_output
    assert "<script>" not in result.sanitized_output
