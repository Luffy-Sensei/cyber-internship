import pytest

from scanner.sanitizer import detect_tokens, sanitize_user_input


def test_html_special_characters_are_encoded():
    result = sanitize_user_input("<hello>")

    assert result.encoded_output == "&lt;hello&gt;"
    assert result.sanitized_output == "&lt;hello&gt;"
    assert result.detected_tokens == []
    assert result.neutralized is True


def test_script_payload_is_detected_and_neutralized():
    payload = "<script>alert('XSS')</script>"

    result = sanitize_user_input(payload)

    assert "SCRIPT_TAG" in result.detected_tokens
    assert "[PROHIBITED_TOKEN]:SCRIPT_TAG" in result.sanitized_output
    assert "<script>" not in result.sanitized_output


def test_event_handler_is_detected():
    payload = '<img src="x" onerror="alert(1)">'

    result = sanitize_user_input(payload)

    assert "EVENT_HANDLER" in result.detected_tokens
    assert "EVENT_HANDLER" in result.sanitized_output


def test_javascript_scheme_is_detected():
    payload = "javascript:alert(1)"

    result = sanitize_user_input(payload)

    assert "JAVASCRIPT_SCHEME" in result.detected_tokens
    assert "JAVASCRIPT_SCHEME" in result.sanitized_output


def test_iframe_is_detected():
    payload = "<iframe src='https://example.invalid'></iframe>"

    result = sanitize_user_input(payload)

    assert "IFRAME_TAG" in result.detected_tokens


def test_svg_is_detected():
    payload = "<svg onload=alert(1)>"

    result = sanitize_user_input(payload)

    assert "SVG_TAG" in result.detected_tokens
    assert "EVENT_HANDLER" in result.detected_tokens


def test_object_is_detected():
    payload = '<object data="javascript:alert(1)">'

    result = sanitize_user_input(payload)

    assert "OBJECT_TAG" in result.detected_tokens
    assert "JAVASCRIPT_SCHEME" in result.detected_tokens


def test_plain_text_is_not_flagged():
    payload = "Hello, this is ordinary user input."

    result = sanitize_user_input(payload)

    assert result.detected_tokens == []
    assert result.sanitized_output == payload
    assert result.neutralized is False


def test_quote_characters_are_encoded():
    payload = '"hello" & \'world\''

    result = sanitize_user_input(payload)

    assert "&quot;" in result.encoded_output
    assert "&#x27;" in result.encoded_output


def test_non_string_payload_is_rejected():
    with pytest.raises(TypeError):
        sanitize_user_input(123)
