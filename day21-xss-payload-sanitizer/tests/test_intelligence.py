import pytest

from scanner.intelligence import analyze_payload
from scanner.sanitizer import sanitize_user_input


def test_script_payload_gets_critical_intelligence():
    result = sanitize_user_input("<script>alert(1)</script>")

    intelligence = analyze_payload(result)

    assert intelligence.severity == "CRITICAL"
    assert intelligence.xss_model == "UNKNOWN"
    assert intelligence.context == "UNKNOWN"
    assert "SCRIPT_TAG" in intelligence.detected_tokens
    assert intelligence.confidence == "MEDIUM"


def test_context_and_model_can_be_supplied():
    result = sanitize_user_input("<script>alert(1)</script>")

    intelligence = analyze_payload(
        result,
        context="HTML",
        xss_model="REFLECTED",
    )

    assert intelligence.context == "HTML"
    assert intelligence.xss_model == "REFLECTED"
    assert intelligence.confidence == "HIGH"


def test_event_handler_is_high_severity():
    result = sanitize_user_input('<img src="x" onerror="alert(1)">')

    intelligence = analyze_payload(result)

    assert intelligence.severity == "HIGH"
    assert "EVENT_HANDLER" in intelligence.detected_tokens


def test_clean_input_has_low_severity():
    result = sanitize_user_input("Hello security lab")

    intelligence = analyze_payload(result)

    assert intelligence.severity == "LOW"
    assert intelligence.detected_tokens == []
    assert intelligence.confidence == "HIGH"


def test_invalid_context_is_rejected():
    result = sanitize_user_input("hello")

    with pytest.raises(ValueError):
        analyze_payload(result, context="INVALID")


def test_invalid_model_is_rejected():
    result = sanitize_user_input("hello")

    with pytest.raises(ValueError):
        analyze_payload(result, xss_model="INVALID")
