import json

from scanner.validation import ValidationEngine


def load_fixture():
    with open(
        "input/validation-threat-feed.json",
        "r",
        encoding="utf-8",
    ) as handle:
        return json.load(handle)


def test_valid_indicators_are_accepted():
    payload = load_fixture()

    result = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    assert result.indicators_received == 6
    assert result.indicators_valid == 3
    assert result.indicators_rejected == 3


def test_valid_indicator_order_is_preserved():
    payload = load_fixture()

    result = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    assert [item.ip for item in result.valid_indicators] == [
        "103.45.67.89",
        "185.10.11.12",
        "198.51.100.33",
    ]


def test_invalid_ip_is_rejected():
    payload = load_fixture()

    result = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    rejected = result.rejected_indicators[0]

    assert rejected.index == 3
    assert "invalid" in rejected.reason


def test_out_of_range_risk_is_rejected():
    payload = load_fixture()

    result = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    rejected = result.rejected_indicators[1]

    assert rejected.index == 4
    assert "between 0 and 100" in rejected.reason


def test_missing_risk_is_rejected():
    payload = load_fixture()

    result = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    rejected = result.rejected_indicators[2]

    assert rejected.index == 5
    assert "must be an integer" in rejected.reason


def test_rejected_indicators_do_not_become_valid_indicators():
    payload = load_fixture()

    result = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"],
    )

    valid_ips = {
        item.ip
        for item in result.valid_indicators
    }

    assert "not-an-ip" not in valid_ips
    assert "192.0.2.10" not in valid_ips
    assert "192.0.2.20" not in valid_ips


def test_clean_feed_reports_validated_status():
    payload = load_fixture()

    result = ValidationEngine().validate(
        feed_id=payload["feed_id"],
        source=payload["source"],
        indicators=payload["indicators"][:3],
    )

    assert result.passed is True
    assert result.status == "VALIDATED"
