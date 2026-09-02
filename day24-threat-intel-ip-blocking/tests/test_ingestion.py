import json

import pytest

from scanner.ingestion import FeedIngestionError, ThreatFeedIngestor
from scanner.models import ThreatIndicator


@pytest.fixture
def ingestor():
    return ThreatFeedIngestor()


def test_parse_valid_feed(ingestor):
    payload = {
        "feed_id": "test-feed-001",
        "source": "unit-test",
        "indicators": [
            {
                "ip": "103.45.67.89",
                "indicator": "malware_c2",
                "risk_score": 98,
            }
        ],
    }

    feed = ingestor.parse(payload)

    assert feed.feed_id == "test-feed-001"
    assert feed.source == "unit-test"
    assert len(feed.indicators) == 1

    indicator = feed.indicators[0]

    assert isinstance(indicator, ThreatIndicator)
    assert indicator.ip == "103.45.67.89"
    assert indicator.indicator == "malware_c2"
    assert indicator.risk_score == 98
    assert indicator.source == "unit-test"


def test_load_file(tmp_path, ingestor):
    feed_path = tmp_path / "feed.json"

    feed_path.write_text(
        json.dumps(
            {
                "feed_id": "file-feed-001",
                "source": "fixture",
                "indicators": [
                    {
                        "ip": "198.51.100.33",
                        "indicator": "brute_forcer",
                        "risk_score": 92,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    feed = ingestor.load_file(feed_path)

    assert feed.feed_id == "file-feed-001"
    assert feed.indicators[0].ip == "198.51.100.33"


def test_missing_file_is_rejected(ingestor, tmp_path):
    with pytest.raises(FeedIngestionError, match="does not exist"):
        ingestor.load_file(tmp_path / "missing.json")


def test_invalid_json_is_rejected(ingestor, tmp_path):
    feed_path = tmp_path / "invalid.json"
    feed_path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(FeedIngestionError, match="invalid JSON"):
        ingestor.load_file(feed_path)


def test_invalid_ip_is_rejected(ingestor):
    payload = {
        "feed_id": "test-feed",
        "source": "unit-test",
        "indicators": [
            {
                "ip": "999.999.999.999",
                "indicator": "malware_c2",
                "risk_score": 98,
            }
        ],
    }

    with pytest.raises(FeedIngestionError, match="valid IP"):
        ingestor.parse(payload)


def test_ipv6_is_rejected(ingestor):
    payload = {
        "feed_id": "test-feed",
        "source": "unit-test",
        "indicators": [
            {
                "ip": "2001:db8::1",
                "indicator": "malware_c2",
                "risk_score": 98,
            }
        ],
    }

    with pytest.raises(FeedIngestionError, match="IPv4"):
        ingestor.parse(payload)


def test_missing_indicator_is_rejected(ingestor):
    payload = {
        "feed_id": "test-feed",
        "source": "unit-test",
        "indicators": [
            {
                "ip": "103.45.67.89",
                "risk_score": 98,
            }
        ],
    }

    with pytest.raises(FeedIngestionError, match="indicator"):
        ingestor.parse(payload)


def test_non_numeric_risk_score_is_rejected(ingestor):
    payload = {
        "feed_id": "test-feed",
        "source": "unit-test",
        "indicators": [
            {
                "ip": "103.45.67.89",
                "indicator": "malware_c2",
                "risk_score": "98",
            }
        ],
    }

    with pytest.raises(FeedIngestionError, match="integer"):
        ingestor.parse(payload)


def test_boolean_risk_score_is_rejected(ingestor):
    payload = {
        "feed_id": "test-feed",
        "source": "unit-test",
        "indicators": [
            {
                "ip": "103.45.67.89",
                "indicator": "malware_c2",
                "risk_score": True,
            }
        ],
    }

    with pytest.raises(FeedIngestionError, match="integer"):
        ingestor.parse(payload)


def test_risk_score_above_range_is_rejected(ingestor):
    payload = {
        "feed_id": "test-feed",
        "source": "unit-test",
        "indicators": [
            {
                "ip": "103.45.67.89",
                "indicator": "malware_c2",
                "risk_score": 101,
            }
        ],
    }

    with pytest.raises(FeedIngestionError, match="between 0 and 100"):
        ingestor.parse(payload)


def test_risk_score_below_range_is_rejected(ingestor):
    payload = {
        "feed_id": "test-feed",
        "source": "unit-test",
        "indicators": [
            {
                "ip": "103.45.67.89",
                "indicator": "malware_c2",
                "risk_score": -1,
            }
        ],
    }

    with pytest.raises(FeedIngestionError, match="between 0 and 100"):
        ingestor.parse(payload)


def test_missing_indicators_array_is_rejected(ingestor):
    payload = {
        "feed_id": "test-feed",
        "source": "unit-test",
    }

    with pytest.raises(FeedIngestionError, match="JSON array"):
        ingestor.parse(payload)


def test_non_object_feed_is_rejected(ingestor):
    with pytest.raises(FeedIngestionError, match="JSON object"):
        ingestor.parse([])
