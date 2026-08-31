from scanner.engine import RateLimitEngine
from scanner.policies import DEFAULT_POLICY


class FakeClock:
    """Deterministic clock for engine tests."""

    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def build_engine(clock):
    return RateLimitEngine(
        policy=DEFAULT_POLICY,
        clock=clock,
    )


def test_engine_allows_initial_burst():
    clock = FakeClock()
    engine = build_engine(clock)

    decisions = engine.process_requests(
        client_id="client-A",
        request_count=3,
    )

    assert all(decision.allowed for decision in decisions)
    assert engine.statistics.total_requests == 3
    assert engine.statistics.allowed_requests == 3
    assert engine.statistics.denied_requests == 0


def test_engine_denies_after_bucket_exhaustion():
    clock = FakeClock()
    engine = build_engine(clock)

    decisions = engine.process_requests(
        client_id="client-A",
        request_count=4,
    )

    assert decisions[:3]
    assert all(decision.allowed for decision in decisions[:3])
    assert decisions[3].allowed is False

    assert engine.statistics.total_requests == 4
    assert engine.statistics.allowed_requests == 3
    assert engine.statistics.denied_requests == 1


def test_engine_records_multiple_denials():
    clock = FakeClock()
    engine = build_engine(clock)

    decisions = engine.process_requests(
        client_id="client-A",
        request_count=5,
    )

    assert decisions[3].allowed is False
    assert decisions[4].allowed is False
    assert engine.statistics.denied_requests == 2


def test_engine_clients_are_independent():
    clock = FakeClock()
    engine = build_engine(clock)

    engine.process_requests("client-A", 3)

    denied = engine.process_request("client-A")
    allowed = engine.process_request("client-B")

    assert denied.allowed is False
    assert allowed.allowed is True
    assert engine.statistics.clients_seen == {
        "client-A",
        "client-B",
    }


def test_engine_allows_request_after_refill():
    clock = FakeClock()
    engine = build_engine(clock)

    engine.process_requests("client-A", 3)

    denied = engine.process_request("client-A")
    assert denied.allowed is False

    clock.advance(2.0)

    allowed = engine.process_request("client-A")

    assert allowed.allowed is True


def test_engine_summary():
    clock = FakeClock()
    engine = build_engine(clock)

    engine.process_requests("client-A", 4)
    engine.process_request("client-B")

    summary = engine.summary()

    assert summary["policy"] == "default"
    assert summary["total_requests"] == 5
    assert summary["allowed_requests"] == 4
    assert summary["denied_requests"] == 1
    assert summary["clients_seen"] == 2


def test_negative_request_count_is_rejected():
    clock = FakeClock()
    engine = build_engine(clock)

    try:
        engine.process_requests("client-A", -1)
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Expected ValueError for negative request count."
        )
