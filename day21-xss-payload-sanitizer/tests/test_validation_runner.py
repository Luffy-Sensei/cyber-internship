import json

from scanner.validation_runner import load_payloads, run_validation


def test_load_payloads_ignores_comments_and_blank_lines(tmp_path):
    payload_file = tmp_path / "payloads.txt"

    payload_file.write_text(
        """
# comment

<script>alert(1)</script>

ordinary text
""",
        encoding="utf-8",
    )

    payloads = load_payloads(payload_file)

    assert payloads == [
        "<script>alert(1)</script>",
        "ordinary text",
    ]


def test_load_payloads_rejects_missing_file(tmp_path):
    missing = tmp_path / "missing.txt"

    try:
        load_payloads(missing)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")


def test_validation_runner_writes_json_report(tmp_path):
    payload_file = tmp_path / "payloads.txt"
    report_file = tmp_path / "report.json"

    payload_file.write_text(
        """
<script>alert(1)</script>
ordinary text
<img src=x onerror=alert(1)>
""",
        encoding="utf-8",
    )

    report = run_validation(
        payload_path=payload_file,
        report_path=report_file,
    )

    assert report["schema_version"] == "1.0"
    assert report["payload_count"] == 3
    assert report["passed"] == 3
    assert report["failed"] == 0
    assert report["all_passed"] is True

    assert report_file.exists()

    loaded = json.loads(
        report_file.read_text(encoding="utf-8")
    )

    assert loaded["payload_count"] == 3
    assert len(loaded["cases"]) == 3


def test_validation_runner_records_detected_tokens(tmp_path):
    payload_file = tmp_path / "payloads.txt"
    report_file = tmp_path / "report.json"

    payload_file.write_text(
        "<script>alert(1)</script>\n",
        encoding="utf-8",
    )

    report = run_validation(
        payload_path=payload_file,
        report_path=report_file,
    )

    case = report["cases"][0]

    assert case["passed"] is True
    assert "SCRIPT_TAG" in case["detected_tokens"]
    assert case["severity"] == "CRITICAL"
    assert case["xss_model"] == "UNKNOWN"
    assert case["context"] == "UNKNOWN"
