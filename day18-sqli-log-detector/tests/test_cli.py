from scanner.cli import main


def test_cli_generates_reports(
    tmp_path,
    monkeypatch,
):
    json_output = tmp_path / "report.json"
    text_output = tmp_path / "report.txt"

    monkeypatch.setattr(
        "sys.argv",
        [
            "day18",
            "--input",
            "input/mock_access.log",
            "--json",
            str(json_output),
            "--text",
            str(text_output),
        ],
    )

    result = main()

    assert result == 0
    assert json_output.exists()
    assert text_output.exists()


def test_cli_missing_input(
    tmp_path,
    monkeypatch,
):
    missing = tmp_path / "missing.log"

    monkeypatch.setattr(
        "sys.argv",
        [
            "day18",
            "--input",
            str(missing),
        ],
    )

    result = main()

    assert result == 2
