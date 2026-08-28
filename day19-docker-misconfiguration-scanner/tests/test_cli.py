from scanner.cli import main


def test_cli_creates_reports(
    tmp_path,
    monkeypatch,
):
    json_output = tmp_path / "report.json"
    text_output = tmp_path / "report.txt"

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli.py",
            "--input",
            "input/Dockerfile.test",
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
    json_output = tmp_path / "report.json"
    text_output = tmp_path / "report.txt"

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli.py",
            "--input",
            str(tmp_path / "missing.Dockerfile"),
            "--json",
            str(json_output),
            "--text",
            str(text_output),
        ],
    )

    result = main()

    assert result == 1
    assert not json_output.exists()
    assert not text_output.exists()
