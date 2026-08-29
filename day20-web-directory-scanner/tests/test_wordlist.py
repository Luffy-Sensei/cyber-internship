from scanner.wordlist import load_wordlist


def test_load_wordlist(tmp_path):
    wordlist = tmp_path / "paths.txt"

    wordlist.write_text(
        """
        # comment
        admin
        /dashboard

        .env
        """,
        encoding="utf-8",
    )

    assert load_wordlist(str(wordlist)) == [
        "admin",
        "dashboard",
        ".env",
    ]


def test_missing_wordlist(tmp_path):
    missing = tmp_path / "missing.txt"

    try:
        load_wordlist(str(missing))
    except FileNotFoundError:
        assert True
    else:
        assert False
