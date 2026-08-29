from pathlib import Path


def load_wordlist(path: str) -> list[str]:
    wordlist = Path(path)

    if not wordlist.is_file():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    entries: list[str] = []

    for line in wordlist.read_text(encoding="utf-8").splitlines():
        entry = line.strip()

        if not entry or entry.startswith("#"):
            continue

        entry = entry.lstrip("/")

        if entry:
            entries.append(entry)

    return entries
