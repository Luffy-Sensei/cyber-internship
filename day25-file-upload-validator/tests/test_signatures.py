import pytest

from scanner.models import FileType
from scanner.signatures import SignatureDetector


PNG_HEADER = b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"
JPEG_HEADER = b"\xFF\xD8\xFF"


def test_detects_png_signature() -> None:
    detector = SignatureDetector()

    assert detector.detect(PNG_HEADER) is FileType.PNG


def test_detects_jpeg_signature() -> None:
    detector = SignatureDetector()

    assert detector.detect(JPEG_HEADER) is FileType.JPEG


def test_detects_png_with_additional_content() -> None:
    detector = SignatureDetector()

    header = PNG_HEADER + b"\x00\x01\x02\x03"

    assert detector.detect(header) is FileType.PNG


def test_detects_jpeg_with_additional_content() -> None:
    detector = SignatureDetector()

    header = JPEG_HEADER + b"\x00\x01\x02\x03"

    assert detector.detect(header) is FileType.JPEG


def test_unknown_signature_returns_none() -> None:
    detector = SignatureDetector()

    assert detector.detect(b"NOT_A_VALID_FILE") is None


def test_empty_header_returns_none() -> None:
    detector = SignatureDetector()

    assert detector.detect(b"") is None


def test_non_bytes_input_is_rejected() -> None:
    detector = SignatureDetector()

    with pytest.raises(TypeError, match="file_header must be bytes"):
        detector.detect("not-bytes")  # type: ignore[arg-type]
