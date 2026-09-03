from __future__ import annotations

from dataclasses import dataclass

from scanner.models import FileSignature, FileType


@dataclass(frozen=True)
class SignatureDetector:
    """Detect supported file formats using binary magic-byte signatures."""

    signatures: tuple[FileSignature, ...] = (
        FileSignature(
            file_type=FileType.PNG,
            signature=b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
        ),
        FileSignature(
            file_type=FileType.JPEG,
            signature=b"\xFF\xD8\xFF",
        ),
    )

    def detect(self, file_header: bytes) -> FileType | None:
        """Return the detected file type or None for an unknown signature."""

        if not isinstance(file_header, bytes):
            raise TypeError("file_header must be bytes")

        for signature in self.signatures:
            if file_header.startswith(signature.signature):
                return signature.file_type

        return None
