from __future__ import annotations

from dataclasses import dataclass

from scanner.models import FileType


@dataclass(frozen=True)
class UploadPolicy:
    """Configuration controlling the file-upload security policy."""

    allowed_types: tuple[FileType, ...] = (
        FileType.PNG,
        FileType.JPEG,
    )

    allowed_extensions: tuple[str, ...] = (
        ".png",
        ".jpg",
        ".jpeg",
    )

    max_file_size_bytes: int = 5 * 1024 * 1024

    require_extension_match: bool = True

    storage_class: str = "NON_EXECUTABLE_UPLOAD_STORAGE"

    generate_server_filename: bool = True

    preserve_original_filename: bool = False

    allow_direct_execution: bool = False

    def __post_init__(self) -> None:
        if not self.allowed_types:
            raise ValueError("allowed_types must not be empty")

        if not self.allowed_extensions:
            raise ValueError("allowed_extensions must not be empty")

        if any(
            not extension.startswith(".")
            for extension in self.allowed_extensions
        ):
            raise ValueError(
                "allowed_extensions must start with '.'"
            )

        if self.max_file_size_bytes <= 0:
            raise ValueError(
                "max_file_size_bytes must be greater than zero"
            )

        if not self.storage_class.strip():
            raise ValueError("storage_class must not be empty")

        if (
            self.generate_server_filename
            and self.preserve_original_filename
        ):
            raise ValueError(
                "server-generated naming and original filename "
                "preservation cannot both be enabled"
            )

        if self.allow_direct_execution:
            raise ValueError(
                "direct execution of uploaded files must remain disabled"
            )


DEFAULT_UPLOAD_POLICY = UploadPolicy()