from pathlib import Path

from .models import (
    DockerfileDocument,
    DockerfileDirective,
    DockerfileInstruction,
)


class DockerfileParser:
    """Parse Dockerfile instructions into structured objects."""

    _DIRECTIVES = {
        "FROM": DockerfileDirective.FROM,
        "USER": DockerfileDirective.USER,
        "EXPOSE": DockerfileDirective.EXPOSE,
        "RUN": DockerfileDirective.RUN,
        "COPY": DockerfileDirective.COPY,
        "ADD": DockerfileDirective.ADD,
        "CMD": DockerfileDirective.CMD,
        "ENTRYPOINT": DockerfileDirective.ENTRYPOINT,
        "WORKDIR": DockerfileDirective.WORKDIR,
        "ENV": DockerfileDirective.ENV,
        "ARG": DockerfileDirective.ARG,
        "LABEL": DockerfileDirective.LABEL,
        "HEALTHCHECK": DockerfileDirective.HEALTHCHECK,
    }

    def parse_line(
        self,
        line: str,
        line_number: int = 1,
    ) -> DockerfileInstruction | None:
        """Parse a single Dockerfile line."""

        raw = line.rstrip("\n")
        stripped = raw.strip()

        if not stripped or stripped.startswith("#"):
            return None

        parts = stripped.split(None, 1)

        directive_name = parts[0].upper()
        arguments = parts[1] if len(parts) == 2 else ""

        directive = self._DIRECTIVES.get(
            directive_name,
            DockerfileDirective.OTHER,
        )

        return DockerfileInstruction(
            line_number=line_number,
            directive=directive,
            arguments=arguments,
            raw=raw,
        )

    def parse_file(self, path: str) -> DockerfileDocument:
        """Parse a Dockerfile from disk."""

        file_path = Path(path)

        if not file_path.is_file():
            raise FileNotFoundError(
                f"Dockerfile not found: {path}"
            )

        instructions = []

        with file_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            for line_number, line in enumerate(
                handle,
                start=1,
            ):
                instruction = self.parse_line(
                    line,
                    line_number,
                )

                if instruction is not None:
                    instructions.append(instruction)

        return DockerfileDocument(
            path=str(file_path),
            instructions=tuple(instructions),
        )
