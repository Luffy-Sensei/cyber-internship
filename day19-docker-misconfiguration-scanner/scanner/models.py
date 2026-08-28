from dataclasses import dataclass
from enum import Enum


class DockerfileDirective(str, Enum):
    FROM = "FROM"
    USER = "USER"
    EXPOSE = "EXPOSE"
    RUN = "RUN"
    COPY = "COPY"
    ADD = "ADD"
    CMD = "CMD"
    ENTRYPOINT = "ENTRYPOINT"
    WORKDIR = "WORKDIR"
    ENV = "ENV"
    ARG = "ARG"
    LABEL = "LABEL"
    HEALTHCHECK = "HEALTHCHECK"
    OTHER = "OTHER"


@dataclass(frozen=True)
class DockerfileInstruction:
    """A parsed Dockerfile instruction."""

    line_number: int
    directive: DockerfileDirective
    arguments: str
    raw: str


@dataclass(frozen=True)
class DockerfileDocument:
    """Parsed representation of a Dockerfile."""

    path: str
    instructions: tuple[DockerfileInstruction, ...]
