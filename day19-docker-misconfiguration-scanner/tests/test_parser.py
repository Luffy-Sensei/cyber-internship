from scanner.models import DockerfileDirective
from scanner.parser import DockerfileParser


def test_parse_from_instruction():
    parser = DockerfileParser()

    instruction = parser.parse_line(
        "FROM python:3.13-slim",
        line_number=1,
    )

    assert instruction is not None
    assert instruction.directive == DockerfileDirective.FROM
    assert instruction.arguments == "python:3.13-slim"
    assert instruction.line_number == 1


def test_parse_user_instruction():
    parser = DockerfileParser()

    instruction = parser.parse_line(
        "USER appuser",
        line_number=7,
    )

    assert instruction is not None
    assert instruction.directive == DockerfileDirective.USER
    assert instruction.arguments == "appuser"


def test_parse_expose_instruction():
    parser = DockerfileParser()

    instruction = parser.parse_line(
        "EXPOSE 8080",
        line_number=5,
    )

    assert instruction is not None
    assert instruction.directive == DockerfileDirective.EXPOSE
    assert instruction.arguments == "8080"


def test_ignore_blank_lines():
    parser = DockerfileParser()

    assert parser.parse_line("") is None
    assert parser.parse_line("   ") is None


def test_ignore_comments():
    parser = DockerfileParser()

    assert parser.parse_line(
        "# FROM python:latest"
    ) is None


def test_unknown_instruction_is_other():
    parser = DockerfileParser()

    instruction = parser.parse_line(
        "CUSTOM something",
        line_number=3,
    )

    assert instruction is not None
    assert instruction.directive == DockerfileDirective.OTHER
    assert instruction.arguments == "something"
