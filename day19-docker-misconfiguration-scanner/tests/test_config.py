from scanner.config import ScannerConfig


def test_default_configuration():
    config = ScannerConfig()

    assert config.input_file == "input/Dockerfile.test"
    assert config.json_output == (
        "output/reports/day19_docker.json"
    )
    assert config.text_output == (
        "output/reports/day19_docker.txt"
    )
    assert config.max_line_length == 8192
