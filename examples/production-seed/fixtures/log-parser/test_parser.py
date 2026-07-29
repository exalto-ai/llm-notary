from parser import parse_levels


def test_parse_levels_counts_known_levels() -> None:
    assert parse_levels(["INFO ready", "WARN slow", "INFO done"]) == {
        "INFO": 2,
        "WARN": 1,
    }
