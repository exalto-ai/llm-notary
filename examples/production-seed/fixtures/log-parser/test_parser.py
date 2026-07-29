import unittest

from parser import parse_levels


class ParserTests(unittest.TestCase):
    def test_parse_levels_counts_known_levels(self) -> None:
        self.assertEqual(
            parse_levels(["INFO ready", "WARN slow", "INFO done"]),
            {
                "INFO": 2,
                "WARN": 1,
            },
        )


if __name__ == "__main__":
    unittest.main()
