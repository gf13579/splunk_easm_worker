from loguru import logger
from api import fix_hec_url


def test_fix_hec_url() -> None:
    # no change, it's valid
    test_values = [
        (
            "https://example.com/services/collector/event",
            "https://example.com/services/collector/event",
        ),
        ("https://example.com/", "https://example.com/services/collector/event"),
        (
            "https://example.com:8088/",
            "https://example.com:8088/services/collector/event",
        ),
    ]
    for testurl, expected in test_values:
        logger.debug("testing {}", testurl)
        logger.debug("expected: {}", expected)
        res = fix_hec_url(testurl)
        logger.debug("got {}", res)
        assert res == expected
