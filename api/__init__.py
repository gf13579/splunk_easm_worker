from loguru import logger
from urllib.parse import urlparse


def fix_hec_url(url: str) -> str:
    """makes sure we're sending to services/collector/event"""
    if "/services/collector/event" in url:
        return url
    else:
        logger.warning(
            "HEC url does not end with /services/collector/event! Is: {}", url
        )
        try:
            parsed_url = urlparse(url)
            url = f"{parsed_url.scheme}://{parsed_url.netloc}/services/collector/event"
        except Exception as error:
            logger.debug(
                "Failed to parse HEC URL ({}), leaving it alone: {}", url, error
            )
    return url
