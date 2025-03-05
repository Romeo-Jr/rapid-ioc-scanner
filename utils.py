from re import fullmatch

def check_ioc_type(ioc: str) -> str:
    """Checks the type of IOC based on the regex pattern."""

    IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    HASH_REGEX = r"\b[a-fA-F0-9]{32,64}\b"
    URL_REGEX = r"https?://(?:www\.)?[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+(/[^\s]*)?"

    regex_mapping = {
        "IP": IP_REGEX,
        "URL": URL_REGEX,
        "Hash": HASH_REGEX,
        "Domain": DOMAIN_REGEX
    }

    for ioc_type, pattern in regex_mapping.items():
        if fullmatch(pattern, ioc):
            return ioc_type

    return "Unknown"