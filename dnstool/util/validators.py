import re

DOMAIN_REGEX = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')

def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.fullmatch(domain))