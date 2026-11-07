import re
import ipaddress

def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False

def validate_domain(domain_str: str) -> bool:
    if not domain_str:
        return False
    clean_domain = domain_str.strip().replace("http://", "").replace("https://", "").split("/")[0]
    pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    return bool(re.match(pattern, clean_domain))

def validate_sha256(hash_str: str) -> bool:
    if not hash_str:
        return False
    pattern = r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$"
    return bool(re.match(pattern, hash_str.strip()))