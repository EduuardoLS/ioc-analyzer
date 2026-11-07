import pytest
from src.validators import validate_ip, validate_domain, validate_sha256

def test_validate_ip():
    assert validate_ip("8.8.8.8") == True
    assert validate_ip("256.0.0.1") == False
    assert validate_ip("abc.def.ghi.jkl") == False

def test_validate_domain():
    assert validate_domain("google.com") == True
    assert validate_domain("malicious-site.co.uk") == True
    assert validate_domain("invalid_domain!.com") == False

def test_validate_sha256():
    valid_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    invalid_hash = "e3b0c44298fc1c149afbf4c"
    assert validate_sha256(valid_hash) == True
    assert validate_sha256(invalid_hash) == False