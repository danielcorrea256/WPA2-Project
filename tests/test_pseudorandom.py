from pseudorandom import hmac_sha1

def test_hmac_sha1():
    """
    Test Case.

    Verifies the HMAC-SHA1 digest matches the known result from wikipedia:
        Key = b"key"
        Data = "The quick brown fox jumps over the lazy dog"

    Expected HMAC-SHA1:
        de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
    """
    key = b"key"
    data = b"The quick brown fox jumps over the lazy dog"
    expected_hex = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
    
    produced_hex = hmac_sha1(key, data).hex()
    assert produced_hex == expected_hex