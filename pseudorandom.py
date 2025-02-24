import hmac
import hashlib

def hmac_sha1(key: bytes, message: bytes) -> str:
    """
    Returns the HMAC-SHA1 of the given message using the provided key.
    
    :param key:     The secret key (as bytes)
    :param message: The message to authenticate (as bytes)
    :return:        The HMAC-SHA1 digest (20 bytes)
    """
    hex_bytes = hmac.new(key, message, hashlib.sha1).digest()
    hex_str = hex_bytes.hex()
    return hex_str