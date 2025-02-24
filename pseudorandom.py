import hmac
import hashlib

def hmac_sha1(key: bytes, message: bytes) -> bytes:
    """
    Returns the HMAC-SHA1 of the given message using the provided key.
    
    :param key:     The secret key (as bytes)
    :param message: The message to authenticate (as bytes)
    :return:        The HMAC-SHA1 digest (20 bytes)
    """
    return hmac.new(key, message, hashlib.sha1).digest()


def prf(k : bytes, a : str, b : str, Len : int):
    """
    Pseudo-random function (PRF) from the document.

    Args:
        key (str): The secret key used for HMAC-SHA1.
        a (str): string input to the PRF.
        b (str): string input to the PRF.
        output_length (int): The desired length (in characters) of the final output.
    Returns:
        str: The truncated pseudo-random string output of length `output_length`.
    """
    R_list = []
    for i in range((Len + 159) // 160):
        m = (a + b + str(i)).encode()
        R_list.append(hmac_sha1(k, m))

    R = b"".join(R_list)
    bytes_requested = Len // 8
    return R[:bytes_requested]