from entities.Client import Client
from entities.AccessPoint import AccessPoint
import secrets
import numpy as np

def test_Client():
    """
    Test Case: Client Authentication and Encryption Handling

    Objective:
        This test verifies the behavior of the Client entity in handling the WPA2 handshake,
        encryption processes, and vulnerability to key reinstallation attacks.

    Setup:
        - Generate a random Pairwise Master Key (PMK) and Group Temporal Key (GTK).
        - Initialize a Client instance with example MAC addresses.

    Test Steps:
        1. Simulate the reception of Message 1 of the WPA2 handshake.
        2. Simulate sending Message 2.
        3. Simulate the reception of Message 3 and its retransmission.
        4. Simulate sending Message 4.
        5. Extract and verify PTK and GTK.
        6. Conduct a Krack Attack and Chosen Plaintext Attack:
        - Encrypt a known message (m1) and infer the encryption key.
        - Force a key reinstallation by handling a retransmitted Message 3.
        - Encrypt a secret message (m2) and attempt to infer it using the extracted key.
        7. Validate that the inferred message matches the original secret message.

    Expected Outcome:
        - The key reinstallation should lead to a vulnerability where the second message (m2) can be decrypted
        using a choosen plain text attack to recover the keystrem.
    """

    pmk = int.to_bytes(secrets.randbits(256), 256 // 8)
    gmk = int.to_bytes(secrets.randbits(256), 256 // 8)

    client_mac = b"A2:4B:C9:8D:7F:12"
    ap_mac = b"3E:91:FA:65:BC:08"

    client = Client(pmk, client_mac, ap_mac)
    ap = AccessPoint(pmk, ap_mac, client_mac, gmk)

    # Simulate Message 1
    message1 = ap.send_message_1()
    client.handle_message_1(message1)

    # Simulate sending Message 2
    message2 = client.send_message_2()
    ap.handle_message_2(message2)

    # Simulate receiving Message 3
    message3 = ap.send_message_3()
    client.handle_message_3(message3)

    # Simulate sending Message 4
    client.send_message_4()
    retransmission_message3 = ap.send_message_3() # ap doesnt receive the response it and sends re transmission of message 3

    # Krack Attack + Choosen Plaintext Attack
    m1 = b"lorem i"
    m1_enc = client.send_message(m1)
    
    m1_int = np.frombuffer(m1, dtype=np.uint8)
    m1_enc_int = np.frombuffer(m1_enc, dtype=np.uint8)

    tk = np.bitwise_xor(m1_int, m1_enc_int)

    client.handle_message_3(retransmission_message3) # key re installation

    m2 = b"secreto"
    m2_enc = client.send_message(m2)

    m2_enc_int = np.frombuffer(m2_enc, dtype=np.uint8)

    inference_int = np.bitwise_xor(m2_enc_int, tk) # lengths have to be equal to dont display error
    inference_msg = inference_int.tobytes()

    assert inference_msg == m2