from entities.Client import Client
import secrets
import numpy as np

def test_Client():
    """
    """
    pmk = int.to_bytes(secrets.randbits(256), 256 // 8)
    gtk = int.to_bytes(secrets.randbits(256), 256 // 8)
    mac_example = "A2:4B:C9:8D:7F:12"
    access_point_mac_example = "3E:91:FA:65:BC:08"
    client = Client(pmk, mac_example, access_point_mac_example)

    # Simulate receiving Message 1
    client.handle_message_1({"ANonce": b"example", "r": 1})

    # Simulate sending Message 2
    client.send_message_2()

    # Simulate receiving Message 3
    message3 = {"gtk": gtk, "r": 2}
    message3_retransmission = {"gtk": gtk, "r": 3}
    client.handle_message_3(message3)

    # Simulate sending Message 4
    client.send_message_4()

    ptk = client.ptk
    gtk = client.gtk

    # Krack Attack + Choosen Plaintext Attack
    m1 = b"lorem i"
    m1_enc = client.send_message(m1)
    
    m1_int = np.frombuffer(m1, dtype=np.uint8)
    m1_enc_int = np.frombuffer(m1_enc, dtype=np.uint8)

    tk = np.bitwise_xor(m1_int, m1_enc_int)

    client.handle_message_3(message3_retransmission) # key re installation

    m2 = b"secreto"
    m2_enc = client.send_message(m2)

    m2_enc_int = np.frombuffer(m2_enc, dtype=np.uint8)
    inference_int = np.bitwise_xor(m2_enc_int, tk)
    inference_msg = inference_int.tobytes()

    assert inference_msg == m2