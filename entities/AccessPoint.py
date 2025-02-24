"""
access_point.py

Implements a simplified Access Point (AP) state machine for a WPA2 4-Way Handshake.
This module demonstrates how an AP (authenticator) initiates the handshake by sending
Message 1 (ANonce and replay counter), processes Message 2 from the client (extracting
SNonce and generating a new GTK), sends Message 3 with the GTK, and finally processes
Message 4 to confirm handshake completion.

The AccessPoint class extends the Entity class, which provides core cryptographic
functions such as nonce generation.

Example Usage:
    1. Create an AccessPoint instance with a PMK, AP MAC, client MAC, and a GMK (Group Master Key).
    2. Call send_message_1() to initiate the handshake (Message 1).
    3. Upon receiving Message 2 from the client, call handle_message_2() to store the SNonce and generate a GTK.
    4. Call send_message_3() to deliver the GTK to the client (Message 3).
    5. Finally, call handle_message_4() to complete the handshake.
"""


from entities.Entity import Entity
from pseudorandom import prf


class AccessPoint(Entity):
    """
    A simplified access point (authenticator) class for managing the WPA2 4-Way Handshake.

    This class extends the Entity class, thereby inheriting cryptographic operations such as
    nonce generation. It implements the state transitions and key management functions required
    to perform the 4-Way Handshake with a client.

    Attributes:
        pmk (bytes): The Pairwise Master Key for this network (inherited from Entity).
        mac (str): The MAC address of this AP (inherited from Entity).
        client_mac (str): The MAC address of the client (supplicant).
        gmk (bytes): The Group Master Key used to derive the Group Temporal Key (GTK).
        replay_counter (int): Counter used to protect against replay attacks.
        anonce (bytes): ANonce generated by the AP for Message 1.
        gtk (bytes): Group Temporal Key generated by this AP for Message 3.
        snonce (bytes): SNonce received from the client in Message 2.
    """

    def __init__(self, pmk: bytes, mac: str, client_mac: str, gmk: bytes):
        """
        Initializes the AccessPoint with a PMK, AP MAC, client MAC, and a GMK.

        Args:
            pmk (bytes): The Pairwise Master Key for this network.
            mac (str): The MAC address of this AP.
            client_mac (str): The MAC address of the client (supplicant).
            gmk (bytes): The Group Master Key used for deriving the GTK.
        """
        super().__init__(pmk, mac)
        self.client_mac = client_mac
        self.gmk = gmk


    def send_message_1(self) -> dict:
        """
        Constructs and returns Message 1 of the 4-Way Handshake.

        This method generates a fresh ANonce using the inherited generate_nonce()
        method, increments the replay counter, and returns a dictionary containing
        the ANonce and replay counter.

        Returns:
            dict: A dictionary representing Message 1, with:
                - "ANonce" (bytes): The AP's generated nonce.
                - "r" (int): The updated replay counter.
        """
        self.anonce = self.generate_nonce()
        self.replay_counter += 1

        return {
            "ANonce": self.anonce,
            "r": self.replay_counter
        }


    def handle_message_2(self, message2: dict):
        """
        Processes Message 2 from the client.

        This method extracts the client's SNonce from Message 2, performs a simple
        replay counter check, and then generates a new GTK by calling generate_gtk().

        Args:
            message2 (dict): A dictionary representing Message 2, containing:
                - "SNonce" (bytes): The client's SNonce.
                - "r" (int): The client's replay counter (used for verification).
        """
        # Verify replay counter (client's counter must not exceed the AP's)
        assert message2["r"] <= self.replay_counter, "Replay counter error in Message 2"

        self.snonce = message2["SNonce"]

        # Generate a new GTK after receiving the SNonce
        self.gtk = self.generate_gtk()


    def send_message_3(self) -> dict:
        """
        Constructs and returns Message 3 of the 4-Way Handshake.

        This method increments the replay counter and returns a dictionary that
        includes the newly generated GTK along with the updated replay counter.
        It assumes that handle_message_2() has already processed the client's SNonce.

        Returns:
            dict: A dictionary representing Message 3, with:
                - "gtk" (bytes): The Group Temporal Key.
                - "r" (int): The updated replay counter.
        """
        self.replay_counter += 1

        return {
            "gtk": self.gtk,
            "r": self.replay_counter
        }


    def handle_message_4(self, message4: dict):
        """
        Processes Message 4 from the client, signaling handshake completion.

        This method performs a replay counter check to ensure that Message 4 is valid.
        No further action is taken as the handshake is assumed to be complete.

        Args:
            message4 (dict): A dictionary representing Message 4, containing:
                - "r" (int): The client's replay counter (used for verification).
        """
        # Verify replay counter (client's counter must not exceed the AP's)
        assert message4["r"] <= self.replay_counter, "Replay counter error in Message 4"


    def generate_gtk(self) -> bytes:
        """
        Generates a 256-bit Group Temporal Key (GTK).

        This private helper method generates a fresh nonce (gnonce) using the inherited
        generate_nonce() method and then uses the pseudorandom function (PRF) to derive
        a GTK based on the AP's GMK, a label ("GroupKeyExpansion"), and the concatenation
        of the AP's MAC address with the generated nonce.

        Returns:
            bytes: A 256-bit GTK.
        """
        gnonce = self.generate_nonce()
        return prf(self.gmk, b"GroupKeyExpansion", self.mac + gnonce, 256)


if __name__ == "__main__":
    # Example usage of the AccessPoint

    # Define example values for PMK, MAC addresses, and GMK
    pmk_example = b"ExamplePMK_AP"
    ap_mac = "3E:91:FA:65:BC:08"
    client_mac = "A2:4B:C9:8D:7F:12"
    gmk_example = b"ExampleGMK"

    # Instantiate an AccessPoint
    ap = AccessPoint(pmk_example, ap_mac, client_mac, gmk_example)

    # Send Message 1 to the client.
    msg1 = ap.send_message_1()
    print("Message 1 from AP:", msg1)

    # Simulate receiving Message 2 from the client.
    example_snonce = b"SNonceExample"
    msg2 = {"SNonce": example_snonce, "r": 2}
    ap.handle_message_2(msg2)

    # Now send Message 3 containing the GTK.
    msg3 = ap.send_message_3()
    print("Message 3 from AP:", msg3)

    # Finally, simulate handling Message 4 from the client.
    msg4 = {"r": 3}
    ap.handle_message_4(msg4)
