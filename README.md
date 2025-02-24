# WPA2 Protocol Implementation

[![Run Pytest](https://github.com/danielcorrea256/WPA2-Project/actions/workflows/tests.yml/badge.svg)](https://github.com/danielcorrea256/WPA2-Project/actions/workflows/tests.yml)

This repository contains a collection of Python implementations demonstrating various aspects of the WPA2 protocol. It is designed for educational purposes, highlighting both the cryptographic mechanisms used in WPA2 and some of its vulnerabilities (e.g., the KRACK attack).

---

## Overview

In this project, you will find implementations of key components used in WPA2, including:

- **Nonce Generation:**  
  Securely generating nonces using randomness, MAC addresses, and current network time (NTP).

- **Pseudorandom Function (PRF):**  
  A custom PRF implementation to derive keys from given inputs, similar to how WPA2 expands keys.

- **Client PTK State Machine:**  
  A simplified client (supplicant) state machine that implements the 4-Way Handshake process. This state machine is subject to the KRACK attack scenario, demonstrating potential vulnerabilities in the protocol.

- **Access Point (AP) State Machine:**  
  A simplified AP (authenticator) implementation that handles the handshake from its end, including nonce generation, GTK generation, and replay counter management.

---

## Features

- **Nonce Generation:**  
  Utilizes secure random bits combined with network time information to produce unique nonces, which are critical for the security of the handshake process.

- **Key Derivation:**  
  Implements a PRF that is used to calculate the Pairwise Transient Key (PTK) from the Pairwise Master Key (PMK) and nonces. This demonstrates the key expansion process in WPA2.

- **Client PTK State Machine:**  
  Simulates the 4-Way Handshake on the client side, handling the key derivation process, message exchanges, and key installation. This component is also a reference for understanding how the KRACK attack exploits vulnerabilities in the PTK state machine.

- **Access Point Handshake:**  
  Implements the corresponding AP side of the handshake, including message creation, nonce management, and GTK generation.

- **Cryptographic Operations:**  
  Uses the `pycryptodome` library for AES-CTR encryption, demonstrating how derived keys are used to secure wireless communications.

---

## Project Structure

```
wpa2-protocol/
├── README.md                # This file
├── client.py                # Client state machine implementation (supplicant)
├── access_point.py          # Access Point (authenticator) state machine implementation
├── entities/
│   └── Entity.py            # Base class with common cryptographic operations
├── pseudorandom.py          # Pseudorandom function implementation for key derivation
└── requirements.txt         # Project dependencies (e.g., pycryptodome)
```

---

## Getting Started

### Installation 
> You might want to create a virtual environment

1. Because he pycrypto package can generate problems, we suggest to uninstalled it first
    ```
    pip uninstall pycrypto
    ```
2. Install necessary packages
    ```
    pip install -r requirements.txt
    ```