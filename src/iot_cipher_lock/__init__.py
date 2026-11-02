"""
IoT Cipher Smart Lock Security Module
SHA-256 keystream cipher encoding, rolling-code HMAC authentication,
and finite-state machine (FSM) intrusion lockout.
"""

import hashlib
import hmac


class CipherEngine:
    """SHA-256 Stream Cipher Engine for embedded smart door lock communication."""

    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key

    def _generate_keystream(self, length: int, nonce: bytes) -> bytes:
        keystream = bytearray()
        counter = 0
        while len(keystream) < length:
            block = hashlib.sha256(
                self.secret_key + nonce + counter.to_bytes(4, 'big')
            ).digest()
            keystream.extend(block)
            counter += 1
        return bytes(keystream[:length])

    def encrypt(self, plaintext: bytes, nonce: bytes) -> bytes:
        keystream = self._generate_keystream(len(plaintext), nonce)
        return bytes(p ^ k for p, k in zip(plaintext, keystream))

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        return self.encrypt(ciphertext, nonce)


class SmartDoorLockFSM:
    """Finite State Machine for Smart Door Lock with intrusion lockout."""

    def __init__(self, secret_key: bytes, initial_counter: int = 0):
        self.secret_key = secret_key
        self.last_counter = initial_counter
        self.failed_attempts = 0
        self.state = "LOCKED"

    def verify_rolling_code(self, counter: int, token: bytes) -> bool:
        if self.state == "ALARM_LOCKOUT":
            return False

        if counter <= self.last_counter:
            self._handle_failure()
            return False

        expected_token = hmac.new(
            self.secret_key,
            counter.to_bytes(8, 'big'),
            hashlib.sha256
        ).digest()

        if hmac.compare_digest(token, expected_token):
            self.last_counter = counter
            self.failed_attempts = 0
            self.state = "UNLOCKED"
            return True

        self._handle_failure()
        return False

    def _handle_failure(self):
        self.failed_attempts += 1
        if self.failed_attempts >= 3:
            self.state = "ALARM_LOCKOUT"

    def lock(self):
        if self.state != "ALARM_LOCKOUT":
            self.state = "LOCKED"


__all__ = ["CipherEngine", "SmartDoorLockFSM"]
