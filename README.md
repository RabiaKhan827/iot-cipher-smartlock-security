# Cryptographic Cipher Encoding & Embedded IoT Smart Door Lock Controller (`iot-cipher-smartlock-security`)

SHA-256 keystream cipher encoding, rolling-code HMAC authentication, and finite-state machine (FSM) intrusion lockout for embedded smart door locks, developed from B.Sc. Computer Engineering projects (**Intelligent Door Lock** and **Cipher Encoding**) at **COMSATS University Islamabad, Abbottabad Campus**.

## Author & Academic Profile
- **Author & Maintainer:** **Rabia Khan** (Lecturer in Information Technology, University of Haripur | M.Sc. in Data Science, PAF-IAST | B.Sc. in Computer Engineering, COMSATS Abbottabad)
- **ORCID:** `0009-0007-5575-1564`

## Core Modules & Security Audit Results
1. **SHA-256 Stream Cipher Engine (`CipherEngine`):** Lossless encryption/decryption achieving **`0.4615` bit-diffusion avalanche ratio** across single-character key perturbations.
2. **Rolling-Code Smart Door Lock FSM (`SmartDoorLockFSM`):** Enforces monotonic counter verification (`100.0%` replay-attack rejection) and automatic `ALARM_LOCKOUT` state transition after 3 failed brute-force attempts.

## Quickstart
```bash
pip install -e .
python -m unittest discover -s tests -v
```
