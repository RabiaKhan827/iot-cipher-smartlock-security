import unittest
from iot_cipher_lock import CipherEngine, SmartDoorLockFSM

class TestCipherLock(unittest.TestCase):
    def test_cipher_roundtrip(self):
        ct = CipherEngine.encrypt_hex("SmartLockTest2026", "KeyA")
        pt = CipherEngine.decrypt_hex(ct, "KeyA")
        self.assertEqual(pt, "SmartLockTest2026")

    def test_fsm_replay_and_lockout(self):
        rep = SmartDoorLockFSM.run_security_audit()
        self.assertTrue(rep.cipher_roundtrip_exact)
        self.assertEqual(rep.replay_attack_rejection_rate, 1.0)
        self.assertTrue(rep.lockout_triggered_on_bruteforce)
        self.assertGreater(rep.avalanche_diffusion_ratio, 0.40)

if __name__ == "__main__":
    unittest.main()
