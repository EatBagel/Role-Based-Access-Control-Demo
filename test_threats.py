"""
Executable evidence for docs/THREAT_MODEL.md. Test names carry the threat ID (T1, T2, ...).

- MitigationsHold: controls the threat model says are in place.
- KnownGaps: desired behaviour that the code does NOT have yet. Each is marked
  expectedFailure so the suite stays green while the gap is visible. When a gap is fixed,
  the test reports "unexpected success": remove the decorator (and adjust the test to the
  new API if needed).
"""

import json
import os
import tempfile
import unittest

from rbac import ROLE_PERMISSIONS, AccessDenied, build_sample_system


class ThreatTestBase(unittest.TestCase):
    def setUp(self):
        fd, self.log_path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        os.remove(self.log_path)
        self.system = build_sample_system(self.log_path)

    def tearDown(self):
        if os.path.exists(self.log_path):
            os.remove(self.log_path)


class MitigationsHold(ThreatTestBase):
    def test_T1_unknown_user_and_wrong_password_are_indistinguishable(self):
        messages = []
        for user, password in (("alex", "wrong"), ("nobody", "wrong")):
            with self.assertRaises(AccessDenied) as ctx:
                self.system.login(user, password)
            messages.append(str(ctx.exception))
        self.assertEqual(messages[0], messages[1])

    def test_T3_unknown_role_gets_no_access(self):
        token = self.system.login("gina", "guest-pass")
        self.system._users["gina"].role = "ghost"  # simulate a removed / misconfigured role
        with self.assertRaises(AccessDenied):
            self.system.access(token, "company_handbook")

    def test_T3_role_permissions_snapshot(self):
        """Fails if a role is widened by accident. Update on purpose when roles change."""
        self.assertEqual(
            {role: set(perms) for role, perms in ROLE_PERMISSIONS.items()},
            {
                "guest": {"read:public"},
                "employee": {"read:public", "read:internal"},
                "manager": {"read:public", "read:internal", "read:confidential"},
                "admin": {"read:public", "read:internal", "read:confidential", "read:secret"},
            },
        )

    def test_T4_tampered_tokens_are_rejected_and_logged(self):
        token = self.system.login("alex", "admin-pass")
        flipped = token[:-1] + ("A" if token[-1] != "A" else "B")
        variants = [flipped, token[:-5], token + "x", ""]
        for bad in variants:
            with self.assertRaises(AccessDenied):
                self.system.access(bad, "master_keys")
        denied = [e for e in self.system.log.entries()
                  if e["event"] == "ACCESS" and e["outcome"] == "DENIED"]
        self.assertEqual(len(denied), len(variants))

    def test_T4_tokens_are_unique_and_long(self):
        tokens = {self.system.login("gina", "guest-pass") for _ in range(10)}
        self.assertEqual(len(tokens), 10)
        self.assertTrue(all(len(t) >= 40 for t in tokens))

    def test_T7_log_injection_is_neutralized(self):
        evil = 'x"\n{"timestamp": "2020-01-01", "event": "LOGIN", "user": "alex", "outcome": "GRANTED"}'
        with self.assertRaises(AccessDenied):
            self.system.login(evil, "pw")
        with open(self.log_path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        self.assertEqual(len(lines), 1)  # the forged "line" stayed inside one JSON string
        entry = json.loads(lines[0])
        self.assertEqual(entry["outcome"], "DENIED")
        self.assertEqual(entry["user"], evil)


class KnownGaps(ThreatTestBase):
    @unittest.expectedFailure
    def test_T1_repeated_failures_lock_the_account(self):
        for _ in range(10):
            with self.assertRaises(AccessDenied):
                self.system.login("alex", "bad")
        with self.assertRaises(AccessDenied):
            self.system.login("alex", "admin-pass")  # locked out even with the right password

    @unittest.expectedFailure
    def test_T2_creating_users_requires_an_authorized_session(self):
        with self.assertRaises(AccessDenied):
            self.system.add_user("eve", "pw", "admin")

    @unittest.expectedFailure
    def test_T8_user_creation_is_logged(self):
        self.system.add_user("eve", "pw", "employee")
        self.assertTrue(any("eve" in json.dumps(e) for e in self.system.log.entries()))

    @unittest.expectedFailure
    def test_T8_malformed_token_is_denied_and_logged(self):
        with self.assertRaises(AccessDenied):
            self.system.access(["not", "a", "token"], "master_keys")
        self.assertEqual(len(self.system.log.entries()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
