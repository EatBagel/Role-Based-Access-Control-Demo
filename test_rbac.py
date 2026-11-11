import os
import tempfile
import unittest

from rbac import AccessDenied, RBACSystem, build_sample_system


class RBACTests(unittest.TestCase):
    def setUp(self):
        fd, self.log_path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        os.remove(self.log_path)  # start with no log file
        self.system = build_sample_system(self.log_path)

    def tearDown(self):
        if os.path.exists(self.log_path):
            os.remove(self.log_path)

    def login(self, user, pw):
        return self.system.login(user, pw)

    # --- authorized access ---------------------------------------------

    def test_authorized_user_gets_data(self):
        token = self.login("maya", "manager-pass")
        self.assertIn("Salary", self.system.access(token, "salary_report"))

    def test_admin_can_access_everything(self):
        token = self.login("alex", "admin-pass")
        for resource in ("company_handbook", "team_roadmap", "salary_report", "master_keys"):
            self.assertTrue(self.system.access(token, resource))

    def test_guest_limited_to_public(self):
        token = self.login("gina", "guest-pass")
        self.assertTrue(self.system.access(token, "company_handbook"))
        for resource in ("team_roadmap", "salary_report", "master_keys"):
            with self.assertRaises(AccessDenied):
                self.system.access(token, resource)

    # --- unauthorized access -------------------------------------------

    def test_lower_role_blocked_from_higher_resource(self):
        token = self.login("eli", "employee-pass")
        with self.assertRaises(AccessDenied):
            self.system.access(token, "salary_report")

    def test_manager_blocked_from_secret(self):
        token = self.login("maya", "manager-pass")
        with self.assertRaises(AccessDenied):
            self.system.access(token, "master_keys")

    def test_wrong_password_blocked(self):
        with self.assertRaises(AccessDenied):
            self.login("alex", "not-the-password")

    def test_unknown_user_blocked(self):
        with self.assertRaises(AccessDenied):
            self.login("mallory", "anything")

    def test_forged_token_blocked(self):
        with self.assertRaises(AccessDenied):
            self.system.access("forged-token", "master_keys")

    def test_none_token_blocked(self):
        with self.assertRaises(AccessDenied):
            self.system.access(None, "company_handbook")

    def test_unknown_resource_blocked(self):
        token = self.login("alex", "admin-pass")
        with self.assertRaises(AccessDenied):
            self.system.access(token, "does_not_exist")

    def test_logout_invalidates_session(self):
        token = self.login("alex", "admin-pass")
        self.system.logout(token)
        with self.assertRaises(AccessDenied):
            self.system.access(token, "master_keys")

    def test_denial_message_does_not_leak_reason(self):
        token = self.login("gina", "guest-pass")
        with self.assertRaises(AccessDenied) as ctx:
            self.system.access(token, "salary_report")
        self.assertNotIn("guest", str(ctx.exception))
        self.assertNotIn("read:confidential", str(ctx.exception))

    def test_accessible_resources_match_role(self):
        guest = self.login("gina", "guest-pass")
        admin = self.login("alex", "admin-pass")
        self.assertEqual(self.system.accessible_resources(guest), ["company_handbook"])
        self.assertEqual(len(self.system.accessible_resources(admin)), 4)
        self.assertEqual(self.system.accessible_resources("forged-token"), [])

    # --- setup validation ----------------------------------------------

    def test_unknown_role_rejected(self):
        with self.assertRaises(ValueError):
            self.system.add_user("zed", "pw", "superuser")

    def test_duplicate_user_rejected(self):
        with self.assertRaises(ValueError):
            self.system.add_user("alex", "pw", "admin")

    # --- audit logging -------------------------------------------------

    def test_every_attempt_is_logged(self):
        token = self.login("gina", "guest-pass")                 # LOGIN granted
        self.system.access(token, "company_handbook")            # ACCESS granted
        with self.assertRaises(AccessDenied):
            self.system.access(token, "master_keys")             # ACCESS denied
        with self.assertRaises(AccessDenied):
            self.login("gina", "bad")                            # LOGIN denied
        with self.assertRaises(AccessDenied):
            self.system.access("forged", "master_keys")          # ACCESS denied (no session)

        log = self.system.log.entries()
        self.assertEqual(
            [(e["event"], e["outcome"]) for e in log],
            [("LOGIN", "GRANTED"), ("ACCESS", "GRANTED"), ("ACCESS", "DENIED"),
             ("LOGIN", "DENIED"), ("ACCESS", "DENIED")],
        )

    def test_log_records_who_what_and_why(self):
        token = self.login("eli", "employee-pass")
        with self.assertRaises(AccessDenied):
            self.system.access(token, "salary_report")
        entry = self.system.log.entries()[-1]
        self.assertEqual(entry["user"], "eli")
        self.assertEqual(entry["resource"], "salary_report")
        self.assertEqual(entry["outcome"], "DENIED")
        self.assertIn("read:confidential", entry["reason"])
        self.assertTrue(entry["timestamp"])

    def test_passwords_and_tokens_never_logged(self):
        token = self.login("alex", "admin-pass")
        self.system.access(token, "master_keys")
        with self.assertRaises(AccessDenied):
            self.login("alex", "super-secret-guess")
        with open(self.log_path, encoding="utf-8") as f:
            raw = f.read()
        for secret in ("admin-pass", "super-secret-guess", token):
            self.assertNotIn(secret, raw)

    def test_log_persists_across_instances(self):
        self.login("gina", "guest-pass")
        before = len(self.system.log.entries())
        other = RBACSystem(self.log_path)  # same log file, fresh instance
        self.assertEqual(len(other.log.entries()), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
