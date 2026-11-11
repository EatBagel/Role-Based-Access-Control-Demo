import os
import tempfile
import unittest

import cli
from rbac import build_sample_system


class CLITests(unittest.TestCase):
    def setUp(self):
        fd, self.log_path = tempfile.mkstemp(suffix=".log")
        os.close(fd)
        os.remove(self.log_path)
        self.system = build_sample_system(self.log_path)

    def tearDown(self):
        if os.path.exists(self.log_path):
            os.remove(self.log_path)

    def run_cli(self, usernames_and_commands, passwords):
        """Feed scripted input to cli.run; return (exit_code, output_lines)."""
        inputs, pws, output = iter(usernames_and_commands), iter(passwords), []
        code = cli.run(
            self.system,
            input_fn=lambda prompt: next(inputs),
            password_fn=lambda prompt: next(pws),
            out=output.append,
        )
        return code, output

    def log(self):
        return [(e["event"], e["user"], e["resource"], e["outcome"]) for e in self.system.log.entries()]

    def test_login_then_authorized_access(self):
        code, out = self.run_cli(["gina", "company_handbook", "logout"], ["guest-pass"])
        self.assertEqual(code, 0)
        self.assertIn("Welcome to the company!", out)

    def test_unauthorized_resource_is_blocked_and_logged(self):
        code, out = self.run_cli(["gina", "salary_report", "logout"], ["guest-pass"])
        self.assertEqual(code, 0)
        self.assertTrue(any("Access denied" in line for line in out))
        self.assertFalse(any("Salary" in line for line in out))
        self.assertIn(("ACCESS", "gina", "salary_report", "DENIED"), self.log())

    def test_unknown_resource_is_blocked(self):
        _, out = self.run_cli(["alex", "nope", "logout"], ["admin-pass"])
        self.assertTrue(any("Access denied" in line for line in out))

    def test_retry_after_failed_login(self):
        code, out = self.run_cli(["alex", "alex", "master_keys", "logout"], ["bad", "admin-pass"])
        self.assertEqual(code, 0)
        self.assertEqual(out.count("Login failed."), 1)
        self.assertTrue(any("Encryption key" in line for line in out))

    def test_three_failed_logins_exit_with_error(self):
        code, out = self.run_cli(["alex", "alex", "alex"], ["a", "b", "c"])
        self.assertEqual(code, 1)
        self.assertEqual(out.count("Login failed."), 3)
        self.assertIn("Too many failed login attempts.", out)
        denied = [e for e in self.log() if e[0] == "LOGIN" and e[3] == "DENIED"]
        self.assertEqual(len(denied), 3)

    def test_list_shows_only_permitted_resources(self):
        _, out = self.run_cli(["eli", "list", "logout"], ["employee-pass"])
        listing = next(line for line in out if line.startswith("You can access"))
        self.assertIn("company_handbook", listing)
        self.assertIn("team_roadmap", listing)
        self.assertNotIn("salary_report", listing)
        self.assertNotIn("master_keys", listing)

    def test_logout_is_logged(self):
        self.run_cli(["maya", "logout"], ["manager-pass"])
        self.assertIn(("LOGOUT", "maya", None, "GRANTED"), self.log())

    def test_password_never_written_to_log(self):
        self.run_cli(["alex", "logout"], ["admin-pass"])
        with open(self.log_path, encoding="utf-8") as f:
            self.assertNotIn("admin-pass", f.read())

    def test_log_is_written_to_the_configured_separate_file(self):
        self.run_cli(["gina", "logout"], ["guest-pass"])
        self.assertTrue(os.path.exists(self.log_path))
        self.assertEqual(self.system.log.path, self.log_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
