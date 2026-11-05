"""
Basic Role-Based Access Control (RBAC) system.

- Users authenticate with a password and receive a session token.
- Each role maps to a set of permissions; each sensitive resource requires one permission.
- Access is DENIED by default: unknown tokens, unknown roles, or unknown resources are all blocked.
- Every login and access attempt (granted or denied) is written to a separate append-only
  log file (see audit_log.py, default `access.log`).

Standard library only. Run `python cli.py` for the interactive login, `python rbac.py` for a scripted demo,
`python -m unittest -v` for tests.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from audit_log import AuditLog

# ---------------------------------------------------------------------------
# Roles and permissions
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS = {
    "guest":    frozenset({"read:public"}),
    "employee": frozenset({"read:public", "read:internal"}),
    "manager":  frozenset({"read:public", "read:internal", "read:confidential"}),
    "admin":    frozenset({"read:public", "read:internal", "read:confidential", "read:secret"}),
}

PBKDF2_ITERATIONS = 200_000


class AccessDenied(Exception):
    """Raised for any failed login or access attempt.

    The message is deliberately generic so callers can't learn *why* they
    were blocked (e.g. whether a username or resource exists). The real
    reason is recorded in the audit log.
    """


# ---------------------------------------------------------------------------
# Core system
# ---------------------------------------------------------------------------

@dataclass
class _User:
    username: str
    role: str
    salt: bytes
    password_hash: bytes


@dataclass
class _Resource:
    name: str
    data: str
    required_permission: str


def _hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)


class RBACSystem:
    def __init__(self, log_path="access.log"):
        self.log = AuditLog(log_path)
        self._users = {}
        self._resources = {}
        self._sessions = {}  # token -> username

    # --- setup ------------------------------------------------------------

    def add_user(self, username, password, role):
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role: {role!r}")
        if username in self._users:
            raise ValueError(f"User already exists: {username!r}")
        salt = secrets.token_bytes(16)
        self._users[username] = _User(username, role, salt, _hash_password(password, salt))

    def add_resource(self, name, data, required_permission):
        self._resources[name] = _Resource(name, data, required_permission)

    # --- authentication ---------------------------------------------------

    def login(self, username, password):
        """Return a session token, or raise AccessDenied."""
        user = self._users.get(username)

        # Always do the hashing work so response time doesn't reveal valid usernames.
        salt = user.salt if user else b"\x00" * 16
        candidate = _hash_password(password, salt)

        if user is None:
            self.log.record("LOGIN", username, "DENIED", reason="unknown user")
            raise AccessDenied("Login failed.")
        if not hmac.compare_digest(candidate, user.password_hash):
            self.log.record("LOGIN", username, "DENIED", reason="wrong password")
            raise AccessDenied("Login failed.")

        token = secrets.token_urlsafe(32)
        self._sessions[token] = username
        self.log.record("LOGIN", username, "GRANTED", reason=f"role={user.role}")
        return token

    def logout(self, token):
        username = self._sessions.pop(token, None)
        if username:
            self.log.record("LOGOUT", username, "GRANTED")

    # --- authorization ----------------------------------------------------

    def access(self, token, resource_name):
        """Return the resource's data if the session's role permits it, else raise AccessDenied."""
        username = self._sessions.get(token)
        if username is None:
            self.log.record("ACCESS", None, "DENIED", resource_name, "invalid or expired session")
            raise AccessDenied("Access denied.")

        user = self._users[username]
        resource = self._resources.get(resource_name)
        if resource is None:
            self.log.record("ACCESS", username, "DENIED", resource_name, "resource not found")
            raise AccessDenied("Access denied.")

        allowed = ROLE_PERMISSIONS.get(user.role, frozenset())
        if resource.required_permission not in allowed:
            self.log.record(
                "ACCESS", username, "DENIED", resource_name,
                f"role '{user.role}' lacks '{resource.required_permission}'",
            )
            raise AccessDenied("Access denied.")

        self.log.record(
            "ACCESS", username, "GRANTED", resource_name,
            f"role '{user.role}' has '{resource.required_permission}'",
        )
        return resource.data

    def accessible_resources(self, token):
        """Names of the resources this session is permitted to read (not logged: it is a listing, not an access)."""
        username = self._sessions.get(token)
        if username is None:
            return []
        allowed = ROLE_PERMISSIONS.get(self._users[username].role, frozenset())
        return sorted(r.name for r in self._resources.values() if r.required_permission in allowed)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def build_sample_system(log_path="access.log"):
    system = RBACSystem(log_path)
    system.add_user("gina", "guest-pass", "guest")
    system.add_user("eli", "employee-pass", "employee")
    system.add_user("maya", "manager-pass", "manager")
    system.add_user("alex", "admin-pass", "admin")

    system.add_resource("company_handbook", "Welcome to the company!", "read:public")
    system.add_resource("team_roadmap", "Q1: ship v2. Q2: expand.", "read:internal")
    system.add_resource("salary_report", "[SAMPLE] Salary bands: ...", "read:confidential")
    system.add_resource("master_keys", "[SAMPLE] Encryption key backup: ...", "read:secret")
    return system


if __name__ == "__main__":
    system = build_sample_system("access.log")
    attempts = [
        ("gina", "guest-pass", "company_handbook"),   # allowed
        ("gina", "guest-pass", "salary_report"),      # blocked: role too low
        ("eli", "employee-pass", "team_roadmap"),     # allowed
        ("maya", "manager-pass", "salary_report"),    # allowed
        ("maya", "manager-pass", "master_keys"),      # blocked
        ("alex", "admin-pass", "master_keys"),        # allowed
        ("alex", "wrong-pass", "master_keys"),        # blocked: bad password
    ]
    for user, pw, resource in attempts:
        try:
            token = system.login(user, pw)
            system.access(token, resource)
            print(f"GRANTED  {user:5} -> {resource}")
        except AccessDenied:
            print(f"DENIED   {user:5} -> {resource}")

    try:
        system.access("forged-token", "master_keys")
    except AccessDenied:
        print("DENIED   (no valid session) -> master_keys")

    print("\n--- access.log ---")
    for e in system.log.entries():
        print(f"{e['timestamp']}  {e['event']:6} {e['outcome']:7} user={e['user']} "
              f"resource={e['resource']} ({e['reason']})")
