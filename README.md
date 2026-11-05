# rbac-access-control

A small role-based access control (RBAC) system in Python. It lets authorized users read sensitive information, blocks everyone else, and records every attempt in a separate audit log. Standard library only, no dependencies.

## Quick start

```
python cli.py                  # interactive login; logs to ./access.log
python cli.py --log my.log     # log to a file of your choice
python rbac.py                 # scripted demo
python -m unittest -v          # run the tests
```

Sample accounts (shown when `cli.py` starts):

| User | Password | Role |
|---|---|---|
| gina | guest-pass | guest |
| eli | employee-pass | employee |
| maya | manager-pass | manager |
| alex | admin-pass | admin |

Once logged in, type `list` to see what your role can access, a resource name (for example `salary_report`) to try to open it, or `logout` to leave.

## How it works

- **Roles and permissions:** each role maps to a set of permissions (`guest` < `employee` < `manager` < `admin`), and each sensitive resource requires one permission.
- **Authentication:** passwords are stored as salted PBKDF2 hashes and compared in constant time. A successful login returns a session token.
- **Deny by default:** unknown users, wrong passwords, forged or logged-out tokens, unknown resources, and roles without the required permission are all blocked.
- **Generic errors:** callers only ever see "Login failed" or "Access denied", so they can't learn whether a user or resource exists. The real reason goes in the log.
- **Audit log:** every login, logout and access attempt, granted or denied, is appended to `access.log` as one JSON object per line. Passwords and tokens are never logged.

Example log line:

```json
{"timestamp": "2026-11-03T00:08:43+00:00", "event": "ACCESS", "user": "gina", "resource": "salary_report", "outcome": "DENIED", "reason": "role 'guest' lacks 'read:confidential'"}
```

## Project layout

| File | Purpose |
|---|---|
| `rbac.py` | Users, roles, permissions, login and access checks |
| `audit_log.py` | Append-only JSON-lines audit log |
| `cli.py` | Interactive login and command prompt |
| `test_rbac.py`, `test_cli.py` | Unit tests (28) |
| `.github/workflows/tests.yml` | Runs the tests on every push |

## Limitations

This is a basic version for learning and prototyping. It does not include account lockout across sessions, session expiry, persistent user storage (users and sessions live in memory), or log tamper protection. The sample accounts and data are for demonstration only.
