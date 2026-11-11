# rbac-access-control

A small role-based access control (RBAC) system in Python. Authorized users can read sensitive information, everyone else is blocked, and every attempt is recorded in a separate audit log. Standard library only, Python 3.9+, no dependencies.

## Quick start

```
python cli.py                  # interactive login; logs to ./access.log
python cli.py --log my.log     # log to a file of your choice
python rbac.py                 # scripted demo
python -m unittest -v          # run the tests
```

Sample accounts (printed when `cli.py` starts; for demonstration only):

| User | Password | Role |
|---|---|---|
| gina | guest-pass | guest |
| eli | employee-pass | employee |
| maya | manager-pass | manager |
| alex | admin-pass | admin |

Sample resources: `company_handbook` (public), `team_roadmap` (internal), `salary_report` (confidential), `master_keys` (secret).

## Example session

Passwords are typed with echo off, so they don't appear on screen.

```
Username: gina
Password:
Login failed.
Username: gina
Password:
Logged in. Commands: list | <resource name> | help | logout
> list
You can access: company_handbook
> company_handbook
Welcome to the company!
> salary_report
Access denied. This attempt has been logged.
> logout
Logged out.
```

## How it works

- **Roles and permissions:** each role maps to a set of permissions (`guest` < `employee` < `manager` < `admin`), and each sensitive resource requires one permission.
- **Authentication:** passwords are stored as salted PBKDF2 hashes and compared in constant time. A successful login returns a random session token.
- **Deny by default:** unknown users, wrong passwords, forged or logged-out tokens, unknown resources, and roles without the required permission are all blocked.
- **Generic errors:** callers only see "Login failed" or "Access denied", so they can't learn whether a user or resource exists. The real reason goes in the log.
- **Audit log:** every login, logout and access attempt, granted or denied, is appended to `access.log`, one JSON object per line. Passwords and tokens are never logged.

### Log format

| Field | Meaning |
|---|---|
| `timestamp` | UTC time of the attempt |
| `event` | `LOGIN`, `LOGOUT` or `ACCESS` |
| `user` | Username, or `null` if the caller couldn't be identified |
| `resource` | Resource requested (`null` for login events) |
| `outcome` | `GRANTED` or `DENIED` |
| `reason` | Why, for example `role 'guest' lacks 'read:confidential'` |

```json
{"timestamp": "2026-11-11T14:02:09+00:00", "event": "ACCESS", "user": "gina", "resource": "salary_report", "outcome": "DENIED", "reason": "role 'guest' lacks 'read:confidential'"}
```

## Use it as a library

```python
from rbac import RBACSystem, AccessDenied

system = RBACSystem("access.log")
system.add_user("sam", "a-strong-password", "manager")
system.add_resource("q3_forecast", "Revenue forecast: ...", "read:confidential")
system.add_resource("vault_codes", "Vault codes: ...", "read:secret")

token = system.login("sam", "a-strong-password")
print(system.access(token, "q3_forecast"))      # allowed: managers hold read:confidential

try:
    system.access(token, "vault_codes")          # blocked: needs read:secret
except AccessDenied:
    print("blocked, and logged")

print(system.accessible_resources(token))        # ['q3_forecast']
```

To change who can see what, edit `ROLE_PERMISSIONS` in `rbac.py`. If you do, update `test_T3_role_permissions_snapshot` in `test_threats.py` on purpose; it exists to catch accidental changes.

## Project layout

| Path | Purpose |
|---|---|
| `rbac.py` | Users, roles, permissions, login and access checks |
| `audit_log.py` | Append-only JSON-lines audit log |
| `cli.py` | Interactive login and command prompt |
| `test_rbac.py`, `test_cli.py` | Functional tests |
| `test_threats.py` | Tests tied to the threat model (6 verify controls, 4 track known gaps) |
| `docs/THREAT_MODEL.md` | STRIDE threat model: system map, ranked threats, mitigations |
| `.github/workflows/tests.yml` | Runs the tests on every push |

## Testing

`python -m unittest -v` runs 38 tests. Four of them are marked as expected failures: they describe security behavior the code doesn't have yet (account lockout, authorization on `add_user`, logging of admin actions, handling of malformed input). The suite stays green while those gaps stay visible. When you fix one, the test reports "unexpected success"; remove its `@unittest.expectedFailure` decorator.

## Security

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the threats considered, how they were rated, and the proposed mitigations. In short, this is a basic version meant for learning and prototyping. It has no account lockout, no session expiry, no protection against edits to the log file, and keeps users and sessions in memory only. Don't deploy it with the sample accounts.
