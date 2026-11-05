"""
Interactive command-line front end for the RBAC system.

    python cli.py                 # logs to ./access.log
    python cli.py --log my.log    # logs to a file of your choice

The password is typed with echo turned off. After MAX_LOGIN_ATTEMPTS failed
logins the program exits. Every attempt is recorded in the log file.
"""

import argparse
import getpass

from rbac import AccessDenied, build_sample_system

MAX_LOGIN_ATTEMPTS = 3
HELP = "Commands: list | <resource name> | help | logout"

DEMO_NOTE = """\
Sample accounts (username / password / role):
  gina / guest-pass    / guest
  eli  / employee-pass / employee
  maya / manager-pass  / manager
  alex / admin-pass    / admin
Sample resources: company_handbook (public), team_roadmap (internal),
                  salary_report (confidential), master_keys (secret)
"""


def run(system, input_fn=input, password_fn=getpass.getpass, out=print,
        max_attempts=MAX_LOGIN_ATTEMPTS):
    """Prompt for a login, then accept commands. Returns 0 on a clean logout, 1 if login fails.

    input_fn / password_fn / out are injectable so the flow can be tested without a terminal.
    """
    token = None
    for _ in range(max_attempts):
        username = input_fn("Username: ").strip()
        password = password_fn("Password: ")
        try:
            token = system.login(username, password)
            break
        except AccessDenied:
            out("Login failed.")

    if token is None:
        out("Too many failed login attempts.")
        return 1

    out(f"Logged in. {HELP}")
    while True:
        command = input_fn("> ").strip()
        if not command:
            continue
        if command in ("logout", "quit", "exit"):
            system.logout(token)
            out("Logged out.")
            return 0
        if command == "help":
            out(HELP)
        elif command == "list":
            names = system.accessible_resources(token)
            out("You can access: " + (", ".join(names) or "(nothing)"))
        else:
            try:
                out(system.access(token, command))
            except AccessDenied:
                out("Access denied. This attempt has been logged.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Role-based access control demo")
    parser.add_argument("--log", default="access.log", help="path of the audit log file")
    args = parser.parse_args(argv)

    system = build_sample_system(args.log)
    print(DEMO_NOTE)
    try:
        return run(system)
    except (EOFError, KeyboardInterrupt):
        print("\nInput closed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
