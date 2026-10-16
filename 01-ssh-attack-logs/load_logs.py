"""Parse the raw OpenSSH log into a SQLite table so it can be queried with SQL.

Usage: python3 load_logs.py   (creates ssh_logs.db next to this file)

Syslog lines don't record a year, so ts uses a placeholder year (2000) only so
SQLite's date/time functions work. Month, day and time are real.
"""
import re
import sqlite3
from pathlib import Path

HERE = Path(__file__).parent
LOG = HERE / "data" / "OpenSSH_2k.log"
DB = HERE / "ssh_logs.db"

MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}

LINE = re.compile(r"^(\w{3})\s+(\d+) (\d\d:\d\d:\d\d) (\S+) sshd\[(\d+)\]: (.*)$")
IP = r"(\d{1,3}(?:\.\d{1,3}){3})"

# (event_type, pattern). First match wins. Named groups: user, ip.
RULES = [
    ("failed_password", re.compile(rf"Failed password for invalid user (?P<user>\S+) from {IP.replace('(', '(?P<ip>', 1)}")),
    ("failed_password", re.compile(rf"Failed password for (?P<user>\S+) from {IP.replace('(', '(?P<ip>', 1)}")),
    ("accepted", re.compile(rf"Accepted \w+ for (?P<user>\S+) from {IP.replace('(', '(?P<ip>', 1)}")),
    ("invalid_user", re.compile(rf"^Invalid user (?P<user>\S*) from {IP.replace('(', '(?P<ip>', 1)}")),
    ("auth_failure", re.compile(r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?")),
    ("session_opened", re.compile(r"session opened for user (?P<user>\S+)")),
    ("session_closed", re.compile(r"session closed for user (?P<user>\S+)")),
    ("too_many_failures", re.compile(r"Too many authentication failures for (?P<user>\S+)")),
    ("break_in_warning", re.compile(rf"POSSIBLE BREAK-IN ATTEMPT.*|reverse mapping.*\[{IP.replace('(', '(?P<ip>', 1)}\]")),
    ("disconnect", re.compile(rf"Received disconnect from {IP.replace('(', '(?P<ip>', 1)}")),
    ("connection_closed", re.compile(rf"Connection closed by {IP.replace('(', '(?P<ip>', 1)}")),
    ("no_identification", re.compile(rf"Did not receive identification string from {IP.replace('(', '(?P<ip>', 1)}")),
]
REPEATED = re.compile(r"^message repeated (\d+) times: \[ (.*)\]$")


def classify(msg):
    """Return (event_type, username, src_ip, invalid_user, repeat_count)."""
    repeat = 1
    m = REPEATED.match(msg)
    if m:
        repeat, msg = int(m.group(1)), m.group(2)
    for event, rx in RULES:
        hit = rx.search(msg)
        if hit:
            g = hit.groupdict()
            invalid = int("invalid user" in msg or event == "invalid_user")
            return event, g.get("user"), g.get("ip"), invalid, repeat
    return "other", None, None, 0, repeat


def main():
    DB.unlink(missing_ok=True)
    con = sqlite3.connect(DB)
    con.execute("""
        CREATE TABLE ssh_logs (
            id            INTEGER PRIMARY KEY,
            ts            TEXT,     -- 2000-MM-DD HH:MM:SS (placeholder year)
            host          TEXT,
            pid           INTEGER,  -- one sshd process = one connection attempt
            event_type    TEXT,
            username      TEXT,
            src_ip        TEXT,
            invalid_user  INTEGER,  -- 1 if the username doesn't exist on the server
            repeat_count  INTEGER,  -- >1 when syslog collapsed repeats ("message repeated N times")
            message       TEXT      -- the original log text
        )""")
    rows, skipped = [], 0
    for line in LOG.read_text(errors="replace").splitlines():
        m = LINE.match(line)
        if not m:
            skipped += 1
            continue
        mon, day, time, host, pid, msg = m.groups()
        ts = f"2000-{MONTHS[mon]:02d}-{int(day):02d} {time}"
        rows.append((ts, host, int(pid), *classify(msg), msg))
    con.executemany(
        "INSERT INTO ssh_logs (ts, host, pid, event_type, username, src_ip,"
        " invalid_user, repeat_count, message) VALUES (?,?,?,?,?,?,?,?,?)", rows)
    con.commit()
    print(f"Loaded {len(rows)} rows into {DB.name} ({skipped} unparsed lines skipped)")
    for event, n in con.execute(
            "SELECT event_type, COUNT(*) FROM ssh_logs GROUP BY 1 ORDER BY 2 DESC"):
        print(f"  {event:<18} {n}")


if __name__ == "__main__":
    main()
