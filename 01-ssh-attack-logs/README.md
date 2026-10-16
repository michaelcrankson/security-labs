# SQL Security Log Analysis Lab

Hunting SSH attacks in real server logs with SQL.

I took about four hours of real SSH logs from a server under attack, loaded them into a
database, and used SQL to answer the questions a security analyst would ask: who attacked,
what they tried, how fast, whether anyone got in, and when it peaked.

## Dataset
`data/OpenSSH_2k.log`: 2,000 lines of real OpenSSH server logs from the
[Loghub](https://github.com/logpai/loghub) collection (logpai), a public log dataset
published for research. It covers one server on Dec 10, from 06:55 to 11:04.

## Setup
The log isn't stored in this repo. Download it from Loghub first:
```
curl -o data/OpenSSH_2k.log https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log
python3 load_logs.py      # builds ssh_logs.db (table: ssh_logs)
sqlite3 ssh_logs.db       # then: .headers on   and   .mode column
```

| Column | Meaning |
|---|---|
| `ts` | timestamp (syslog has no year; 2000 is a placeholder so date functions work) |
| `pid` | sshd process id: one process = one connection attempt |
| `event_type` | failed_password, invalid_user, auth_failure, accepted, disconnect, break_in_warning, ... |
| `username`, `src_ip` | who was tried, and from where |
| `invalid_user` | 1 if the username doesn't exist on the server |
| `repeat_count` | >1 when syslog collapsed repeats ("message repeated N times") |
| `message` | the original log line text |

All queries, with notes, are in [`queries.sql`](queries.sql).

## Findings

**1. One IP did over half the damage.**
There were 519 failed password attempts from 23 different IPs. 286 of them came from a
single address, 183.62.140.253.

**2. Root was the main target, inside a wider dictionary attack.**
Attackers tried 62 different usernames (admin, support, oracle, test, guest and so on),
but 370 of the 519 failures (about 71%) were guesses at `root`, the account with full
control of the server. Most of the other names don't exist on this server, so those
guesses could never work. `root` does exist, which is what made it the real risk.

**3. It was brute force: automated, and fast.**
Grouping failures per IP per minute showed 183.62.140.253 hitting up to 30 failed
passwords a minute. All 286 of its attempts landed in about ten minutes (10:54 to 11:04),
roughly one guess every two seconds. No person types that fast, so this was a tool.
Totals show how much an IP attacked; per-minute counts show how fast.

**4. Nobody broke in.**
There was exactly one successful login: user `fztu` from 119.137.62.142 at 09:32. That IP
had no failed attempts at all. It got the password right first time, stayed about 13
minutes, and disconnected normally. That looks like a legitimate user, not a cracked
account, and none of the attacking IPs ever got in.
Caveat: a stolen password (as opposed to a guessed one) would look exactly the same, so
in a real investigation I'd confirm with the user or check the IP against known locations
before closing it.

**5. The attack was getting worse when the log ended.**

| Hour | Failed passwords |
|---|---|
| 06 | 1 |
| 07 | 44 |
| 08 | 24 |
| 09 | 133 |
| 10 | 171 |
| 11 | 146 |

The attacks came in waves from different IPs through the morning. The 11:00 hour looks
similar to 10:00, but the log stops at 11:04, so those 146 failures happened in under five
minutes. The attack was at full speed when the record ends.

**Data note.** The server sometimes collapses repeated lines into one ("message repeated 5
times"). Counting rows gives 519 failures; adding up the repeats gives 527. Eight attempts
on root (from 5.36.59.76 and 106.5.5.195) are hidden inside two collapsed lines. Small
here, but on a busy server, counting rows instead of events would undercount an attack.

## Defences
What would have stopped this:

- **Disable root login over SSH** (`PermitRootLogin no`). That alone makes 71% of this
  attack pointless; admins log in as themselves and use `sudo`.
- **Block repeat offenders automatically** with fail2ban. A rule like "5 failures in 10
  minutes = ban" would have stopped 183.62.140.253 after a handful of guesses instead of 286.
- **Use SSH keys instead of passwords** (`PasswordAuthentication no`). With no password to
  guess, a dictionary attack has nothing to work with.
- **Alert on the pattern**, not just the total: the per-minute query in challenge 3 is
  effectively a detection rule.

## What I learned
- `LIMIT` on raw rows shows the *first* rows, not the *top* ones. Count first, then sort.
- Text values in SQL need exact spelling and single quotes. When a query returns nothing,
  check the real values with `SELECT DISTINCT`.
- Grouping by two columns (IP and minute) turns "how much" into "how fast".
- Not every alert is an attack, but you verify before you dismiss it.
