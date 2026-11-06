"""Generate a synthetic sshd auth.log for the demo.

The output is deterministic (fixed random seed), so every run produces
the same file and the numbers in the README stay reproducible.

Only documentation IP ranges are used (RFC 5737):
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.

Usage:
    python src/generate_sample_log.py data/auth.log
"""

import random
import sys
from datetime import datetime, timedelta

HOST = "web01"
START = datetime(2026, 11, 5, 8, 0, 0)

rng = random.Random(42)


def syslog_time(ts):
    # Classic syslog format: "Nov  5 08:00:00" (day padded with a space, no year).
    return ts.strftime("%b ") + f"{ts.day:>2}" + ts.strftime(" %H:%M:%S")


def line(ts, process, message):
    return (ts, f"{syslog_time(ts)} {HOST} {process}: {message}")


def sshd():
    return f"sshd[{rng.randint(1000, 9999)}]"


def port():
    return rng.randint(40000, 65000)


def normal_sessions():
    """Legitimate logins from the office network (192.0.2.x)."""
    users = {"alice": "192.0.2.10", "bob": "192.0.2.11", "carol": "192.0.2.12"}
    lines = []
    for _ in range(40):
        user = rng.choice(list(users))
        ip = users[user]
        ts = START + timedelta(minutes=rng.randint(0, 600), seconds=rng.randint(0, 59))
        p = port()
        proc = sshd()
        method = rng.choice(["publickey", "password"])
        lines.append(line(ts, proc, f"Accepted {method} for {user} from {ip} port {p} ssh2"))
        lines.append(line(ts, proc, f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)"))
        end = ts + timedelta(minutes=rng.randint(5, 90))
        lines.append(line(end, proc, f"Disconnected from user {user} {ip} port {p}"))
    return lines


def cron_noise():
    """Unrelated CRON lines, so the parser has to skip them."""
    lines = []
    for i in range(50):
        ts = START + timedelta(minutes=i * 12)
        lines.append(line(ts, f"CRON[{rng.randint(1000, 9999)}]",
                          "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
    return lines


def typo_failures():
    """A few failed logins from real users mistyping passwords (below any threshold)."""
    lines = []
    for user, ip, count in [("bob", "198.51.100.7", 3), ("carol", "198.51.100.23", 4)]:
        for _ in range(count):
            ts = START + timedelta(minutes=rng.randint(0, 600))
            lines.append(line(ts, sshd(), f"Failed password for {user} from {ip} port {port()} ssh2"))
    return lines


def slow_scanner():
    """8 failures spread over ~80 minutes: many failures, but not a burst."""
    lines = []
    ts = START + timedelta(hours=2)
    for _ in range(8):
        ts += timedelta(minutes=10)
        lines.append(line(ts, sshd(), f"Failed password for root from 203.0.113.77 port {port()} ssh2"))
    return lines


def brute_force():
    """60 failed attempts in about 4 minutes from one IP (the attack)."""
    ip = "203.0.113.50"
    lines = []
    ts = START + timedelta(hours=4)
    for _ in range(60):
        ts += timedelta(seconds=4)
        proc = sshd()
        p = port()
        user = rng.choice(["root", "admin", "test", "oracle", "ubuntu"])
        if user == "root":
            lines.append(line(ts, proc, f"Failed password for root from {ip} port {p} ssh2"))
        else:
            # Unknown accounts log an extra "Invalid user" line first.
            lines.append(line(ts, proc, f"Invalid user {user} from {ip} port {p}"))
            lines.append(line(ts, proc, f"Failed password for invalid user {user} from {ip} port {p} ssh2"))
    return lines


def privileged_group_change():
    """An admin creates a user and adds it to the sudo group."""
    ts = START + timedelta(hours=6)
    return [
        line(ts, "sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -m dave"),
        line(ts, "useradd[4242]", "new group: name=dave, GID=1004"),
        line(ts, "useradd[4242]",
             "new user: name=dave, UID=1004, GID=1004, home=/home/dave, shell=/bin/sh, from=/dev/pts/0"),
        line(ts + timedelta(minutes=1), "sudo",
             "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo dave"),
        line(ts + timedelta(minutes=1), "usermod[4250]", "add 'dave' to group 'sudo'"),
        line(ts + timedelta(minutes=1), "usermod[4250]", "add 'dave' to shadow group 'sudo'"),
    ]


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "data/auth.log"
    lines = (normal_sessions() + cron_noise() + typo_failures()
             + slow_scanner() + brute_force() + privileged_group_change())
    # Sort by timestamp so the file looks like a real log. sorted() is stable,
    # so lines with the same timestamp keep their order.
    lines.sort(key=lambda item: item[0])
    with open(out_path, "w") as f:
        for _, text in lines:
            f.write(text + "\n")
    print(f"Wrote {len(lines)} lines to {out_path}")


if __name__ == "__main__":
    main()
