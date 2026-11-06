from load_linux_auth import parse_file, parse_line


def test_parse_failed_password_for_invalid_user():
    line = ("Nov  5 12:00:04 web01 sshd[1234]: Failed password for invalid user admin "
            "from 203.0.113.50 port 51234 ssh2")

    event = parse_line(line)

    assert event["event_type"] == "failed_password"
    assert event["user"] == "admin"
    assert event["src_ip"] == "203.0.113.50"
    assert event["port"] == 51234
    assert event["timestamp"] == "2026-11-05T12:00:04"


def test_parse_file_skips_unrelated_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(
        "Nov  5 08:00:00 web01 CRON[1]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n"
        "Nov  5 08:01:00 web01 sshd[2]: Failed password for root from 198.51.100.7 port 40000 ssh2\n"
        "Nov  5 08:02:00 web01 sshd[3]: Accepted publickey for alice from 192.0.2.10 port 40001 ssh2\n"
        "Nov  5 08:03:00 web01 usermod[4]: add 'dave' to group 'sudo'\n"
        "not a syslog line at all\n"
    )

    events = parse_file(log)

    assert [e["event_type"] for e in events] == ["failed_password", "accepted"]
