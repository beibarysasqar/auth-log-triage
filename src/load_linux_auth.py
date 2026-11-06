"""Parse a Linux sshd auth.log, print statistics and optionally index to Elasticsearch.

Usage:
    python src/load_linux_auth.py data/auth.log

Elasticsearch is optional: if http://localhost:9200 is not reachable,
the script only prints statistics.
"""

import json
import re
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime

ES_URL = "http://localhost:9200"
ES_INDEX = "linux-auth"

# Syslog lines have no year, so we assume one for the sample data.
LOG_YEAR = 2026

# Common syslog prefix: "Nov  5 08:15:05 web01 sshd[4872]: <message>"
SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<process>[\w\-]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)

# sshd messages we care about, mapped to an event type.
SSHD_PATTERNS = [
    ("failed_password",
     re.compile(r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)")),
    ("accepted",
     re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)")),
    ("invalid_user",
     re.compile(r"^Invalid user (?P<user>\S+) from (?P<src_ip>\S+) port (?P<port>\d+)")),
]


def parse_line(line):
    """Parse one auth.log line. Return a dict for sshd login events, otherwise None."""
    match = SYSLOG_RE.match(line.strip())
    if not match or match.group("process") != "sshd":
        return None

    message = match.group("message")
    for event_type, pattern in SSHD_PATTERNS:
        event_match = pattern.match(message)
        if event_match:
            ts = datetime.strptime(f"{LOG_YEAR} {match.group('ts')}", "%Y %b %d %H:%M:%S")
            return {
                "timestamp": ts.isoformat(),
                "host": match.group("host"),
                "event_type": event_type,
                "user": event_match.group("user"),
                "src_ip": event_match.group("src_ip"),
                "port": int(event_match.group("port")),
                "message": message,
            }
    return None


def parse_file(path):
    """Parse a whole file and return the list of recognised events."""
    events = []
    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events


def print_stats(events, top_n=5):
    failed = [e for e in events if e["event_type"] == "failed_password"]
    accepted = [e for e in events if e["event_type"] == "accepted"]

    print(f"Parsed sshd events:  {len(events)}")
    print(f"Failed logins:       {len(failed)}")
    print(f"Successful logins:   {len(accepted)}")
    print()
    print(f"Top {top_n} source IPs by failed logins:")
    for ip, count in Counter(e["src_ip"] for e in failed).most_common(top_n):
        print(f"  {ip:<16} {count}")


def elasticsearch_available():
    try:
        with urllib.request.urlopen(ES_URL, timeout=2) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError):
        return False


def delete_index():
    """Drop the index so re-running the script does not create duplicates."""
    request = urllib.request.Request(f"{ES_URL}/{ES_INDEX}", method="DELETE")
    try:
        urllib.request.urlopen(request, timeout=10)
    except urllib.error.HTTPError as error:
        if error.code != 404:  # 404 means the index does not exist yet
            raise


def index_to_elasticsearch(events):
    """Send all events in one _bulk request (NDJSON: action line + document line)."""
    delete_index()
    body = ""
    for event in events:
        body += json.dumps({"index": {"_index": ES_INDEX}}) + "\n"
        body += json.dumps(event) + "\n"

    request = urllib.request.Request(
        f"{ES_URL}/_bulk?refresh=true",
        data=body.encode(),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        result = json.load(response)

    if result.get("errors"):
        print("Elasticsearch reported errors for some documents.")
    else:
        print(f"Indexed {len(result['items'])} events into '{ES_INDEX}'.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python src/load_linux_auth.py <auth.log>")
        sys.exit(1)

    events = parse_file(sys.argv[1])
    print_stats(events)
    print()

    if elasticsearch_available():
        index_to_elasticsearch(events)
    else:
        print(f"Elasticsearch not reachable at {ES_URL}, skipping indexing.")


if __name__ == "__main__":
    main()
