"""Run the Sigma rules in rules/ against an auth.log and print matches per rule.

This is NOT a full Sigma engine. It supports only what our rules use:
  - one selection with "Message|contains" or "Message|re" (the raw log line is the Message)
  - list values are OR-ed, different keys in a selection are AND-ed
  - condition "selection" or "selection | count() by src_ip > N" with a "timeframe"

Usage:
    python src/evaluate_rules.py [data/auth.log] [rules/]
"""

import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from load_linux_auth import parse_line

CONDITION_RE = re.compile(r"^(?P<name>\w+)(?:\s*\|\s*count\(\)\s+by\s+(?P<field>\w+)\s*>\s*(?P<threshold>\d+))?$")
TIMEFRAME_UNITS = {"s": "seconds", "m": "minutes", "h": "hours"}


def load_rules(rules_dir):
    rules = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        with open(path) as f:
            rules.append(yaml.safe_load(f))
    return rules


def parse_timeframe(value):
    """Turn '5m' into timedelta(minutes=5)."""
    number, unit = int(value[:-1]), value[-1]
    return timedelta(**{TIMEFRAME_UNITS[unit]: number})


def line_matches(selection, line):
    """Return True if the raw log line satisfies every key of the selection."""
    for key, values in selection.items():
        field, _, modifier = key.partition("|")
        if field != "Message":
            raise ValueError(f"Unsupported field: {field}")
        if not isinstance(values, list):
            values = [values]

        if modifier == "contains":
            ok = any(v in line for v in values)
        elif modifier == "re":
            ok = any(re.search(v, line) for v in values)
        else:
            raise ValueError(f"Unsupported modifier: {modifier}")

        if not ok:
            return False
    return True


def ips_over_threshold(events, field, threshold, timeframe):
    """Return the set of field values (e.g. IPs) with more than `threshold` events in any window."""
    times_by_key = defaultdict(list)
    for event in events:
        times_by_key[event[field]].append(datetime.fromisoformat(event["timestamp"]))

    alerts = set()
    for key, times in times_by_key.items():
        times.sort()
        start = 0
        # Sliding window: move `start` forward until the window fits in `timeframe`.
        for end in range(len(times)):
            while times[end] - times[start] > timeframe:
                start += 1
            if end - start + 1 > threshold:
                alerts.add(key)
                break
    return alerts


def evaluate(rule, lines):
    """Return (number of matched lines, list of alerts) for one rule."""
    detection = rule["detection"]
    condition = CONDITION_RE.match(detection["condition"].strip())
    if not condition:
        raise ValueError(f"Unsupported condition: {detection['condition']}")

    selection = detection[condition.group("name")]
    matched = [line for line in lines if line_matches(selection, line)]

    if not condition.group("field"):
        # Simple rule: every matched line is an alert.
        return len(matched), matched

    # Aggregation rule: we need parsed fields (timestamp, src_ip) for each line.
    events = [e for e in (parse_line(line) for line in matched) if e]
    alerts = ips_over_threshold(
        events,
        field=condition.group("field"),
        threshold=int(condition.group("threshold")),
        timeframe=parse_timeframe(detection["timeframe"]),
    )
    return len(matched), sorted(alerts)


def mitre_tags(rule):
    return ", ".join(t.removeprefix("attack.").upper() for t in rule.get("tags", []) if re.match(r"attack\.t\d", t))


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "data/auth.log"
    rules_dir = sys.argv[2] if len(sys.argv) > 2 else "rules"

    with open(log_path) as f:
        lines = [line.rstrip("\n") for line in f]

    rows = []
    for rule in load_rules(rules_dir):
        matched_count, alerts = evaluate(rule, lines)
        rows.append((rule["title"], rule["level"], mitre_tags(rule), matched_count, alerts))

    header = f"{'Rule':<42} {'Level':<7} {'ATT&CK':<10} {'Matched lines':>13} {'Alerts':>7}"
    print(header)
    print("-" * len(header))
    for title, level, mitre, matched_count, alerts in rows:
        print(f"{title:<42} {level:<7} {mitre:<10} {matched_count:>13} {len(alerts):>7}")

    print()
    for title, _, _, _, alerts in rows:
        print(f"{title}:")
        for alert in alerts:
            print(f"  {alert}")


if __name__ == "__main__":
    main()
