# Linux Auth Log Triage

A small demo project: parse an sshd `auth.log`, detect suspicious activity with two
Sigma rules, and triage it with a playbook. Simplicity over completeness.

## Structure

```
data/auth.log            synthetic sample log (300 lines, documentation IPs only)
rules/                   two Sigma rules (YAML)
src/generate_sample_log.py   generates data/auth.log (fixed seed, reproducible)
src/load_linux_auth.py   parser + statistics + optional Elasticsearch indexing
src/evaluate_rules.py    minimal Sigma evaluator, prints matches per rule
playbooks/ssh_bruteforce.md  triage playbook
tests/                   pytest tests for the parser
docker-compose.yml       single-node Elasticsearch for local dev
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install pyyaml pytest
```

Dependencies: `pyyaml` (the standard library has no YAML parser) and `pytest`.
Elasticsearch is accessed with `urllib` from the standard library.

## Sample data

`data/auth.log` is fully synthetic and uses only RFC 5737 documentation ranges
(`192.0.2.x`, `198.51.100.x`, `203.0.113.x`). It contains:

- normal logins from `192.0.2.10-12`;
- a few password typos from `198.51.100.7` and `198.51.100.23`;
- a slow guesser `203.0.113.77` (one attempt every 10 minutes);
- a brute-force burst from `203.0.113.50` (one attempt every 4 seconds);
- `useradd` of user `dave` and `usermod -aG sudo dave`;
- unrelated CRON lines.

Regenerate it with `python src/generate_sample_log.py data/auth.log`.

## 1. Parse the log

```bash
python src/load_linux_auth.py data/auth.log
```

Output (Elasticsearch not running):

```
Parsed sshd events:  164
Failed logins:       75
Successful logins:   40

Top 5 source IPs by failed logins:
  203.0.113.50     60
  203.0.113.77     8
  198.51.100.23    4
  198.51.100.7     3

Elasticsearch not reachable at http://localhost:9200, skipping indexing.
```

"Parsed sshd events" counts `Failed password`, `Accepted ...` and `Invalid user` lines.

### Optional: Elasticsearch

```bash
docker compose up -d          # single node, security disabled, 1 GB memory limit
python src/load_linux_auth.py data/auth.log
```

The last line of the output becomes:

```
Indexed 164 events into 'linux-auth'.
```

The script deletes and recreates the `linux-auth` index on every run, so there are no duplicates.
Check with `curl localhost:9200/linux-auth/_count`.

## 2. Run the detection rules

| Rule | ATT&CK | Logic |
|------|--------|-------|
| `rules/ssh_bruteforce.yml` | T1110.001 | `Failed password` lines, `count() by src_ip > 10` within `5m` |
| `rules/linux_privileged_group_change.yml` | T1098 | regex on `useradd`/`usermod` "add '...' to group 'sudo/wheel/adm/root'" |

```bash
python src/evaluate_rules.py
```

Output:

```
Rule                                       Level   ATT&CK     Matched lines  Alerts
-----------------------------------------------------------------------------------
User Added To Privileged Group On Linux    medium  T1098                  2       2
SSH Brute Force From Single Source IP      high    T1110.001             75       1

User Added To Privileged Group On Linux:
  Nov  5 14:01:00 web01 usermod[4250]: add 'dave' to group 'sudo'
  Nov  5 14:01:00 web01 usermod[4250]: add 'dave' to shadow group 'sudo'
SSH Brute Force From Single Source IP:
  203.0.113.50
```

The brute-force rule matches all 75 failed lines but alerts only on `203.0.113.50`.
`203.0.113.77` has 8 failures in total, but they are spread out, so it never
exceeds 10 failures in a 5-minute window.

`evaluate_rules.py` is not a full Sigma engine. It supports only what these rules use:
`Message|contains` and `Message|re` on the raw log line, and the
`selection | count() by <field> > N` condition with `timeframe`. No Sigma converter
(`sigma-cli`, pySigma) is used.

## 3. Tests

```bash
pytest
```

```
2 passed
```

## 4. Triage

See [`playbooks/ssh_bruteforce.md`](playbooks/ssh_bruteforce.md): triage questions,
data to collect, escalation criteria.
