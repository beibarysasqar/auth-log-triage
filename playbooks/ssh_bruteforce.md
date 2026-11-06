# Playbook: SSH Brute Force

**Triggered by:** `rules/ssh_bruteforce.yml` (more than 10 failed SSH passwords from one IP in 5 minutes)
**ATT&CK:** T1110.001 Brute Force: Password Guessing

## 1. Triage questions

1. **Did any login from the source IP succeed?** This is the most important question.
   A success after many failures means a possible compromise.
2. **Which accounts were targeted?** `root` and generic names (`admin`, `test`, `oracle`)
   point to an automated scan. Real employee usernames point to a targeted attack.
3. **Do the targeted accounts exist?** `Failed password for invalid user ...` means the account
   does not exist on the host.
4. **Is the source IP known?** Internal range, VPN, a scanner run by the security team,
   or an external address?
5. **Is it one host or many?** The same IP hitting several servers means a wider campaign.
6. **Is the activity still ongoing?**

## 2. Data to collect

| Data | Where / how |
|------|-------------|
| All auth events for the source IP | `grep '<ip>' /var/log/auth.log` or the `linux-auth` index, filter `src_ip` |
| Successful logins from the IP | `grep 'Accepted .* from <ip>' /var/log/auth.log` |
| List of targeted usernames | `user` field of `failed_password` events |
| First and last time seen, number of attempts | output of `src/load_linux_auth.py`, timestamps in the index |
| Activity after a successful login | `sudo` lines, new users (`useradd`/`usermod`), shell history, `last`, `who` |
| sshd configuration | `PasswordAuthentication`, `PermitRootLogin` in `/etc/ssh/sshd_config` |
| IP reputation and owner | internal asset inventory, threat intel, WHOIS |

## 3. Escalation criteria

**Escalate to incident response immediately if any of these is true:**

- A successful login (`Accepted ...`) from the same IP after the failures.
- After a login: privilege escalation, new accounts, or a privileged group change
  (see `rules/linux_privileged_group_change.yml`).
- Real, existing employee accounts were targeted, or an account got locked.
- The same source hits several hosts.

**Close as a benign / low-priority event if all of these are true:**

- No successful logins from the IP.
- Only non-existent or generic accounts were tried.
- Password authentication is disabled, or root login is not permitted.

Then block the IP (firewall / fail2ban) and record the case.

## 4. Containment (if escalated)

1. Block the source IP at the firewall.
2. Disable or reset the password of any account that logged in from it.
3. Kill active sessions of that account (`pkill -u <user>` after evidence is saved).
4. Keep a copy of `/var/log/auth.log` before any changes on the host.
