# SPL Searches — Lab 3: Splunk SIEM & Log Analysis

All searches run in the **Search & Reporting** app in Splunk.
Index: `windows_logs` | Source: `WinEventLog:Security`

---

## 1. Confirm Data Is Flowing

```spl
index=windows_logs | head 100
```

- `index=windows_logs` — search only in the windows_logs index
- `| head 100` — return only the first 100 events

**Expected result:** Recent Windows events from DC01.
If empty, check that `SplunkForwarder` service is Running on DC01.

---

## 2. Failed Login Attempts — EventCode 4625

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Workstation_Name
| sort -count
```

- `EventCode=4625` — filter to failed logon events only
- `| stats count by ...` — count events grouped by username and source machine
- `| sort -count` — sort highest count first (minus = descending)

**Investigation threshold:** 5+ failures for one account in a short window = possible brute force.

---

## 3. Successful Logins — EventCode 4624

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name, Logon_Type
| sort -count
```

**Logon_Type values:**

| Type | Meaning | SOC Note |
|---|---|---|
| 2 | Interactive (keyboard) | Normal for admin work at console |
| 3 | Network (file share / resource) | Normal for domain activity |
| 5 | Service account | Automated — usually expected |
| 10 | Remote Interactive (RDP) | Review unexpected RDP sessions |

---

## 4. Account Lockout Events — EventCode 4740

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4740
| table _time, Account_Name, Caller_Computer_Name
| sort -_time
```

- `| table _time, ...` — display as a table with timestamp, username, and source machine
- `Caller_Computer_Name` — the machine where failed attempts originated

**Investigation signal:** Multiple lockouts for the same account = likely brute force or password spray.

---

## 5. Top 10 Failed Login Usernames — Threat Hunting

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h
| stats count as failures by Account_Name
| sort -failures
| head 10
```

- `earliest=-24h` — only the last 24 hours
- `count as failures` — rename count column to 'failures' for readability
- `| head 10` — top 10 results only

**Investigation signals:**
- 20+ failures = investigate
- Usernames that don't exist in AD = account enumeration attack

---

## 6. Detect After-Hours Logins

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, Account_Name, Workstation_Name, Logon_Type
| sort -_time
```

- `eval hour=strftime(_time, "%H")` — extract the hour (0–23) from each event timestamp
- `where hour < 7 OR hour > 19` — keep only events outside 7am–7pm

**Investigation signals:**
- Service account logins (Type 5) after hours = normal, expected
- Interactive logins (Type 2 or 10) from regular users after hours = review

---

## 7. Brute Force Alert Search

```spl
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count as failures by Account_Name
| where failures > 10
```

Finds any account with more than 10 failed logins in the search time window.
Save this as a **Scheduled Alert** running every 15 minutes.

**Alert name:** Potential Brute Force — High Failure Count
**Trigger:** Number of Results > 0

---

## Dashboard Panels Reference

| Panel | Search Basis | Visualization |
|---|---|---|
| Failed Logins — Last 24h | EventCode=4625 · stats count by Account_Name | Bar chart |
| Account Lockouts — Last 7d | EventCode=4740 · table output | Events list |
| Login Activity Over Time | EventCode=4624 · timechart count | Line chart |
| Top Source IPs — After Hours | After-hours search · stats count by Workstation_Name | Column chart |

---

## SPL Cheat Sheet

| Command | Purpose |
|---|---|
| `index=name` | Search a specific index |
| `sourcetype=WinEventLog:Security` | Filter to Security Event Log only |
| `EventCode=XXXX` | Filter to specific Windows Event ID |
| `\| stats count by field` | Count events grouped by field |
| `\| sort -field` | Sort descending by field |
| `\| head N` | Return first N results |
| `\| table field1, field2` | Display as table with named columns |
| `\| timechart count` | Count events over time (for line/area charts) |
| `\| eval name=function` | Create a new calculated field |
| `\| where condition` | Filter results based on a condition |
| `earliest=-24h` | Limit search to last 24 hours |
