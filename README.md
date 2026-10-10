
# Sentinel — Security Log Analyzer

Sentinel is a defensive cybersecurity learning project that analyzes
CSV authentication logs and identifies repeated failed logins.

## Features

- CSV log loading and validation
- Rolling-window failed-login detection
- Configurable thresholds and detection windows
- Severity-labelled security alerts
- JSON report output
- Automated unit tests
- No third-party dependencies

## Requirements

- Python 3.10 or newer

## Run the analyzer

From the project directory:

```cmd
py main.py
```

The sample dataset should produce a HIGH alert for
192.0.2.10 because five failed login attempts occur within four minutes.

## Configure detection

Five failures within five minutes:

```cmd
py main.py --threshold 5 --window 5
```

Three failures within two minutes:

```cmd
py main.py --threshold 3 --window 2
```

Analyze another CSV file:

```cmd
py main.py --file data\sample_logs.csv
```

Output JSON:

```cmd
py main.py --json
```

## Run automated tests

```cmd
py -m unittest discover -s tests -v
```

## CSV format

Required columns:

- timestamp
- source_ip
- username
- event_type

Example:

```csv
timestamp,source_ip,username,event_type
2026-10-01T10:00:00,192.0.2.10,alex,login_failed
```

Only events with event_type `login_failed` count toward the
failed-login detection rule.

## Limitations

- Sentinel analyzes files you supply; it does not monitor a network live.
- An alert is a signal for investigation, not proof of an attack.
- The sample IP addresses use documentation-only address ranges.
- This is a learning project, not a production SIEM.
- Use only logs you are authorized to access and analyze.
