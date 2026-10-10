
import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 5

REQUIRED_FIELDS = {
    "timestamp",
    "source_ip",
    "username",
    "event_type",
}


def parse_timestamp(value):
    """Parse an ISO 8601 timestamp or return None if invalid."""
    if not isinstance(value, str):
        return None

    try:
        timestamp = datetime.fromisoformat(value.strip())
    except ValueError:
        return None

    # Normalize timezone-aware timestamps to naive UTC timestamps.
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(
            datetime.now().astimezone().tzinfo
        )
        timestamp = timestamp.replace(tzinfo=None)

    return timestamp


def load_logs(file_path):
    """Load and validate security events from a CSV file."""
    path = Path(file_path)

    if not path.is_file():
        print(f"Error: Log file not found: {path}", file=sys.stderr)
        return []

    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as file:
            reader = csv.DictReader(file, skipinitialspace=True)

            if not reader.fieldnames:
                print(
                    "Error: CSV file is empty or has no header.",
                    file=sys.stderr,
                )
                return []

            reader.fieldnames = [
                name.strip() for name in reader.fieldnames
            ]

            missing_fields = REQUIRED_FIELDS - set(reader.fieldnames)

            if missing_fields:
                print(
                    "Error: Missing required columns: "
                    + ", ".join(sorted(missing_fields)),
                    file=sys.stderr,
                )
                return []

            events = []
            skipped_rows = 0

            for line_number, row in enumerate(reader, start=2):
                if None in row:
                    print(
                        f"Warning: Skipping malformed row "
                        f"{line_number}.",
                        file=sys.stderr,
                    )
                    skipped_rows += 1
                    continue

                event = {
                    key.strip(): (
                        value.strip()
                        if isinstance(value, str)
                        else ""
                    )
                    for key, value in row.items()
                    if key is not None
                }

                if any(
                    not event.get(field)
                    for field in REQUIRED_FIELDS
                ):
                    print(
                        f"Warning: Skipping incomplete row "
                        f"{line_number}.",
                        file=sys.stderr,
                    )
                    skipped_rows += 1
                    continue

                if parse_timestamp(event["timestamp"]) is None:
                    print(
                        f"Warning: Skipping row {line_number}: "
                        "invalid timestamp.",
                        file=sys.stderr,
                    )
                    skipped_rows += 1
                    continue

                events.append(event)

            print(f"Loaded {len(events)} valid events.")

            if skipped_rows:
                print(f"Skipped {skipped_rows} invalid row(s).")

            return events

    except (OSError, csv.Error) as error:
        print(f"Error reading CSV file: {error}", file=sys.stderr)
        return []


def detect_failed_logins(
    logs,
    threshold=DEFAULT_THRESHOLD,
    window_minutes=DEFAULT_WINDOW_MINUTES,
):
    """
    Detect source IPs reaching the failed-login threshold
    within a rolling time window.

    Returns at most one alert per source IP.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than 0")

    failed_by_ip = defaultdict(list)

    for event in logs:
        event_type = event.get("event_type", "").strip().lower()

        if event_type != "login_failed":
            continue

        ip_address = event.get("source_ip", "").strip()
        timestamp = parse_timestamp(event.get("timestamp", ""))

        if not ip_address or timestamp is None:
            continue

        failed_by_ip[ip_address].append(timestamp)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for ip_address, timestamps in sorted(failed_by_ip.items()):
        timestamps.sort()
        left = 0

        for right, current_time in enumerate(timestamps):
            while current_time - timestamps[left] > window:
                left += 1

            attempts = right - left + 1

            if attempts >= threshold:
                alerts.append({
                    "source_ip": ip_address,
                    "failed_attempts": attempts,
                    "threshold": threshold,
                    "window_minutes": window_minutes,
                    "first_attempt": timestamps[left].isoformat(),
                    "last_attempt": current_time.isoformat(),
                    "severity": "HIGH",
                    "reason": (
                        f"{attempts} failed login attempts within "
                        f"{window_minutes} minutes "
                        f"(threshold: {threshold})"
                    ),
                })
                break

    return alerts


def print_report(logs, alerts):
    """Print a readable security analysis report."""
    print("\nEvent summary:")

    for event in logs:
        print(
            f"{event['timestamp']} | "
            f"{event['source_ip']} | "
            f"{event['username']} | "
            f"{event['event_type']}"
        )

    print("\nSecurity alerts:")

    if not alerts:
        print("No suspicious activity detected.")
        return

    for alert in alerts:
        print(
            f"[{alert['severity']}] IP: {alert['source_ip']} | "
            f"Failed attempts: {alert['failed_attempts']} | "
            f"Window: {alert['window_minutes']} minutes | "
            f"Period: {alert['first_attempt']} to "
            f"{alert['last_attempt']} | "
            f"Reason: {alert['reason']}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Sentinel: a defensive security log analyzer."
    )

    default_file = (
        Path(__file__).parent / "data" / "sample_logs.csv"
    )

    parser.add_argument(
        "--file",
        default=str(default_file),
        help="Path to the input CSV file.",
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        help="Failed-login count that triggers an alert.",
    )

    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WINDOW_MINUTES,
        help="Rolling detection window in minutes.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the report in JSON format.",
    )

    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")

    if args.window <= 0:
        parser.error("--window must be greater than 0")

    print("Sentinel - Security Log Analyzer")

    logs = load_logs(args.file)

    if not logs:
        print("No valid events to analyze.")
        return 1

    alerts = detect_failed_logins(
        logs,
        threshold=args.threshold,
        window_minutes=args.window,
    )

    if args.json:
        report = {
            "events_analyzed": len(logs),
            "threshold": args.threshold,
            "window_minutes": args.window,
            "alerts": alerts,
        }
        print(json.dumps(report, indent=2))
    else:
        print_report(logs, alerts)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
