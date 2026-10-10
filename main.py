import csv
from pathlib import Path


def load_logs(file_path):
    """Load security events from a CSV file."""
    path = Path(file_path)

    if not path.exists():
        print(f"Error: File not found: {path}")
        return []

    try:
        with path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            logs = list(reader)

        print(f"Loaded {len(logs)} events.")
        return logs

    except (OSError, csv.Error) as error:
        print(f"Error reading file: {error}")
        return []


def main():
    print("Sentinel - Security Log Analyzer")
    print("The project has been initialized.")


if __name__ == "__main__":
    main()
