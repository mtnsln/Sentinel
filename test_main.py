
import unittest

from main import detect_failed_logins, parse_timestamp


def make_event(
    timestamp,
    source_ip="192.0.2.10",
    event_type="login_failed",
):
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": "test-user",
        "event_type": event_type,
    }


class TimestampTests(unittest.TestCase):
    def test_valid_timestamp(self):
        result = parse_timestamp("2026-10-01T10:00:00")
        self.assertIsNotNone(result)

    def test_invalid_timestamp(self):
        self.assertIsNone(parse_timestamp("not-a-timestamp"))


class DetectionTests(unittest.TestCase):
    def test_detects_five_failures_within_five_minutes(self):
        logs = [
            make_event("2026-10-01T10:00:00"),
            make_event("2026-10-01T10:01:00"),
            make_event("2026-10-01T10:02:00"),
            make_event("2026-10-01T10:03:00"),
            make_event("2026-10-01T10:04:00"),
        ]

        alerts = detect_failed_logins(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "192.0.2.10")
        self.assertEqual(alerts[0]["failed_attempts"], 5)

    def test_ignores_failures_spanning_eight_minutes(self):
        logs = [
            make_event("2026-10-01T10:00:00"),
            make_event("2026-10-01T10:02:00"),
            make_event("2026-10-01T10:04:00"),
            make_event("2026-10-01T10:06:00"),
            make_event("2026-10-01T10:08:00"),
        ]

        self.assertEqual(detect_failed_logins(logs), [])

    def test_successful_logins_do_not_trigger_alerts(self):
        logs = [
            make_event(
                f"2026-10-01T10:0{i}:00",
                event_type="login_success",
            )
            for i in range(5)
        ]

        self.assertEqual(detect_failed_logins(logs), [])

    def test_tracks_different_ips_separately(self):
        logs = []

        for minute in range(5):
            logs.append(
                make_event(
                    f"2026-10-01T10:0{minute}:00",
                    "192.0.2.10",
                )
            )
            logs.append(
                make_event(
                    f"2026-10-01T10:0{minute}:00",
                    "192.0.2.20",
                )
            )

        alerts = detect_failed_logins(logs)

        self.assertEqual(
            {alert["source_ip"] for alert in alerts},
            {"192.0.2.10", "192.0.2.20"},
        )

    def test_rejects_invalid_settings(self):
        with self.assertRaises(ValueError):
            detect_failed_logins([], threshold=0)

        with self.assertRaises(ValueError):
            detect_failed_logins([], window_minutes=0)


if __name__ == "__main__":
    unittest.main()
