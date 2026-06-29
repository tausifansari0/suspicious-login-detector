"""
Suspicious Login Activity Detector
-----------------------------------
A SIEM-style correlation engine that ingests login event logs and flags
suspicious authentication patterns using rule-based correlation and a
lightweight statistical anomaly model.

Detection modules:
    1. Brute Force Detection      -> sliding time-window threshold per source IP
    2. Impossible Travel Detection -> geo-velocity check between consecutive logins
    3. Off-Hours Anomaly Detection -> per-user baseline (mean/std) of login hour,
                                       flags logins outside the learned normal range
                                       (z-score based, not just a fixed clock range)

Author: Mo Tausif
"""

from __future__ import annotations
import csv
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Iterable

from config import Config, mitre_for


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class LoginEvent:
    timestamp: datetime
    username: str
    ip: str
    status: str          # "SUCCESS" or "FAIL"
    latitude: float
    longitude: float
    city: str = ""
    device: str = ""     # user-agent / device fingerprint

    @staticmethod
    def from_row(row: dict) -> "LoginEvent":
        return LoginEvent(
            timestamp=datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S"),
            username=row["username"].strip(),
            ip=row["ip"].strip(),
            status=row["status"].strip().upper(),
            latitude=float(row["latitude"]),
            longitude=float(row["longitude"]),
            city=row.get("city", "").strip(),
            device=row.get("device", "").strip(),
        )


@dataclass
class Alert:
    rule: str
    severity: str
    username: str
    detail: str
    timestamp: datetime
    mitre_technique_id: str = ""
    mitre_technique_name: str = ""
    mitre_tactic: str = ""

    def __post_init__(self):
        m = mitre_for(self.rule)
        self.mitre_technique_id = m["technique_id"]
        self.mitre_technique_name = m["technique_name"]
        self.mitre_tactic = m["tactic"]

    def __str__(self) -> str:
        return (f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] "
                f"({self.severity}) {self.rule} -> user={self.username} :: {self.detail} "
                f"[MITRE {self.mitre_technique_id} – {self.mitre_technique_name}]")

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "rule": self.rule,
            "severity": self.severity,
            "username": self.username,
            "detail": self.detail,
            "mitre": {
                "technique_id": self.mitre_technique_id,
                "technique_name": self.mitre_technique_name,
                "tactic": self.mitre_tactic,
            },
        }


# ---------------------------------------------------------------------------
# Log ingestion
# ---------------------------------------------------------------------------

def load_events(csv_path: str) -> list[LoginEvent]:
    """Load and time-sort login events from a CSV log file."""
    events: list[LoginEvent] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            events.append(LoginEvent.from_row(row))
    events.sort(key=lambda e: e.timestamp)
    return events


# ---------------------------------------------------------------------------
# Module 1: Brute Force Detection (sliding window over a deque)
# ---------------------------------------------------------------------------

class BruteForceDetector:
    """
    Flags an IP once it accumulates >= `threshold` failed login attempts
    inside a rolling `window` of time. Uses a deque per IP so the check
    is O(1) amortized per event instead of re-scanning the whole log
    (important once you're processing large log volumes, e.g. CBS-scale
    traffic, not just a toy file).
    """

    def __init__(self, threshold: int = 5, window: timedelta = timedelta(minutes=10)):
        self.threshold = threshold
        self.window = window
        self._fail_history: dict[str, deque[datetime]] = defaultdict(deque)
        self._already_flagged: set[str] = set()

    def process(self, event: LoginEvent) -> Alert | None:
        if event.status != "FAIL":
            return None

        history = self._fail_history[event.ip]
        history.append(event.timestamp)

        # Evict timestamps that have fallen outside the rolling window
        while history and (event.timestamp - history[0]) > self.window:
            history.popleft()

        if len(history) >= self.threshold:
            key = f"{event.ip}:{event.timestamp:%Y%m%d%H}"  # de-dupe per IP per hour
            if key not in self._already_flagged:
                self._already_flagged.add(key)
                return Alert(
                    rule="BRUTE_FORCE",
                    severity="HIGH",
                    username=event.username,
                    detail=(f"{len(history)} failed attempts from {event.ip} "
                            f"within {self.window.seconds // 60} min window"),
                    timestamp=event.timestamp,
                )
        return None


# ---------------------------------------------------------------------------
# Module 2: Impossible Travel Detection (geo-velocity check)
# ---------------------------------------------------------------------------

EARTH_RADIUS_KM = 6371.0
MAX_PLAUSIBLE_SPEED_KMH = 900  # ~commercial flight speed; anything faster is "impossible"


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two lat/lon points, in kilometers."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = (math.sin(d_phi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return EARTH_RADIUS_KM * c


class ImpossibleTravelDetector:
    """
    Tracks each user's last successful login location/time. If the next
    successful login implies a travel speed faster than is physically
    plausible, flag it. This catches credential sharing / account
    takeover that simple IP-allowlisting misses.
    """

    def __init__(self, max_speed_kmh: float = MAX_PLAUSIBLE_SPEED_KMH):
        self.max_speed_kmh = max_speed_kmh
        self._last_login: dict[str, LoginEvent] = {}

    def process(self, event: LoginEvent) -> Alert | None:
        if event.status != "SUCCESS":
            return None

        prev = self._last_login.get(event.username)
        self._last_login[event.username] = event

        if prev is None or prev.ip == event.ip:
            return None

        distance_km = haversine_km(prev.latitude, prev.longitude,
                                    event.latitude, event.longitude)
        elapsed_h = max((event.timestamp - prev.timestamp).total_seconds() / 3600, 1e-6)
        implied_speed = distance_km / elapsed_h

        if implied_speed > self.max_speed_kmh and distance_km > 50:
            return Alert(
                rule="IMPOSSIBLE_TRAVEL",
                severity="CRITICAL",
                username=event.username,
                detail=(f"{prev.city or prev.ip} -> {event.city or event.ip}, "
                        f"{distance_km:.0f} km in {elapsed_h:.2f}h "
                        f"(implied speed {implied_speed:.0f} km/h)"),
                timestamp=event.timestamp,
            )
        return None


# ---------------------------------------------------------------------------
# Module 3: Off-Hours / Behavioral Anomaly Detection (z-score baseline)
# ---------------------------------------------------------------------------

class LoginTimeAnomalyDetector:
    """
    Learns a per-user baseline of "normal" login hour using running mean/
    variance (Welford's online algorithm, so it doesn't need to store full
    history or re-scan data). Once a baseline exists, a new login is
    flagged if it deviates from the user's typical hour by more than
    `z_threshold` standard deviations -- a simple, explainable analogue of
    the "AI/ML-based anomaly detection" use case mentioned in security
    product JDs, without needing an external ML library.
    """

    def __init__(self, z_threshold: float = 2.5, min_history: int = 5):
        self.z_threshold = z_threshold
        self.min_history = min_history
        # Welford's online mean/variance accumulators, per user
        self._n: dict[str, int] = defaultdict(int)
        self._mean: dict[str, float] = defaultdict(float)
        self._m2: dict[str, float] = defaultdict(float)  # sum of squared diffs

    @staticmethod
    def _hour_as_float(ts: datetime) -> float:
        return ts.hour + ts.minute / 60.0

    def process(self, event: LoginEvent) -> Alert | None:
        if event.status != "SUCCESS":
            return None

        user = event.username
        hour = self._hour_as_float(event.timestamp)

        n = self._n[user]
        alert = None

        if n >= self.min_history:
            mean = self._mean[user]
            variance = self._m2[user] / n
            std = math.sqrt(variance) if variance > 0 else 1e-6
            # circular distance so 23:50 vs 00:10 isn't treated as a huge gap
            diff = min(abs(hour - mean), 24 - abs(hour - mean))
            z = diff / std

            if z > self.z_threshold:
                alert = Alert(
                    rule="LOGIN_TIME_ANOMALY",
                    severity="MEDIUM",
                    username=user,
                    detail=(f"Login at {event.timestamp:%H:%M} deviates {z:.1f}σ "
                            f"from user baseline (avg ~{mean:.1f}h, n={n})"),
                    timestamp=event.timestamp,
                )

        # Update Welford accumulators regardless, so the baseline keeps learning
        n_new = n + 1
        delta = hour - self._mean[user]
        self._mean[user] += delta / n_new
        delta2 = hour - self._mean[user]
        self._m2[user] += delta * delta2
        self._n[user] = n_new

        return alert


# ---------------------------------------------------------------------------
# Module 4: New / Unrecognized Device Detection
# ---------------------------------------------------------------------------

class NewDeviceDetector:
    """
    Flags a successful login from a (user, device-fingerprint) pair never
    seen before for that user. 'Device' here is a stand-in for what a real
    system would derive from User-Agent + TLS fingerprint + screen/platform
    signals. The first-ever login for a user is treated as enrollment, not
    an alert -- only *subsequent* new devices are flagged.
    """

    def __init__(self):
        self._known_devices: dict[str, set[str]] = defaultdict(set)

    def process(self, event: LoginEvent) -> Alert | None:
        if event.status != "SUCCESS" or not event.device:
            return None

        known = self._known_devices[event.username]
        is_first_login_ever = len(known) == 0
        is_new = event.device not in known
        known.add(event.device)

        if is_new and not is_first_login_ever:
            return Alert(
                rule="NEW_DEVICE",
                severity="MEDIUM",
                username=event.username,
                detail=f"Login from previously unseen device '{event.device}' on {event.ip}",
                timestamp=event.timestamp,
            )
        return None


# ---------------------------------------------------------------------------
# Module 5: Success-After-Failures Detection
# ---------------------------------------------------------------------------

class SuccessAfterFailuresDetector:
    """
    Flags a successful login that immediately follows a burst of failed
    attempts for the same user -- the classic "attacker finally guessed it"
    signature, distinct from brute force (which fires on the failures
    themselves, regardless of whether one eventually succeeds).
    """

    def __init__(self, min_failures: int = 3, window: timedelta = timedelta(minutes=15)):
        self.min_failures = min_failures
        self.window = window
        self._recent_failures: dict[str, deque[datetime]] = defaultdict(deque)

    def process(self, event: LoginEvent) -> Alert | None:
        history = self._recent_failures[event.username]

        if event.status == "FAIL":
            history.append(event.timestamp)
            while history and (event.timestamp - history[0]) > self.window:
                history.popleft()
            return None

        # SUCCESS: check if it was preceded by a qualifying failure streak
        while history and (event.timestamp - history[0]) > self.window:
            history.popleft()

        if len(history) >= self.min_failures:
            count = len(history)
            history.clear()  # reset streak once it resolves in a success
            return Alert(
                rule="SUCCESS_AFTER_FAILURES",
                severity="HIGH",
                username=event.username,
                detail=(f"Successful login immediately followed {count} failed "
                        f"attempts within {self.window.seconds // 60} min"),
                timestamp=event.timestamp,
            )
        return None


# ---------------------------------------------------------------------------
# Module 6: Credential Stuffing Detection (distributed, low-and-slow)
# ---------------------------------------------------------------------------

class CredentialStuffingDetector:
    """
    Unlike brute force (one IP hammering one user many times), credential
    stuffing looks like a small set of IPs each trying *many different*
    usernames a *few* times each -- consistent with an attacker replaying
    a breached username/password list. Tracked per-IP with a rolling
    window of (user, timestamp) pairs.
    """

    def __init__(self, min_distinct_users: int = 4, window: timedelta = timedelta(minutes=15),
                 max_attempts_per_user: int = 2):
        self.min_distinct_users = min_distinct_users
        self.window = window
        self.max_attempts_per_user = max_attempts_per_user
        self._attempts: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
        self._flagged_ips: set[str] = set()

    def process(self, event: LoginEvent) -> Alert | None:
        if event.status not in ("FAIL", "SUCCESS"):
            return None

        history = self._attempts[event.ip]
        history.append((event.timestamp, event.username))
        while history and (event.timestamp - history[0][0]) > self.window:
            history.popleft()

        users_seen: dict[str, int] = defaultdict(int)
        for _, user in history:
            users_seen[user] += 1

        distinct_users = len(users_seen)
        looks_distributed = all(c <= self.max_attempts_per_user for c in users_seen.values())

        if (distinct_users >= self.min_distinct_users and looks_distributed
                and event.ip not in self._flagged_ips):
            self._flagged_ips.add(event.ip)
            return Alert(
                rule="CREDENTIAL_STUFFING",
                severity="HIGH",
                username=event.username,
                detail=(f"IP {event.ip} attempted {distinct_users} distinct usernames "
                        f"(\u2264{self.max_attempts_per_user} tries each) within "
                        f"{self.window.seconds // 60} min -- consistent with credential stuffing"),
                timestamp=event.timestamp,
            )
        return None


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

class RiskScorer:
    """
    Aggregates alerts into a per-user threat score. Each rule contributes
    a configurable weight; scores are additive but capped at 100, which
    mirrors how vendor risk-scoring engines (e.g. Splunk Risk-Based
    Alerting, Microsoft Sentinel's UEBA score) combine multiple weak
    signals into one prioritization number for SOC triage.
    """

    def __init__(self, weights: dict[str, int], thresholds: dict[str, int]):
        self.weights = weights
        self.thresholds = thresholds
        self._scores: dict[str, int] = defaultdict(int)
        self._contributing_rules: dict[str, list[str]] = defaultdict(list)

    def ingest(self, alert: Alert) -> None:
        weight = self.weights.get(alert.rule, 10)
        self._scores[alert.username] = min(100, self._scores[alert.username] + weight)
        self._contributing_rules[alert.username].append(alert.rule)

    def tier_for(self, score: int) -> str:
        if score >= self.thresholds["high"]:
            return "CRITICAL"
        if score >= self.thresholds["medium"]:
            return "HIGH"
        if score >= self.thresholds["low"]:
            return "MEDIUM"
        return "LOW"

    def report(self) -> list[dict]:
        rows = []
        for user, score in sorted(self._scores.items(), key=lambda kv: -kv[1]):
            rows.append({
                "username": user,
                "threat_score": score,
                "risk_tier": self.tier_for(score),
                "contributing_rules": self._contributing_rules[user],
            })
        return rows


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """Runs all detection modules over an event stream, like a mini SIEM pipeline."""

    def __init__(self, cfg: Config):
        bf = cfg["brute_force"]
        it = cfg["impossible_travel"]
        lta = cfg["login_time_anomaly"]
        saf = cfg["success_after_failures"]
        cs = cfg["credential_stuffing"]
        rs = cfg["risk_scoring"]

        self.brute_force = BruteForceDetector(
            threshold=bf["threshold"], window=timedelta(minutes=bf["window_minutes"]))
        self.impossible_travel = ImpossibleTravelDetector(
            max_speed_kmh=it["max_speed_kmh"])
        self.anomaly = LoginTimeAnomalyDetector(
            z_threshold=lta["z_threshold"], min_history=lta["min_history"])
        self.new_device = NewDeviceDetector()
        self.success_after_failures = SuccessAfterFailuresDetector(
            min_failures=saf["min_failures"], window=timedelta(minutes=saf["window_minutes"]))
        self.credential_stuffing = CredentialStuffingDetector(
            min_distinct_users=cs["min_distinct_users"],
            window=timedelta(minutes=cs["window_minutes"]),
            max_attempts_per_user=cs["max_attempts_per_user"])

        self.risk_scorer = RiskScorer(weights=rs["weights"], thresholds=rs["thresholds"])
        self.alerts: list[Alert] = []
        self._event_count = 0

    def run(self, events: Iterable[LoginEvent]) -> list[Alert]:
        detectors = (
            self.brute_force, self.impossible_travel, self.anomaly,
            self.new_device, self.success_after_failures, self.credential_stuffing,
        )
        for event in events:
            self._event_count += 1
            for detector in detectors:
                alert = detector.process(event)
                if alert:
                    self.alerts.append(alert)
                    self.risk_scorer.ingest(alert)
        return self.alerts

    def statistics(self) -> dict:
        by_rule: dict[str, int] = defaultdict(int)
        by_severity: dict[str, int] = defaultdict(int)
        for a in self.alerts:
            by_rule[a.rule] += 1
            by_severity[a.severity] += 1
        return {
            "total_events_processed": self._event_count,
            "total_alerts": len(self.alerts),
            "alerts_by_rule": dict(by_rule),
            "alerts_by_severity": dict(by_severity),
            "unique_users_flagged": len({a.username for a in self.alerts}),
        }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(log_path: str = "sample_logs.csv", config_path: str = "config.yaml") -> None:
    cfg = Config.load(config_path)
    out = cfg["output"]

    events = load_events(log_path)
    engine = CorrelationEngine(cfg)
    alerts = engine.run(events)

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    alerts.sort(key=lambda a: (severity_rank.get(a.severity, 9), a.timestamp))

    stats = engine.statistics()
    risk_report = engine.risk_scorer.report()

    print(f"Processed {stats['total_events_processed']} login events.")
    print(f"Generated {stats['total_alerts']} alerts across "
          f"{stats['unique_users_flagged']} users.\n")
    for alert in alerts:
        print(alert)

    print("\n--- Detection Statistics ---")
    print(f"By rule:     {stats['alerts_by_rule']}")
    print(f"By severity: {stats['alerts_by_severity']}")

    print("\n--- Per-User Threat Scores ---")
    for row in risk_report:
        print(f"  {row['username']:<12} score={row['threat_score']:>3}  "
              f"tier={row['risk_tier']:<8}  rules={row['contributing_rules']}")

    # CSV export
    with open(out["csv_path"], "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "rule", "severity", "username", "detail",
                          "mitre_technique_id", "mitre_technique_name", "mitre_tactic"])
        for a in alerts:
            writer.writerow([a.timestamp.isoformat(), a.rule, a.severity, a.username,
                              a.detail, a.mitre_technique_id, a.mitre_technique_name,
                              a.mitre_tactic])

    # JSON export (alerts + stats + risk report, for the dashboard to consume)
    json_payload = {
        "generated_at": datetime.now().isoformat(),
        "statistics": stats,
        "risk_scores": risk_report,
        "alerts": [a.to_dict() for a in alerts],
    }
    with open(out["json_path"], "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)

    print(f"\nCSV report  -> {out['csv_path']}")
    print(f"JSON report -> {out['json_path']}")


if __name__ == "__main__":
    main()
