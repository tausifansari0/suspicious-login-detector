# Suspicious Login Activity Detector

A SIEM-style correlation engine, written in Python, that ingests authentication
logs and flags suspicious login behavior using rule-based correlation, geo-velocity
checks, and a lightweight statistical anomaly model — the same category of logic
that underlies detection content in commercial SIEM/EDR/UEBA platforms.

Built to demonstrate practical detection-engineering skills: threshold tuning,
sliding-window algorithms, online statistics, and risk-based alert prioritization,
not just basic log filtering.

## Detection Modules

| Module | Technique | MITRE ATT&CK |
|---|---|---|
| **Brute Force** | Sliding time-window over failed attempts per source IP (deque-based, O(1) amortized) | T1110.001 |
| **Impossible Travel** | Haversine great-circle distance vs. elapsed time → implied travel speed | T1078 |
| **Login-Time Anomaly** | Per-user baseline via Welford's online mean/variance, z-score deviation flagging | T1078 |
| **New Device Detection** | Tracks known (user, device-fingerprint) pairs; flags first use of an unrecognized device | T1078 |
| **Success-After-Failures** | Flags a successful login immediately preceded by a qualifying failure streak | T1110 |
| **Credential Stuffing** | Detects distributed low-and-slow attempts: one IP, many distinct usernames, few tries each | T1110.004 |

## Risk Scoring

Each alert contributes a configurable weight to a per-user **threat score** (capped
at 100), which is then bucketed into LOW / MEDIUM / HIGH / CRITICAL risk tiers —
mirroring how Splunk Risk-Based Alerting and Microsoft Sentinel's UEBA scoring
combine multiple weak signals into one SOC triage priority number.

## Project Structure

```
.
├── config.py                 # Config loader + MITRE ATT&CK technique mapping
├── config.yaml                # All thresholds (tunable without touching code)
├── detector.py                 # Core engine: detectors, risk scorer, reporting
├── generate_sample_logs.py     # Synthetic log generator with embedded ground-truth anomalies
├── dashboard.html              # Standalone SOC-style dashboard (reads alerts_report.json)
└── README.md
```

## Running It

```bash
pip install pyyaml

# 1. Generate a synthetic log file with known, embedded anomalies
python generate_sample_logs.py

# 2. Run the correlation engine
python detector.py
```

This produces:
- `alerts_report.csv` — flat alert log
- `alerts_report.json` — full report (alerts + per-user risk scores + statistics)

Then open `dashboard.html` directly in a browser (same folder as the JSON report)
to view the alert feed, per-user threat scores, and rule-distribution breakdown.

## Configuration

All thresholds live in `config.yaml` — brute-force window/count, impossible-travel
max speed, anomaly z-score sensitivity, credential-stuffing parameters, and the
risk-score weight per rule. Tune these without touching detection logic, the same
way a real correlation-rule pack exposes tunables per deployment.

## Why These Design Choices

- **Sliding windows via `deque`** instead of re-scanning the full log on every
  event — keeps brute-force/stuffing checks closer to O(1) amortized rather than
  O(n²), which matters once you're past toy-sized logs.
- **Welford's algorithm** for the anomaly baseline avoids storing a user's entire
  login history just to compute a running mean/variance.
- **MITRE ATT&CK tagging on every alert** so output is immediately usable in a
  SOC workflow, not just a bare list of rule names.
- **Config-driven thresholds** so detection sensitivity can be tuned per
  environment without code changes — the same separation real SIEM rule packs
  maintain between logic and tunables.

## Possible Extensions

- Swap the synthetic CSV source for a live log stream (Kafka/syslog) for real-time alerting
- Add a SOAR-style auto-response layer (e.g., auto-disable account after CRITICAL score)
- Replace the z-score anomaly model with an actual ML model (Isolation Forest /
  One-Class SVM) trained on a larger behavioral dataset
