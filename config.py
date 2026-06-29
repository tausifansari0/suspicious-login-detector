"""
config.py
---------
Loads detector thresholds from config.yaml, and maps each detection rule
to its corresponding MITRE ATT&CK technique so alerts carry industry-
standard context (the same way commercial SIEM rule packs annotate
detections with technique IDs).
"""

from __future__ import annotations
import yaml
from dataclasses import dataclass


@dataclass
class Config:
    raw: dict

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        with open(path, "r", encoding="utf-8") as f:
            return cls(raw=yaml.safe_load(f))

    def __getitem__(self, key):
        return self.raw[key]


# ---------------------------------------------------------------------------
# MITRE ATT&CK mapping
# ---------------------------------------------------------------------------
# Each rule maps to the technique(s) it's evidence of. Referenced by ID so
# analysts can pivot straight to attack.mitre.org for the full technique.

MITRE_MAP: dict[str, dict] = {
    "BRUTE_FORCE": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
    },
    "CREDENTIAL_STUFFING": {
        "technique_id": "T1110.004",
        "technique_name": "Brute Force: Credential Stuffing",
        "tactic": "Credential Access",
    },
    "IMPOSSIBLE_TRAVEL": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
    },
    "NEW_DEVICE": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts (Unfamiliar Device)",
        "tactic": "Initial Access / Defense Evasion",
    },
    "SUCCESS_AFTER_FAILURES": {
        "technique_id": "T1110",
        "technique_name": "Brute Force (Successful)",
        "tactic": "Credential Access",
    },
    "LOGIN_TIME_ANOMALY": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts (Anomalous Usage Pattern)",
        "tactic": "Defense Evasion",
    },
}


def mitre_for(rule: str) -> dict:
    return MITRE_MAP.get(rule, {
        "technique_id": "N/A", "technique_name": "Unmapped", "tactic": "N/A"
    })
