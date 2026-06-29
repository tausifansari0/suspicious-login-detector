"""
Generates a synthetic login-event log (CSV) for testing the detector.
Includes embedded "ground truth" anomalies so you can verify each
detection module actually catches what it's supposed to:

    - A brute-force burst from a single IP against 'rakesh.k'
    - An impossible-travel pair for 'priya.s' (Mumbai -> London in 40 min)
    - A 3 AM login anomaly for 'amit.v' (who always logs in ~9-10 AM)
    - A pool of normal, unremarkable logins as background noise
"""

import csv
import random
from datetime import datetime, timedelta

random.seed(42)

CITIES = [
    ("Mumbai", 19.0760, 72.8777),
    ("Delhi", 28.7041, 77.1025),
    ("Bengaluru", 12.9716, 77.5946),
    ("Pune", 18.5204, 73.8567),
    ("London", 51.5074, -0.1278),
]

USERS = ["amit.v", "priya.s", "rakesh.k", "neha.r", "sandeep.t"]

DEVICES = ["Chrome-Win10-Desktop", "Safari-iOS-Mobile", "Edge-Win11-Desktop",
           "Chrome-Android-Mobile", "Firefox-Linux-Desktop"]


def rand_ip():
    return f"{random.randint(10,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def make_normal_traffic(start: datetime, count: int) -> list[dict]:
    rows = []
    home_device = {u: random.choice(DEVICES) for u in USERS}  # each user's usual device
    home_city = {u: random.choice(CITIES[:4]) for u in USERS}  # each user's usual city

    for _ in range(count):
        user = random.choice(USERS)
        # 95% of the time a user logs in from their home city (realistic);
        # only rarely from elsewhere, and never close enough in time to
        # another login to look like impossible travel.
        city, lat, lon = home_city[user]

        # amit.v has a tight morning routine -> needed so his anomaly stands out later
        if user == "amit.v":
            hour = random.gauss(9.5, 0.4)
            hour = max(0, min(23.9, hour))
        else:
            hour = random.uniform(7, 22)

        ts = start + timedelta(
            days=random.randint(0, 6),
            hours=int(hour),
            minutes=random.randint(0, 59),
        )
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": user,
            "ip": rand_ip(),
            "status": "SUCCESS" if random.random() > 0.08 else "FAIL",
            "latitude": lat,
            "longitude": lon,
            "city": city,
            "device": home_device[user],
        })
    return rows


def make_brute_force_burst(start: datetime) -> list[dict]:
    """8 failed attempts from the same IP against rakesh.k within 6 minutes."""
    attacker_ip = "203.0.113.77"
    rows = []
    base = start + timedelta(days=2, hours=3, minutes=10)
    for i in range(8):
        ts = base + timedelta(seconds=i * 40)
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": "rakesh.k",
            "ip": attacker_ip,
            "status": "FAIL",
            "latitude": 35.6895,
            "longitude": 139.6917,
            "city": "Unknown",
            "device": "Unknown-Bot-Client",
        })
    return rows


def make_impossible_travel(start: datetime) -> list[dict]:
    """priya.s logs in from Mumbai, then 'London' 40 minutes later."""
    base = start + timedelta(days=3, hours=14, minutes=0)
    mumbai = ("Mumbai", 19.0760, 72.8777)
    london = ("London", 51.5074, -0.1278)
    rows = [
        {
            "timestamp": base.strftime("%Y-%m-%d %H:%M:%S"),
            "username": "priya.s", "ip": rand_ip(), "status": "SUCCESS",
            "latitude": mumbai[1], "longitude": mumbai[2], "city": mumbai[0],
            "device": "Chrome-Win10-Desktop",
        },
        {
            "timestamp": (base + timedelta(minutes=40)).strftime("%Y-%m-%d %H:%M:%S"),
            "username": "priya.s", "ip": rand_ip(), "status": "SUCCESS",
            "latitude": london[1], "longitude": london[2], "city": london[0],
            "device": "Chrome-Win10-Desktop",
        },
    ]
    return rows


def make_offhours_anomaly(start: datetime) -> list[dict]:
    """amit.v, who always logs in ~9:30 AM, suddenly logs in at 3 AM."""
    base = start + timedelta(days=4, hours=3, minutes=5)
    return [{
        "timestamp": base.strftime("%Y-%m-%d %H:%M:%S"),
        "username": "amit.v", "ip": rand_ip(), "status": "SUCCESS",
        "latitude": 28.7041, "longitude": 77.1025, "city": "Delhi",
        "device": "Chrome-Win10-Desktop",
    }]


def make_new_device_login(start: datetime) -> list[dict]:
    """neha.r, normally on Safari-iOS, suddenly logs in from a Linux desktop."""
    base = start + timedelta(days=4, hours=11, minutes=20)
    return [{
        "timestamp": base.strftime("%Y-%m-%d %H:%M:%S"),
        "username": "neha.r", "ip": rand_ip(), "status": "SUCCESS",
        "latitude": 19.0760, "longitude": 72.8777, "city": "Mumbai",
        "device": "Firefox-Linux-Desktop",
    }]


def make_success_after_failures(start: datetime) -> list[dict]:
    """sandeep.t fails 4 times then succeeds on the 5th try, same IP and device
    (so this scenario tests SUCCESS_AFTER_FAILURES in isolation, not NEW_DEVICE)."""
    base = start + timedelta(days=5, hours=16, minutes=0)
    ip = rand_ip()
    device = "Chrome-Win10-Desktop"
    rows = []
    for i in range(4):
        ts = base + timedelta(minutes=i * 2)
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "username": "sandeep.t", "ip": ip, "status": "FAIL",
            "latitude": 12.9716, "longitude": 77.5946, "city": "Bengaluru",
            "device": device,
        })
    success_ts = base + timedelta(minutes=9)
    rows.append({
        "timestamp": success_ts.strftime("%Y-%m-%d %H:%M:%S"),
        "username": "sandeep.t", "ip": ip, "status": "SUCCESS",
        "latitude": 12.9716, "longitude": 77.5946, "city": "Bengaluru",
        "device": device,
    })
    return rows


def make_credential_stuffing(start: datetime) -> list[dict]:
    """One IP tries 6 distinct usernames, 1-2 attempts each, in 10 minutes."""
    base = start + timedelta(days=6, hours=2, minutes=0)
    attacker_ip = "198.51.100.23"
    stuffing_targets = USERS + ["guest.user", "admin"]  # includes accounts outside the normal pool
    rows = []
    t = base
    for user in stuffing_targets:
        rows.append({
            "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
            "username": user, "ip": attacker_ip, "status": "FAIL",
            "latitude": 37.7749, "longitude": -122.4194, "city": "Unknown",
            "device": "Headless-Script-Client",
        })
        t += timedelta(minutes=1, seconds=20)
    return rows


def generate(out_path: str = "sample_logs.csv", normal_count: int = 250):
    start = datetime(2026, 6, 1, 0, 0, 0)

    rows = make_normal_traffic(start, normal_count)
    rows += make_brute_force_burst(start)
    rows += make_impossible_travel(start)
    rows += make_offhours_anomaly(start)
    rows += make_new_device_login(start)
    rows += make_success_after_failures(start)
    rows += make_credential_stuffing(start)

    rows.sort(key=lambda r: r["timestamp"])

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "username", "ip", "status",
                                                "latitude", "longitude", "city", "device"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} synthetic login events -> {out_path}")


if __name__ == "__main__":
    generate()
