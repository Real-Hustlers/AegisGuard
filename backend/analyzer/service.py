def get_dashboard_summary():
    """Return dummy dashboard statistics and chart payloads."""
    return {
        "events": 12034,
        "threats": 24,
        "devices": 36,
        "alerts": 3,
        "timeline": {
            "labels": ["00:00", "02:00", "04:00", "06:00", "08:00", "10:00", "12:00", "14:00", "16:00", "18:00", "20:00", "22:00"],
            "values": [12, 10, 8, 12, 35, 55, 50, 65, 50, 40, 32, 28],
        },
        "distribution": {
            "labels": ["Linux Servers", "Win Workstations", "VMs (VirtualBox)", "Network Devices"],
            "values": [14, 22, 8, 6],
        },
    }


def get_events():
    """Return dummy event logs with the shape expected by the frontend."""
    return [
        {
            "id": "LOG-7821",
            "timestamp": "2026-07-13 14:32:07",
            "hostname": "SRV-ALPHA",
            "ip": "192.168.1.104",
            "severity": "Critical",
            "event": "SSH brute-force detected — 48 failed attempts in 60s",
        },
        {
            "id": "LOG-7820",
            "timestamp": "2026-07-13 14:31:44",
            "hostname": "WS-003",
            "ip": "192.168.1.87",
            "severity": "High",
            "event": "Nmap port scan signature identified on internal interface",
        },
        {
            "id": "LOG-7819",
            "timestamp": "2026-07-13 14:30:11",
            "hostname": "VM-GUEST-2",
            "ip": "192.168.2.15",
            "severity": "High",
            "event": "Hydra credential stuffing pattern on service port 8080",
        },
        {
            "id": "LOG-7818",
            "timestamp": "2026-07-13 14:28:56",
            "hostname": "GW-MAIN",
            "ip": "192.168.1.1",
            "severity": "Medium",
            "event": "Unusual outbound traffic spike — 3.2GB in 5 minutes",
        },
    ]


def get_alerts():
    """Return dummy alert cards for the dashboard."""
    return [
        {
            "id": "ALT-301",
            "severity": "Critical",
            "title": "SSH Brute Force in Progress",
            "device": "SRV-ALPHA",
            "time": "2 min ago",
        },
        {
            "id": "ALT-300",
            "severity": "High",
            "title": "Port Scan from Internal Host",
            "device": "WS-003",
            "time": "3 min ago",
        },
    ]