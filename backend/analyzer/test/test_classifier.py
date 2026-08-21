import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.analyzer.ingestion.classifier import classify_logs


def test_successful_login_is_classified_as_normal():
    sample = [{
        "timestamp": "2026-07-14T09:31:10Z",
        "event_type": "LOGON_SUCCESS",
        "user": "admin",
        "hostname": "Dev-Server",
        "source_ip": "192.168.1.10",
        "destination_ip": "",
        "process": "sshd",
        "file_path": "",
        "severity": "LOW",
        "raw_log": "Successful login"
    }]

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "merged.json"
        output_path = Path(tmpdir) / "classified.json"
        input_path.write_text(json.dumps(sample), encoding="utf-8")
        classify_logs(str(input_path), str(output_path))
        payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload[0]["ml_prediction"] == "NORMAL"
    assert payload[0]["threat_level"] == "LOW"


def test_malware_alert_is_classified_as_malware():
    sample = [{
        "timestamp": "2026-07-14T09:32:10Z",
        "event_type": "DEFENDER_ALERT",
        "user": "admin",
        "hostname": "Dev-Server",
        "source_ip": "192.168.1.10",
        "destination_ip": "",
        "process": "defender",
        "file_path": "",
        "severity": "CRITICAL",
        "raw_log": "Malware detected"
    }]

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "merged.json"
        output_path = Path(tmpdir) / "classified.json"
        input_path.write_text(json.dumps(sample), encoding="utf-8")
        classify_logs(str(input_path), str(output_path))
        payload = json.loads(output_path.read_text(encoding="utf-8"))

    assert payload[0]["ml_prediction"] == "MALWARE"
    assert payload[0]["threat_level"] == "CRITICAL"
