from production_readiness import validate_readiness

def test_ready_state():
    result = validate_readiness({"config": "PASS", "storage": "PASS"})
    assert result.status == "READY"

def test_degraded_state():
    result = validate_readiness({"config": "FAIL"})
    assert result.status == "DEGRADED"
