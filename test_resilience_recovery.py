from resilience_recovery import recover_component

def test_recovery_success():
    result = recover_component("Analyzer", {"storage": "PASS"})
    assert result.state == "READY"

def test_recovery_failure():
    result = recover_component("Analyzer", {"storage": "FAIL"})
    assert result.state == "DEGRADED"

def test_component_name():
    result = recover_component("Collector", {"health": "PASS"})
    assert result.component == "Collector"
