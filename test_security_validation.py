from security_validation import validate_operations

def test_validation_success():
    result = validate_operations({"runtime":"PASS","health":"PASS"})
    assert result.status == "VALIDATED"

def test_validation_failure():
    result = validate_operations({"runtime":"FAIL"})
    assert result.status == "FAILED"
