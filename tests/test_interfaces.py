import pyrealm
import pyrealm_forensics


def test_library_and_recovery_namespaces_are_separate() -> None:
    assert "open_realm" in pyrealm.__all__
    assert "analyze_realm" not in pyrealm.__all__
    assert "analyze_realm" in pyrealm_forensics.__all__
    assert "open_realm" not in pyrealm_forensics.__all__
