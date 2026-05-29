import pytest
from waechter.providers import ClamAVProvider
import os
from unittest.mock import patch

def test_clamav_provider_initialization_override():
    with patch("waechter.providers._clamav.config.load_provider_section") as mock_cfg:
        mock_cfg.return_value = {"enabled": False}

        # Scenario 1: YAML says False, but we pass enabled=True (like main.py does)
        p1 = ClamAVProvider(enabled=True)
        assert p1.enabled is True, "Constructor parameter should override YAML config"

        # Scenario 2: YAML says False, we pass nothing -> should be False from YAML
        p2 = ClamAVProvider()
        assert p2.enabled is False, "Should fall back to YAML config if no parameter given"

def test_clamav_provider_initialization_yaml_fallback():
    with patch("waechter.providers._clamav.config.load_provider_section") as mock_cfg:
        mock_cfg.return_value = {"enabled": True}

        # Scenario 3: YAML says True, but we pass enabled=False
        p1 = ClamAVProvider(enabled=False)
        assert p1.enabled is False, "Constructor parameter should override YAML config (False case)"

        # Scenario 4: YAML says True, we pass nothing -> should be True from YAML
        p2 = ClamAVProvider()
        assert p2.enabled is True, "Should fall back to YAML config (True case)"

if __name__ == "__main__":
    try:
        test_clamav_provider_initialization_override()
        test_clamav_provider_initialization_yaml_fallback()
        print("Tests passed!")
    except AssertionError as e:
        print(f"Test failed: {e}")
        exit(1)
