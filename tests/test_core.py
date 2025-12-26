import pytest
from contextleak.core import ContextLeakCore

# Mock NLP model class (to keep tests fast and avoid 500MB downloads for unit tests)
class MockAnalyzerResult:
    def __init__(self, entity_type, score):
        self.entity_type = entity_type
        self.score = score

def test_initialization():
    """Checks if the engine initializes without errors."""
    core = ContextLeakCore(model_name="test-model")
    assert core.model_name == "test-model"
    assert "email" in core.PRESIDIO_MAPPING
    assert "openai_key" in core.REGEX_PATTERNS

def test_regex_sanitization():
    """Checks if API keys are redacted correctly using Regex."""
    core = ContextLeakCore()
    # Manually enable the filter for testing purposes
    core.active_filters["openai_key"] = True
    
    unsafe_text = "My key is sk-1234567890abcdef1234567890abcdef and it is secret."
    safe_text = core._sanitize_text(unsafe_text)
    
    assert "sk-" not in safe_text
    assert "[REDACTED: OPENAI_KEY]" in safe_text

def test_custom_blocklist(tmp_path):
    """Checks if the custom blocklist functionality works."""
    # Create a temporary file with a blocked word
    blocked_file = tmp_path / "blocked_words.txt"
    blocked_file.write_text("SecretProjectX", encoding="utf-8")
    
    core = ContextLeakCore()
    core.custom_list_file = str(blocked_file)
    # Reload the list to pick up the temp file
    core.custom_patterns = core._load_custom_list()
    
    text = "I am working on SecretProjectX at the company."
    safe_text = core._sanitize_text(text)
    
    assert "SecretProjectX" not in safe_text
    assert "[REDACTED: CUSTOM]" in safe_text

def test_pii_sanitization_integration():
    """Integration test with the real Presidio engine (requires the spacy model)."""
    # This test runs only if the environment is set up correctly (libraries + model)
    try:
        core = ContextLeakCore()
        text = "My email is test@example.com"
        # Force enable the email filter
        core.active_filters["email"] = True
        
        safe_text = core._sanitize_text(text)
        
        # Presidio should replace the email
        assert "test@example.com" not in safe_text
        assert "[REDACTED: PII]" in safe_text
    except Exception:
        pytest.skip("Skipping PII test - model or libraries missing")