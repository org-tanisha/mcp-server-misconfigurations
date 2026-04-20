import re

class Redactor:
    """Redacts sensitive information from strings and dictionaries."""
    
    # Common patterns for security findings
    PATTERNS = {
        "aws_account_id": r"\b\d{12}\b",
        "aws_access_key": r"\bAKIA[A-Z0-9]{16}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        # Generic sensitive patterns can be added here
    }

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.compiled_patterns = {name: re.compile(pattern) for name, pattern in self.PATTERNS.items()}

    def redact_text(self, text: str) -> str:
        if not self.enabled or not text:
            return text
        
        redacted = text
        for name, pattern in self.compiled_patterns.items():
            redacted = pattern.sub(f"[REDACTED_{name.upper()}]", redacted)
        return redacted

    def redact_dict(self, data: dict) -> dict:
        if not self.enabled:
            return data
        
        new_data = {}
        for key, value in data.items():
            if isinstance(value, str):
                new_data[key] = self.redact_text(value)
            elif isinstance(value, dict):
                new_data[key] = self.redact_dict(value)
            elif isinstance(value, list):
                new_data[key] = [
                    self.redact_dict(item) if isinstance(item, dict) else (self.redact_text(item) if isinstance(item, str) else item)
                    for item in value
                ]
            else:
                new_data[key] = value
        return new_data

default_redactor = Redactor()
