from __future__ import annotations


def slugify(text: str) -> str:
    """Turn a title into a URL-safe slug."""
    return "-".join(text.lower().split())


def chunk(items: list, size: int) -> list[list]:
    return [items[i : i + size] for i in range(0, len(items), size)]


class RetryPolicy:
    def __init__(self, max_attempts: int = 3, backoff_seconds: float = 1.5):
        self.max_attempts = max_attempts
        self.backoff_seconds = backoff_seconds
