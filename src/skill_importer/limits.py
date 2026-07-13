"""Resource limits applied throughout one importer operation."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Limits:
    """Immutable resource limits with conservative POC defaults."""

    git_timeout_seconds: int = 60
    fm_timeout_seconds: int = 20
    max_archive_bytes: int = 100 * 1024 * 1024
    max_entries: int = 10_000
    max_scan_bytes: int = 250 * 1024 * 1024
    max_file_bytes: int = 10 * 1024 * 1024
    max_depth: int = 64
    max_fm_context_chars: int = 128 * 1024
    max_fm_response_bytes: int = 1024 * 1024
    max_fm_reviews: int = 50

    def __post_init__(self) -> None:
        values = (
            self.git_timeout_seconds,
            self.fm_timeout_seconds,
            self.max_archive_bytes,
            self.max_entries,
            self.max_scan_bytes,
            self.max_file_bytes,
            self.max_depth,
            self.max_fm_context_chars,
            self.max_fm_response_bytes,
            self.max_fm_reviews,
        )
        if any(value <= 0 for value in values):
            raise ValueError("resource limits must be positive")

    def to_dict(self) -> dict[str, int]:
        """Serialize limits using public JSON field names."""
        return {
            "gitTimeoutSeconds": self.git_timeout_seconds,
            "fmTimeoutSeconds": self.fm_timeout_seconds,
            "maxArchiveBytes": self.max_archive_bytes,
            "maxEntries": self.max_entries,
            "maxScanBytes": self.max_scan_bytes,
            "maxFileBytes": self.max_file_bytes,
            "maxDepth": self.max_depth,
            "maxFmContextChars": self.max_fm_context_chars,
            "maxFmResponseBytes": self.max_fm_response_bytes,
            "maxFmReviews": self.max_fm_reviews,
        }
