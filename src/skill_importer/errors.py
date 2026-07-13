"""Safe public errors for importer operations."""

import re

_ERROR_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]*")


class ImporterError(Exception):
    """An operational error containing only bounded public text."""

    MAX_CODE_LENGTH = 64
    MAX_MESSAGE_LENGTH = 512

    def __init__(self, code: str, message: str) -> None:
        if len(code) > self.MAX_CODE_LENGTH or _ERROR_CODE_RE.fullmatch(code) is None:
            raise ValueError("error code must be an uppercase machine-readable identifier")
        if not message:
            raise ValueError("error message must not be empty")

        self.code = code
        self.message = message[: self.MAX_MESSAGE_LENGTH]
        super().__init__(self.message)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"
