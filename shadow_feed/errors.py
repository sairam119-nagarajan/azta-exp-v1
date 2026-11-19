"""Refusal types of the shadow feed. A refusal means: stop and report. Nothing is repaired, skipped, defaulted or retried silently."""


class ScientificReadRefused(ValueError):
    """The manifest-verified reader refused a campaign, a run or a file. `code` is a stable, test-visible reason."""

    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code


class StreamRefused(ValueError):
    """The streaming pipeline was configured in a way that could change broker state or fabricate evidence."""

    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code
