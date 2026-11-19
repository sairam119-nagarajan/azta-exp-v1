"""Refusal types of the live adapter. A refusal means: stop and report. Nothing is repaired, skipped, defaulted or retried silently."""


class LiveRefused(ValueError):
    """A declaration, source, audit, ledger or finalization check refused. `code` is a stable, test-visible reason."""

    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code


class LiveIntegrityFailure(LiveRefused):
    """FATAL: the live evidence can no longer be trusted (a source or audit file was rewritten or truncated, the ledger chain is broken, the final
    digest differs from the observer's own). The session halts and every undecided window is refused; nothing continues on suspect evidence."""
