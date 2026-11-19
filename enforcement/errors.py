"""Refusal and failure types of the enforcement layer. `code` is a stable, test-visible reason; no response object, password or secret enters a message."""


class EnforcementError(Exception):
    def __init__(self, code, message=""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


class GuardRefused(EnforcementError):
    """An authorization guard refused to mint a request. Nothing was sent to the broker."""


class PepRefused(EnforcementError):
    """The PEP adapter refused a request before any mutation (unauthorized, inconsistent baseline, unknown device, wrong environment, bad transition)."""


class ControlUnavailable(EnforcementError):
    """The control channel could not deliver a command or read a response; the broker-side effect of an in-flight command is UNKNOWN."""


class ApprovalRefused(EnforcementError):
    """A controller approval record is missing, malformed, unpinned, expired, not yet valid or does not match the artifacts it names. Nothing is enabled."""


class AuditIntegrityError(EnforcementError):
    """The audit log chain, its tail or a recorded cursor is not intact; the layer stops rather than continuing on a suspect record."""
