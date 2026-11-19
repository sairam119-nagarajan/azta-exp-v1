"""Refusal types of the integrated decision pipeline. A refusal means: stop and report; nothing is repaired, defaulted or guessed."""


class RegistryRefused(ValueError):
    """A device-profile registry (or its use) is not acceptable. `code` is a stable, test-visible reason."""

    def __init__(self, code, message):
        super().__init__(f"{code}: {message}")
        self.code = code


class ModelVersionMismatch(RegistryRefused):
    """The registry names a model other than the frozen, loaded one (digest, fit id or profile): an incompatible model version."""

    def __init__(self, message):
        super().__init__("MODEL_VERSION_MISMATCH", message)
