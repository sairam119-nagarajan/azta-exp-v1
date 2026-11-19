"""Gate 5F refusal types. Each one means: stop and report; nothing is repaired, defaulted or retried silently."""


class ConfigError(ValueError):
    """A trust configuration is invalid or incomplete."""


class BundleRefused(ValueError):
    """An evidence bundle is structurally malformed and cannot be interpreted at all."""


class ArtifactRefused(RuntimeError):
    """A frozen model, scaler or calibration artifact failed its integrity or compatibility check."""


class PathRefused(PermissionError):
    """An input or output path lies inside a protected evidence location."""


class ProducerRefused(ValueError):
    """The evidence-bundle producer was given inputs it must not combine (mixed provenance, reserved evidence, mismatched digests)."""
