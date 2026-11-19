"""Autoencoder inference timing for the live pilot worker (engineering instrumentation, no scientific effect).

`instrument(behavior, path)` replaces each frozen model in a `BehaviorEvaluator` by a thin proxy that times every `loss_for_vector` call on the host's `time.perf_counter_ns` (the pipeline's own
monotonic clock, only DIFFERENCES are meaningful) and appends {profile, start_mono_ns, end_mono_ns, duration_ns} to a JSONL file. The proxy forwards the call and its result unchanged and
delegates every other attribute, so scores, digests and descriptors are untouched. The report joins a call to a decision by its time interval ([decision start, decision end] on the same clock).
"""
import json
from pathlib import Path
import time


class TimedModel:
    def __init__(self, profile, model, stream):
        self._profile, self._model, self._stream = profile, model, stream

    def loss_for_vector(self, *args, **kwargs):
        start = time.perf_counter_ns()
        result = self._model.loss_for_vector(*args, **kwargs)
        end = time.perf_counter_ns()
        self._stream.write(json.dumps(dict(profile=self._profile, start_mono_ns=start, end_mono_ns=end, duration_ns=end - start), sort_keys=True) + "\n")
        self._stream.flush()
        return result

    def __getattr__(self, name):
        return getattr(self._model, name)


def instrument(behavior, path):
    stream = open(Path(path), "a", encoding="utf-8", newline="\n")
    behavior.models = {profile: TimedModel(profile, model, stream) for profile, model in behavior.models.items()}
    return stream
