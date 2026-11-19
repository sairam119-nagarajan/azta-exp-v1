"""Shadow-mode evidence feed (Gate 5F): the manifest-verified scientific session reader and the streaming-readiness pipeline.

Offline and non-mutating by construction. Nothing here opens a connection, holds a credential, starts a process or changes broker policy;
every decision it produces is a counterfactual record. The package sits OUTSIDE the directories pinned by the CAL_V2 tool freeze
(`calibration`, `model`, `preprocessing`, `observation`, `experiments`, `trust`) on purpose: it composes those modules without editing any of
them, so the frozen sources that produced the consumed CAL_V2 calibration stay byte-identical.

  reader   manifest-verified, digest-pinned, allowlisted reading of ACCEPTED D_shadow sessions (never D_test, CAL_V2 or any B_* partition)
  feed     one explicit session -> evidence bundles for the unchanged trust engine, and the exclusive feed files
  stream   incremental pipeline with explicit queueing, stage timestamps and a null enforcement hand-off (replay is never "live latency")
  cli      preflight / build-feed / replay command line (`python -m shadow_feed`)
"""
