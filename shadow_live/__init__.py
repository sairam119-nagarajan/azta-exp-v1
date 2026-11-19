"""Prospective live-session Shadow adapter (Gate 5F): evidence from an UNFINISHED observer session into the existing Shadow pipeline.

    authorized live observer  ->  windows.jsonl grows, window by window
        -> `source`   byte-exact incremental reading with a rolling SHA-256 chain, session binding, grid, identity and time-plausibility checks
        -> `audits`   freshness-bounded read-only broker-policy audits (identity evidence), read as they are produced
        -> `pipeline` the EXISTING streaming pipeline (queue, stage timestamps, null hand-off) and the UNCHANGED trust engine
        -> `ledger`   one atomic, hash-chained entry per poll: restartable, tamper-evident, never rewritten
        -> `finalize` the bridge to the accepted scientific session: byte-for-byte digest reconciliation, never an acceptance

It sits OUTSIDE every directory pinned by the CAL_V2 tool freeze (`calibration`, `model`, `preprocessing`, `observation`, `experiments`, `trust`) and
composes them without editing any: the pinned evidence producer has no provenance class for an unfinished session, so this package supplies its own,
separately versioned `LIVE_SESSION_PROVISIONAL` run provenance through the producer's documented attribute interface. A live decision is always
`LIVE_PROVISIONAL`: it is never D_shadow evidence and never an accepted scientific result. Offline-testable; it holds no broker handle, no credential
and no enforcement object, and the only hand-off is the streaming pipeline's null sink.
"""
