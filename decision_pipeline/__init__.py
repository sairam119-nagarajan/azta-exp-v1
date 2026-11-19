"""Integrated AZTA decision pipeline (Master Implementation 1): the glue between the observer's windows and the trust engine's Shadow decisions.

    authenticated device -> broker -> observer -> six-feature window -> [registry routing] -> [frozen model inference] -> identity/context evidence
        -> unchanged trust engine -> Shadow decision (proposal, never applied) -> auditable record

It sits OUTSIDE every directory pinned by the CAL_V2 tool freeze (`calibration`, `model`, `preprocessing`, `observation`, `experiments`, `trust`) and
composes them without editing any. Modules: `registry` (versioned device-to-profile routing with model identity), `inference` (uncalibrated loss as
labelled telemetry), `taxonomy` (stable failure classes), `integrated` (the engine wrapper that plugs into the existing offline, replay and live
pipelines), `compose` (wiring from verified artifacts). It holds no broker handle, no credential, no network access and writes no file; every record
keeps `enforcement NONE` and `broker_policy_changes 0`. No calibration, weight, threshold or epsilon is chosen or defaulted here.
"""
