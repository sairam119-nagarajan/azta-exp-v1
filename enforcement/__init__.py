"""AZTA enforcement layer (Master Implementation 2): the PEP adapter, its authorization boundary and the persistent runner.

    decision record -> [guard: operational | TEST_ONLY | administrative] -> AuthorizedRequest -> [persistence filter] -> PEP adapter -> Mosquitto Dynamic Security
        -> verified broker state -> hash-chained audit log

It sits OUTSIDE every directory pinned by the CAL_V2 freeze and composes `observation.registry` only. The PEP adapter is the ONLY component that holds the administrative
credential (in its own container); the PDP, the decision pipeline and the devices never import this package. Real-evidence enforcement is refused unless a controller-accepted
calibration, a CONTROLLER_APPROVED device registry and operating configuration, and live-observer evidence with verified provenance all exist (none does today); the independent
TEST_ONLY pathway exercises the mechanics on an isolated engineering broker and is not detection, calibrated trust scoring or a measured attack.
"""
