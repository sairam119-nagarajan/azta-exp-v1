"""Isolated engineering environment tooling (Master Implementation 2): secrets, provisioning, probes and orchestration for the `azta-eng` Docker project.

Operator tooling, not a guarded package and not scientific evidence. It talks only to the engineering broker (`compose.engineering.yaml`, project `azta-eng`) and refuses to
act on anything else. It sits outside every directory pinned by the CAL_V2 freeze.
"""
