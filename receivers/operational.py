"""Operational receipt recorder: own MQTT principal, no administration or actuation."""
from pdp.research_subscriber import ResearchPDP


class OperationalReceiver(ResearchPDP):
    def __init__(self, config, records, session_id):
        super().__init__(config, records, session_id, stream="receiver", prefix="RECEIVER")
