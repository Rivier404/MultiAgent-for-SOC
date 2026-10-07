from __future__ import annotations
from .base import BaseSOCAgent
from .prompts import NETWORK, OUTPUT_SCHEMA

class NetworkAgent(BaseSOCAgent):
    name = "NetworkAgent"
    log_type = "network"
    system_prompt = NETWORK + "\n" + OUTPUT_SCHEMA
