from __future__ import annotations
from .base import BaseSOCAgent
from .prompts import ENDPOINT, OUTPUT_SCHEMA

class EndpointAgent(BaseSOCAgent):
    name = "EndpointAgent"
    log_type = "endpoint"
    system_prompt = ENDPOINT + "\n" + OUTPUT_SCHEMA
