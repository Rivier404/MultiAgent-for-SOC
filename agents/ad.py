from __future__ import annotations
from .base import BaseSOCAgent
from .prompts import AD, OUTPUT_SCHEMA

class ADAgent(BaseSOCAgent):
    name = "ADAgent"
    log_type = "ad"
    system_prompt = AD + "\n" + OUTPUT_SCHEMA
