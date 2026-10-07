from __future__ import annotations
from .base import BaseSOCAgent
from .prompts import WEB, OUTPUT_SCHEMA

class WebAgent(BaseSOCAgent):
    name = "WebAgent"
    log_type = "web"
    system_prompt = WEB + "\n" + OUTPUT_SCHEMA
