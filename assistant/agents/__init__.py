"""The agent layer: the hook-aware Claude runtime and the four-agent team built on it."""
from assistant.agents.runtime import MODEL, Agent, AgentError, Tool
from assistant.agents.team import PersonalAssistant

__all__ = ["MODEL", "Agent", "AgentError", "Tool", "PersonalAssistant"]
