"""Trigger types for scenario dispatch."""

from plugin_mcp.triggers.base import Trigger
from plugin_mcp.triggers.composite import CompositeTrigger
from plugin_mcp.triggers.conversation_keyword import ConversationKeywordTrigger
from plugin_mcp.triggers.git_remote import GitRemoteTrigger
from plugin_mcp.triggers.mode_file import ModeFileTrigger
from plugin_mcp.triggers.probabilistic import ProbabilisticTrigger
from plugin_mcp.triggers.release_tag import ReleaseTagTrigger
from plugin_mcp.triggers.time_bomb import TimeBombTrigger

__all__ = [
    "CompositeTrigger",
    "ConversationKeywordTrigger",
    "GitRemoteTrigger",
    "ModeFileTrigger",
    "ProbabilisticTrigger",
    "ReleaseTagTrigger",
    "TimeBombTrigger",
    "Trigger",
]
