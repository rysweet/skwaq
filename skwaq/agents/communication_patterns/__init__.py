"""Agent communication patterns for the Skwaq vulnerability assessment system.

This package contains implementations of advanced communication patterns
for agent interaction and collaboration.
"""

from .chain_of_thought import ChainOfThoughtPattern
from .debate import DebatePattern
from .feedback_loop import FeedbackLoopPattern
from .parallel_reasoning import ParallelReasoningPattern

__all__ = [
    "ChainOfThoughtPattern",
    "DebatePattern",
    "FeedbackLoopPattern",
    "ParallelReasoningPattern",
]
