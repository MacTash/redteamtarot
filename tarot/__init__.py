"""
Red Team Tarot - Divine Your Security Vulnerabilities

A mystical security tool that maps attack patterns to tarot archetypes.
"""

__version__ = "0.1.0"
__author__ = "Mayukh"

from .deck import TarotCard, MAJOR_ARCANA, MINOR_ARCANA
from .engine import RedTeamTarot

__all__ = [
    "TarotCard",
    "MAJOR_ARCANA",
    "MINOR_ARCANA",
    "RedTeamTarot"
]
