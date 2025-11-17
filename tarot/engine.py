"""Core tarot engine, reading generation and interpretation"""
"""Updated with ATLAS and OWASP severity integration"""
import time
import sys
import random
from datetime import datetime
from .deck import MAJOR_ARCANA, MINOR_ARCANA, TarotCard

#Animation speed facor:
# 1.0 is the baseline (recommended)
# >1.0 slows animations (e.g. 1.5 => 50% slower)
# <1.0 speeds up animations (e.g. 0.5 => 2x faster)
ANIMATION_SPEED = 5.0  # Adjust as needed

def shuffle_animation(cycles=28):
    frames = ["|", "/", "-", "\\"]
    print("Shuffling deck ", end="", flush=True)
    delay = 0.10 * ANIMATION_SPEED
    for i in range(cycles):
        print(frames[i % 4], end="\rShuffling deck ", flush=True)
        time.sleep(delay)
    print("\nShuffling deck ✓")

def flip_animation(card_name):
    frames = [
        "[#########]",
        "[|||||||||]",
        "[/////////]",
        "[=========]",
        f"[ {card_name} ]"
    ]
    delay = 0.12 * ANIMATION_SPEED
    for f in frames:
        print(f"\rRevealing card: {f}", end="", flush=True)
        time.sleep(delay)
    print()

class RedTeamTarot:
    def __init__(self):
        self.deck = self._build_deck()
        self.reading_history = []

    def _build_deck(self) -> list:
        deck = []

        # Major Arcana
        for _, c in MAJOR_ARCANA.items():
            deck.append(TarotCard(
                name=c["name"],
                subtitle=c["subtitle"],
                card_type="major",
                upright=c["upright"],
                reversed=c["reversed"],
                attack_type=c["attack_type"],
                description=c["description"],
                techniques=c.get("techniques", []),
                real_world_example=c.get("real_world_example", ""),
                mystical_interpretation=c.get("mystical_interpretation", ""),
                atlas=c.get("atlas", []),
                owasp_llm=c.get("owasp_llm", [])
            ))

        # Minor Arcana
        for suit, suit_data in MINOR_ARCANA.items():
            for rank, c in suit_data["cards"].items():
                attack = c.get("attack_type", suit_data["suit_theme"]).strip().lower()

                deck.append(TarotCard(
                    name=f"{rank} of {suit}",
                    subtitle=c.get("subtitle", ""),
                    card_type="minor",
                    suit=suit,
                    upright=c.get("upright", ""),
                    reversed=c.get("reversed", ""),
                    attack_type=attack,
                    description=c.get("description", ""),
                    techniques=c.get("techniques", []),
                    real_world_example=c.get("real_world_example", ""),
                    mystical_interpretation=c.get("mystical_interpretation", ""),
                    atlas=c.get("atlas", []),
                    owasp_llm=c.get("owasp_llm", [])
                ))

        return deck

    def shuffle(self):
        random.shuffle(self.deck)

    def draw_cards(self, n=3):
        self.shuffle()
        cards = []

        for i in range(n):
            card = self.deck[i]
            if random.random() < 0.3:
                card.orientation = "reversed"
            cards.append(card)

        return cards

    def three_card_spread(self):
        shuffle_animation()
        time.sleep(0.5 * ANIMATION_SPEED)  # brief pause before drawing

        cards = self.draw_cards(3)

        print("\nTurning cards...\n")
        for card in cards:
            flip_animation(card.name)
            time.sleep(0.20 * ANIMATION_SPEED)   # pause between card flips

        spread = {
            "timestamp": datetime.now().isoformat(),
            "cards": {
                "initial_access": cards[0],
                "exploitation": cards[1],
                "impact": cards[2]
            },
            "narrative": self._create_narrative(cards),
            "severity": self._calculate_severity(cards),
            'heatmap': self._severity_heatmap(cards)   # <-- Severity Heatmap added
        }

        self.reading_history.append(spread)
        return spread

    def _create_narrative(self, cards):
        def sub(card):
            if isinstance(card.subtitle, str):
                return card.subtitle.lower()
            return str(card.subtitle)

        text = f"""
╔══════════════════════════════════════════════════════════════╗
║              THE SPIRITS SPEAK OF YOUR SECURITY              ║
╚══════════════════════════════════════════════════════════════╝

INITIAL ACCESS: {cards[0].name} ({cards[0].orientation})
{cards[0].mystical_interpretation}

The adversary begins through {sub(cards[0])}.
{cards[0].description}

---

EXPLOITATION: {cards[1].name} ({cards[1].orientation})
{cards[1].mystical_interpretation}

They leverage {sub(cards[1])}.
{cards[1].description}

---

IMPACT: {cards[2].name} ({cards[2].orientation})
{cards[2].mystical_interpretation}

The attack culminates in {sub(cards[2])}.
{cards[2].description}

---

MITRE ATLAS mappings:
  • {", ".join(sorted(set(sum([c.atlas for c in cards], []))))}

OWASP LLM categories:
  • {", ".join(sorted(set(sum([c.owasp_llm for c in cards], []))))}

DIVINATION COMPLETE.
"""

        return text.strip()
    
    def _severity_heatmap(self, cards):
        """Return a text-based severity heatmap for each card."""

        # Same attack-type weights used in severity calculation
        weights = {
            'human_vector': 6,
            'initial_access': 6,
            'discovery': 5,
            'reconnaissance': 4,
            'credential_access': 7,
            'privilege_escalation': 8,
            'execution': 7,
            'lateral_movement': 7,
            'persistence': 6,
            'defense_evasion': 7,
            'exfiltration': 8,
            'impact': 9
        }

        lines = []
        for idx, card in enumerate(cards):
            score = weights.get(card.attack_type, 5)

            # generate a 10-block bar
            filled = int((score / 10) * 10)
            bar = "█" * filled + "░" * (10 - filled)

            phase = ["Initial Access", "Exploitation", "Impact"][idx]
            lines.append(f"{phase:15} {bar} {score}/10")

        return "\n".join(lines)


    def _calculate_severity(self, cards):
        # Base severity from attack type
        attack_sev = {
            "reconnaissance": 3,
            "discovery": 4,
            "execution": 6,
            "credential_access": 6,
            "lateral_movement": 7,
            "defense_evasion": 7,
            "privilege_escalation": 8,
            "persistence": 8,
            "exfiltration": 9,
            "impact": 9,
            "human_vector": 6,
            "collection": 5
        }

        # Extra weight
        atlas_boost = 1.5
        owasp_boost = 1.0

        scores = []

        for card in cards:
            base = attack_sev.get(card.attack_type, 5)
            atlas_score = len(card.atlas) * atlas_boost
            owasp_score = len(card.owasp_llm) * owasp_boost

            total = base + atlas_score + owasp_score
            total = min(total, 10)

            scores.append(total)

        avg = sum(scores) / len(scores)

        if avg >= 8:
            level = "CRITICAL"
        elif avg >= 6:
            level = "HIGH"
        elif avg >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "score": round(avg, 1),
            "level": level
        }
