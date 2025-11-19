# tarot/engine.py
"""Core tarot engine, reading generation and interpretation
Updated to support auto/custom draws for 3, 6, 10-card spreads,
two divination templates, and configurable animation modes.
"""
import random
import time
from datetime import datetime
from .deck import MAJOR_ARCANA, MINOR_ARCANA, TarotCard

# Animation helpers live here so runner can toggle them via flags.
def shuffle_animation(cycles=20, speed=1.0):
    frames = ["|", "/", "-", "\\"]
    print("Shuffling deck ", end="", flush=True)
    delay = 0.08 * speed
    for i in range(cycles):
        print(frames[i % len(frames)], end="\rShuffling deck ", flush=True)
        time.sleep(delay)
    print("\nShuffling deck ✓")

def flip_animation(card_name, speed=1.0):
    frames = [
        "[#########]",
        "[|||||||||]",
        "[/////////]",
        "[=========]",
        f"[ {card_name} ]"
    ]
    delay = 0.06 * speed
    for f in frames:
        print(f"\rRevealing card: {f}", end="", flush=True)
        time.sleep(delay)
    print()

class RedTeamTarot:
    """Main tarot engine, now with flexible spread support"""

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
                upright=c.get("upright", ""),
                reversed=c.get("reversed", ""),
                attack_type=c.get("attack_type", ""),
                description=c.get("description", ""),
                techniques=c.get("techniques", []),
                real_world_example=c.get("real_world_example", ""),
                mystical_interpretation=c.get("mystical_interpretation", ""),
                atlas=c.get("atlas", []),
                owasp_llm=c.get("owasp_llm", [])
            ))

        # Minor Arcana
        for suit, suit_data in MINOR_ARCANA.items():
            for rank, c in suit_data["cards"].items():
                attack = c.get("attack_type", suit_data.get("suit_theme", "")).strip().lower()
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

    def _assign_orientations(self, cards, reverse_chance=0.3):
        for card in cards:
            card.orientation = "upright"
            if random.random() < reverse_chance:
                card.orientation = "reversed"

    def draw_auto(self, n=3):
        """Return the top n cards from a freshly shuffled deck"""
        self.shuffle()
        cards = [self.deck[i] for i in range(n)]
        self._assign_orientations(cards)
        return cards

    def draw_custom(self, n=3):
        """Allow user to choose positions blind from the shuffled deck.
        They pick positions 1..len(deck), then the selected cards are returned.
        """
        self.shuffle()
        deck_size = len(self.deck)
        print(f"Deck has been shuffled. Choose {n} positions from 1 to {deck_size}.")
        chosen = []
        used = set()
        while len(chosen) < n:
            choice = input(f"Choose card {len(chosen)+1}/{n} (1-{deck_size}): ").strip()
            if not choice.isdigit():
                print("Enter a number.")
                continue
            pos = int(choice)
            if pos < 1 or pos > deck_size:
                print("Out of range.")
                continue
            if pos in used:
                print("Already chosen.")
                continue
            used.add(pos)
            chosen.append(self.deck[pos-1])
        self._assign_orientations(chosen)
        return chosen

    # Public spread entrypoint to keep run logic simple
    def spread(self, count=3, mode="auto", divination_template="security", animate_mode="default", name=None):
        """Draw `count` cards using mode 'auto' or 'custom'.
        animate_mode: 'off', 'default', 'cinematic'
        divination_template matters only for 10-card spreads.
        Returns a dict with narrative, cards, heatmap, severity, timestamp.
        """
        # draw
        if mode == "custom":
            cards = self.draw_custom(count)
        else:
            cards = self.draw_auto(count)

        # animation handling
        # default = animate first 3 with mild speed
        if animate_mode == "off":
            do_shuffle_anim = False
            flip_all = False
            speed = 0.0
        elif animate_mode == "cinematic":
            do_shuffle_anim = True
            flip_all = True
            speed = 1.6
        else:  # default
            do_shuffle_anim = True
            flip_all = False
            speed = 0.9

        if do_shuffle_anim:
            shuffle_animation(speed=speed)
            # small pause
            time.sleep(0.08 * speed)

        # card revealing sequence
        # if flip_all True animate all; if False animate first 3, reveal the rest fast
        for i, card in enumerate(cards):
            if animate_mode == "off":
                # no animation, just show label
                print(f"Revealed: {card.name} ({card.orientation})")
            else:
                # determine per-card animation speed
                if flip_all:
                    flip_animation(card.name, speed=speed)
                else:
                    if i < 3:
                        flip_animation(card.name, speed=speed)
                    else:
                        # quick textual reveal for later cards
                        print(f"Revealed: {card.name} ({card.orientation})")
            # brief pause between reveals
            time.sleep(0.06 * (speed if speed > 0 else 1.0))

        # build narrative and metadata
        narrative = self._build_narrative(cards, template=divination_template)
        heatmap = self._severity_heatmap(cards)
        severity = self._calculate_severity(cards)
        ts = datetime.now().isoformat()

        spread = {
            "timestamp": ts,
            "name": name or "",
            "cards": cards,
            "narrative": narrative,
            "heatmap": heatmap,
            "severity": severity
        }

        self.reading_history.append(spread)
        return spread

    # Narrative templates
    def _build_narrative(self, cards, template="security"):
        """Dispatch to appropriate narrative builder based on card count"""
        n = len(cards)
        if n == 3:
            return self._narrative_three(cards)
        if n == 6:
            return self._narrative_six_security(cards)
        if n == 10:
            if template == "classic":
                return self._narrative_ten_classic(cards)
            return self._narrative_ten_security(cards)
        # fallback generic listing
        return self._narrative_generic(cards)

    def _narrative_three(self, cards):
        def safe_sub(c):
            return c.subtitle.lower() if isinstance(c.subtitle, str) else str(c.subtitle)
        text = f"""
╔══════════════════════════════════════════════════════════════╗
║              THE SPIRITS SPEAK OF YOUR SECURITY              ║
╚══════════════════════════════════════════════════════════════╝

INITIAL ACCESS: {cards[0].name} ({cards[0].orientation})
{cards[0].mystical_interpretation}

The adversary begins through {safe_sub(cards[0])}.
{cards[0].description}

---

EXPLOITATION: {cards[1].name} ({cards[1].orientation})
{cards[1].mystical_interpretation}

They leverage {safe_sub(cards[1])}.
{cards[1].description}

---

IMPACT: {cards[2].name} ({cards[2].orientation})
{cards[2].mystical_interpretation}

The attack culminates in {safe_sub(cards[2])}.
{cards[2].description}

---

DIVINATION COMPLETE.
"""
        return text.strip()

    def _narrative_six_security(self, cards):
        # 6-card security lifecycle: Recon, Initial Access, Exploitation, Pivot, Exfiltration, Impact
        labels = ["RECONNAISSANCE", "INITIAL ACCESS", "EXPLOITATION", "PIVOT", "EXFILTRATION", "IMPACT"]
        lines = []
        for i, c in enumerate(cards):
            lines.append(f"{labels[i]}: {c.name} ({c.orientation})")
            lines.append(c.mystical_interpretation)
            lines.append(f" - {c.subtitle}")
            lines.append(c.description)
            lines.append("\n")
        header = "╔" + "═" * 62 + "╗\n║              THE SPIRITS SPEAK OF YOUR SECURITY              ║\n╚" + "═" * 62 + "╝\n"
        return header + "\n".join(lines).strip()

    def _narrative_ten_classic(self, cards):
        # Classic Celtic cross adapted to security language lightly
        mapping = [
            ("The Heart of the Matter", cards[0]),
            ("The Challenge", cards[1]),
            ("Past", cards[2]),
            ("Future", cards[3]),
            ("Above", cards[4]),
            ("Below", cards[5]),
            ("Self", cards[6]),
            ("Environment", cards[7]),
            ("Hopes and Fears", cards[8]),
            ("Outcome", cards[9])
        ]
        lines = []
        for label, c in mapping:
            lines.append(f"{label}: {c.name} ({c.orientation})")
            lines.append(c.mystical_interpretation)
            lines.append(f" - {c.subtitle}")
            lines.append(c.description)
            lines.append("\n")
        header = "╔" + "═" * 62 + "╗\n║              THE SPIRITS SPEAK OF YOUR SECURITY              ║\n╚" + "═" * 62 + "╝\n"
        return header + "\n".join(lines).strip()

    def _narrative_ten_security(self, cards):
        # Security-focused celtic cross like mapping for incident analysis
        mapping = [
            ("Initial Exposure", cards[0]),
            ("Threat Pressure", cards[1]),
            ("Root Cause", cards[2]),
            ("Adversary Next Step", cards[3]),
            ("Strategic Weakness", cards[4]),
            ("Hidden Variable", cards[5]),
            ("Defender State", cards[6]),
            ("Attack Surface", cards[7]),
            ("Worst Case", cards[8]),
            ("Final Impact", cards[9])
        ]
        lines = []
        for label, c in mapping:
            lines.append(f"{label}: {c.name} ({c.orientation})")
            lines.append(c.mystical_interpretation)
            lines.append(f" - {c.subtitle}")
            lines.append(c.description)
            lines.append("\n")
        header = "╔" + "═" * 62 + "╗\n║              THE SPIRITS SPEAK OF YOUR SECURITY              ║\n╚" + "═" * 62 + "╝\n"
        return header + "\n".join(lines).strip()

    def _narrative_generic(self, cards):
        lines = []
        for i, c in enumerate(cards, start=1):
            lines.append(f"CARD {i}: {c.name} ({c.orientation})")
            lines.append(c.mystical_interpretation)
            lines.append(f" - {c.subtitle}")
            lines.append(c.description)
            lines.append("\n")
        return "\n".join(lines).strip()

    # Heatmap and severity utilities are similar to earlier versions
    def _severity_heatmap(self, cards):
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
        phases = ["Initial Access", "Exploitation", "Impact", "Pivot", "Exfiltration", "Other"]
        for idx, card in enumerate(cards):
            score = weights.get(card.attack_type, 5)
            filled = int((score / 10) * 10)
            bar = "█" * filled + "░" * (10 - filled)
            phase = phases[idx] if idx < len(phases) else f"Card{idx+1}"
            lines.append(f"{phase:15} {bar} {score}/10")
        return "\n".join(lines)

    def _calculate_severity(self, cards):
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
