# run_tarot.py
import random
import sys
from tarot.engine import RedTeamTarot

CONTINUE_QUOTES = [
    "You persist.",
    "Improvise, adapt, overcome.",
    "The wheel turns again.",
    "Once more into the breach.",
    "The veil lifts anew.",
    "You make your own fate.",
    "Ad astra abyssosque.",
    "A wise choice.",
    "Hocus pocus!",
    "The horrors persist but so do you.",
    "The truth is out there.",
]

EXIT_QUOTES = [
    "The end of it.",
    "The sun smiles at you with eternal malice.",
    "Toil and trouble, fire burn and cauldron bubble.",
    "A journey's end.",
    "Bountiful fortune and towering riches escapes you.",
    "TAROT OUT!",
    "Goodbye, flesh automaton.",
    "The lesson ends.",
    "*Chicken sounds*.",
    "Rule no 60: Never play fair.",
    "No rest for the wicked.",
    "DEBUG THIS!",
]

def header():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                    🃏 RED TEAM TAROT 🃏                      ║
║                                                              ║
║              Divine Your Security Vulnerabilities            ║
║                                                              ║
║                       By: MacTash                            ║
╚══════════════════════════════════════════════════════════════╝
""")


def prompt_yes_no(prompt="Draw again? (y/n): "):
    """Prompt until user supplies a valid y/n response. Returns True for y, False for n."""
    while True:
        try:
            choice = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            # Treat Ctrl+C / EOF as a no and exit gracefully
            print()
            return False

        if choice in ("y", "yes"):
            return True
        if choice in ("n", "no"):
            return False
        # invalid input, loop again
        print("Please answer 'y' or 'n'.")


def main():
    tarot = RedTeamTarot()
    header()
    print(f"\nDeck loaded: {len(tarot.deck)} cards\n")

    try:
        while True:
            print("Drawing three cards...\n")
            spread = tarot.three_card_spread()

            print(spread["narrative"])
            print()
            print(f"Severity: {spread['severity']['level']} ({spread['severity']['score']}/10)\n")

            print("\nSeverity Heatmap:")
            print(spread["heatmap"])
            print()

            again = prompt_yes_no("Draw again? (y/n): ")
            if again:
                print("\n" + random.choice(CONTINUE_QUOTES) + "\n")
                # loop continues naturally
                continue
            else:
                print("\n" + random.choice(EXIT_QUOTES) + "\n")
                break

    except KeyboardInterrupt:
        # final graceful exit if user presses Ctrl+C during the reading
        print("\n")
        print(random.choice(EXIT_QUOTES))
        sys.exit(0)


if __name__ == "__main__":
    main()