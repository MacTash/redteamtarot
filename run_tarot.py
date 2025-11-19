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
    "Hocus pocus!"
]

EXIT_QUOTES = [
    "The end of it.",
    "The sun smiles at you with eternal malice.",
    "Toil and trouble, fire burn and cauldron bubble.",
    "A journey's end.",
    "Bountiful fortune and towering riches escapes you.",
    "TAROT OUT!",
    "Goodbye, biological unit.",
    "The lesson ends.",
    "May your logs be ever clean."
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

def prompt_menu(prompt, options):
    """Prompt with numbered options. options is list of tuples (key, label). Returns key."""
    print(prompt)
    for k, label in options:
        print(f"  {k}. {label}")
    while True:
        choice = input("Choice: ").strip()
        if choice.isdigit():
            for k, label in options:
                if str(k) == choice:
                    return choice
        print("Please enter a valid number from the menu.")

def prompt_yes_no(prompt="Yes or No? (y/n): "):
    while True:
        try:
            choice = input(prompt).strip().lower()
        except (KeyboardInterrupt, EOFError):
            return False
        if choice in ("y", "yes"):
            return True
        if choice in ("n", "no"):
            return False
        print("Answer y or n.")

def main():
    tarot = RedTeamTarot()
    header()
    print(f"\nDeck loaded: {len(tarot.deck)} cards\n")

    try:
        while True:
            mode = prompt_menu("Choose draw mode:", [("1", "Auto"), ("2", "Custom (blind selection)")])
            spread_choice = prompt_menu("Choose spread:", [("1", "Half Fate - 3 cards"), ("2", "Full Fate - 6 cards"), ("3", "Divination - 10 cards")])

            div_template = "security"
            if spread_choice == "3":
                dt = prompt_menu("Choose divination template:", [("1", "Classic Celtic Cross"), ("2", "Security Cross")])
                div_template = "classic" if dt == "1" else "security"

            # animation mode
            anim_choice = prompt_menu("Animation mode:", [("1", "Default (first 3 animated)"), ("2", "Cinematic (all animated)"), ("3", "Off (no animations)")])
            animate_mode = {"1": "default", "2": "cinematic", "3": "off"}[anim_choice]

            # optional naming
            name_it = prompt_yes_no("Would you like to name this reading? (y/n): ")
            name = ""
            if name_it:
                name = input("Enter reading name (press Enter to skip): ").strip()

            # map choices to counts and draw mode
            count = 3 if spread_choice == "1" else 6 if spread_choice == "2" else 10
            mode_key = "custom" if mode == "2" else "auto"

            print("\nDrawing...\n")
            spread = tarot.spread(count=count, mode=mode_key, divination_template=div_template, animate_mode=animate_mode, name=name)

            # show results
            if spread["name"]:
                print(f"=== Reading: {spread['name']} ===\n")

            print(spread["narrative"])
            print()
            print(f"Severity: {spread['severity']['level']} ({spread['severity']['score']}/10)\n")
            print("\nSeverity Heatmap:")
            print(spread["heatmap"])
            print()

            again = prompt_yes_no("Draw again? (y/n): ")
            if again:
                print("\n" + random.choice(CONTINUE_QUOTES) + "\n")
                continue
            else:
                print("\n" + random.choice(EXIT_QUOTES) + "\n")
                break

    except KeyboardInterrupt:
        print("\n" + random.choice(EXIT_QUOTES))
        sys.exit(0)

if __name__ == "__main__":
    main()
