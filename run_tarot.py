#Red Team Tarot
from tarot.engine import RedTeamTarot

def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║                    🃏 RED TEAM TAROT 🃏                      ║
    ║                                                              ║
    ║              Divine Your Security Vulnerabil                 ║
    ║                                                              ║
    ║                      By: MacTash                             ║
    ╚══════════════════════════════════════════════════════════════╝
    """)


    tarot = RedTeamTarot()
    print(f"\nDeck loaded: {len(tarot.deck)} cards\n")
    print("Drawing three cards...\n")

    spread = tarot.three_card_spread()

    print(spread["narrative"])
    print()
    print(f"Severity: {spread['severity']['level']} ({spread['severity']['score']}/10)\n")

    print("\nSeverity Heatmap:")
    print(spread["heatmap"])

if __name__ == "__main__":
    main()
