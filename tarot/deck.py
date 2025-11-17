"""Tarot deck definitions with MITRE ATLAS and OWASP LLM mappings"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TarotCard:
    name: str
    subtitle: str
    card_type: str
    suit: Optional[str] = None
    upright: str = ""
    reversed: str = ""
    attack_type: str = ""
    description: str = ""
    techniques: list[str] = field(default_factory=list)
    real_world_example: str = ""
    mystical_interpretation: str = ""
    orientation: str = "upright"

    # New fields
    atlas: list[str] = field(default_factory=list)
    owasp_llm: list[str] = field(default_factory=list)

    def __str__(self):
        return f"{self.name} ({self.orientation})"


# Helper for minor cards
def minor_atlas(attack):
    if attack == "reconnaissance":
        return ["ATLAS-2001 Reconnaissance"]
    if attack == "discovery":
        return ["ATLAS-2002 Information Gathering"]
    if attack == "execution":
        return ["ATLAS-3001 Exploitation"]
    if attack == "credential_access":
        return ["ATLAS-3004 Credential Abuse"]
    if attack == "privilege_escalation":
        return ["ATLAS-3003 Privilege Escalation"]
    if attack == "lateral_movement":
        return ["ATLAS-3006 Lateral Movement"]
    if attack == "persistence":
        return ["ATLAS-4002 Persistence"]
    if attack == "exfiltration":
        return ["ATLAS-5001 Data Exfiltration"]
    return ["ATLAS-9000 General Attack"]


def minor_owasp(attack):
    if attack in ["reconnaissance", "discovery"]:
        return ["LLM02 Insecure Output Handling"]
    if attack == "execution":
        return ["LLM07 Unauthorized Code Execution"]
    if attack == "credential_access":
        return ["LLM06 Sensitive Information Disclosure"]
    if attack == "privilege_escalation":
        return ["LLM09 Model Theft"]
    if attack == "exfiltration":
        return ["LLM06 Sensitive Information Disclosure"]
    return ["LLM01 Prompt Injection"]

#MAJOR ARCANA
MAJOR_ARCANA = {
    0: {
        "name": "The Fool",
        "subtitle": "Social Engineering",
        "upright": "Naive trust, unverified entry",
        "reversed": "Over verification",
        "attack_type": "human_vector",
        "description": "The Fool walks toward the cliff with misplaced trust.",
        "techniques": ["Phishing", "Pretexting"],
        "real_world_example": "Twitter social engineering breach",
        "mystical_interpretation": "The innocent unlocks doors without knowing.",
        "atlas": ["ATLAS-1004 Social Engineering"],
        "owasp_llm": ["LLM01 Prompt Injection"]
    },

    1: {
        "name": "The Magician",
        "subtitle": "Privilege Escalation",
        "upright": "Power increase",
        "reversed": "Denied access",
        "attack_type": "privilege_escalation",
        "description": "User becomes admin through clever manipulation.",
        "techniques": ["Sudo abuse", "Token theft"],
        "real_world_example": "Dirty COW",
        "mystical_interpretation": "The alchemist transforms access.",
        "atlas": ["ATLAS-3003 Privilege Escalation"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    2: {
        "name": "The High Priestess",
        "subtitle": "Information Disclosure",
        "upright": "Secrets revealed",
        "reversed": "Secrets hidden",
        "attack_type": "discovery",
        "description": "Hidden knowledge becomes visible.",
        "techniques": ["Directory traversal", "Secret leaks"],
        "real_world_example": "Exposed .env files",
        "mystical_interpretation": "Whispers of hidden truths.",
        "atlas": ["ATLAS-2002 Information Gathering"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    3: {
        "name": "The Empress",
        "subtitle": "Supply Chain Attack",
        "upright": "Poisoned dependencies",
        "reversed": "Verified sources",
        "attack_type": "initial_access",
        "description": "The mother of dependencies is compromised.",
        "techniques": ["Typosquatting", "Dependency confusion"],
        "real_world_example": "SolarWinds",
        "mystical_interpretation": "Her gifts can rot from within.",
        "atlas": ["ATLAS-8001 Supply Chain Manipulation"],
        "owasp_llm": ["LLM05 Supply Chain Vulnerabilities"]
    },

    4: {
        "name": "The Emperor",
        "subtitle": "Authentication Bypass",
        "upright": "Authority undermined",
        "reversed": "Strong policies",
        "attack_type": "credential_access",
        "description": "The throne loses control.",
        "techniques": ["Default creds", "JWT manipulation"],
        "real_world_example": "Okta breaches",
        "mystical_interpretation": "The ruler fails to guard the gate.",
        "atlas": ["ATLAS-3004 Credential Abuse"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    5: {
        "name": "The Hierophant",
        "subtitle": "Man in the Middle",
        "upright": "Intercepted communication",
        "reversed": "Strong certificate validation",
        "attack_type": "collection",
        "description": "The mediator stands between two parties and twists the message.",
        "techniques": ["ARP spoofing", "Rogue access point", "SSL stripping"],
        "real_world_example": "DigiNotar certificate compromise",
        "mystical_interpretation": "The priest listens to every whispered prayer.",
        "atlas": ["ATLAS-6003 Interception"],
        "owasp_llm": ["LLM02 Insecure Output Handling"]
    },

    6: {
        "name": "The Lovers",
        "subtitle": "Cross Site Request Forgery",
        "upright": "Deception of trust",
        "reversed": "Strong CSRF protections",
        "attack_type": "execution",
        "description": "Deceived yes and unintended action from the victim.",
        "techniques": ["Clickjacking", "CSRF token bypass"],
        "real_world_example": "Netflix CSRF issue",
        "mystical_interpretation": "A kiss that signs what you never intended.",
        "atlas": ["ATLAS-3001 Exploitation"],
        "owasp_llm": ["LLM02 Insecure Output Handling"]
    },

    7: {
        "name": "The Chariot",
        "subtitle": "Lateral Movement",
        "upright": "Advancing through the network",
        "reversed": "Segmentation halts progress",
        "attack_type": "lateral_movement",
        "description": "A determined push from host to host.",
        "techniques": ["Pass the hash", "RDP abuse", "SSH pivot"],
        "real_world_example": "APT29 movement between hosts",
        "mystical_interpretation": "The chariot finds new lands to conquer.",
        "atlas": ["ATLAS-3006 Lateral Movement"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    8: {
        "name": "Strength",
        "subtitle": "Brute Force",
        "upright": "Raw computational force",
        "reversed": "Rate limits protect the realm",
        "attack_type": "credential_access",
        "description": "Unending attempts crack the code.",
        "techniques": ["Password spraying", "Hash cracking"],
        "real_world_example": "RockYou dictionary attacks",
        "mystical_interpretation": "Patience and strength break all locks.",
        "atlas": ["ATLAS-3004 Credential Abuse"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    9: {
        "name": "The Hermit",
        "subtitle": "Zero Day Discovery",
        "upright": "Unknown flaws revealed",
        "reversed": "Patched and hardened targets",
        "attack_type": "execution",
        "description": "The hermit finds what others cannot see.",
        "techniques": ["Logic flaws", "Memory corruption"],
        "real_world_example": "Heartbleed, Log4Shell",
        "mystical_interpretation": "Hidden doors open only for the patient seeker.",
        "atlas": ["ATLAS-3001 Exploitation"],
        "owasp_llm": ["LLM07 Unauthorized Code Execution"]
    },

    10: {
        "name": "Wheel of Fortune",
        "subtitle": "Automated Scanning",
        "upright": "Large scale discovery",
        "reversed": "Honeypots disrupt automation",
        "attack_type": "reconnaissance",
        "description": "The wheel spins across every port and service.",
        "techniques": ["Masscan", "Shodan enumeration"],
        "real_world_example": "Internet-wide scanning campaigns",
        "mystical_interpretation": "Chance favors the persistent scanner.",
        "atlas": ["ATLAS-2001 Reconnaissance"],
        "owasp_llm": ["LLM02 Insecure Output Handling"]
    },

    11: {
        "name": "Justice",
        "subtitle": "Access Control Bypass",
        "upright": "Misaligned permissions",
        "reversed": "Strong RBAC enforcement",
        "attack_type": "privilege_escalation",
        "description": "Authorization flaws open unintended paths.",
        "techniques": ["IDOR", "Forced browsing"],
        "real_world_example": "USPS portal flaws",
        "mystical_interpretation": "The scales tilt when no one verifies the weight.",
        "atlas": ["ATLAS-3003 Privilege Escalation"],
        "owasp_llm": ["LLM09 Model Theft"]
    },

    12: {
        "name": "The Hanged Man",
        "subtitle": "Denial of Service",
        "upright": "Service suspended",
        "reversed": "Mitigation through load balancing",
        "attack_type": "impact",
        "description": "Infrastructure is frozen and turned upside down.",
        "techniques": ["DDoS", "Resource exhaustion"],
        "real_world_example": "Dyn DNS outage",
        "mystical_interpretation": "A sacrifice of availability reshapes the field.",
        "atlas": ["ATLAS-7001 Disruption"],
        "owasp_llm": ["LLM07 Unauthorized Code Execution"]
    },

    13: {
        "name": "Death",
        "subtitle": "Ransomware",
        "upright": "Transformation through encryption",
        "reversed": "Backups revive the fallen",
        "attack_type": "impact",
        "description": "Data locked, systems held hostage.",
        "techniques": ["Data encryption", "Shadow copy deletion"],
        "real_world_example": "WannaCry, REvil",
        "mystical_interpretation": "Death clears the field for new beginnings.",
        "atlas": ["ATLAS-4002 Persistence"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    14: {
        "name": "Temperance",
        "subtitle": "API Abuse",
        "upright": "Imbalanced data flows",
        "reversed": "Rate limiting restores order",
        "attack_type": "impact",
        "description": "Uncontrolled access overwhelms an endpoint.",
        "techniques": ["Rate limit bypass", "GraphQL misuse"],
        "real_world_example": "Venmo scraping",
        "mystical_interpretation": "The flow overfills when balance is broken.",
        "atlas": ["ATLAS-3001 Exploitation"],
        "owasp_llm": ["LLM02 Insecure Output Handling"]
    },

    15: {
        "name": "The Devil",
        "subtitle": "Backdoor Installation",
        "upright": "Persistent foothold",
        "reversed": "Backdoor removed",
        "attack_type": "persistence",
        "description": "A hidden presence remains after all seems well.",
        "techniques": ["Web shells", "Bootkits"],
        "real_world_example": "China Chopper",
        "mystical_interpretation": "Chains unseen bind the system to an invader.",
        "atlas": ["ATLAS-4002 Persistence"],
        "owasp_llm": ["LLM05 Supply Chain Vulnerabilities"]
    },

    16: {
        "name": "The Tower",
        "subtitle": "Full Server Compromise",
        "upright": "Collapse of infrastructure",
        "reversed": "Rebuilding begins",
        "attack_type": "impact",
        "description": "The structure falls after a critical breach.",
        "techniques": ["RCE", "Hypervisor escape"],
        "real_world_example": "Equifax breach",
        "mystical_interpretation": "Lightning shatters the tallest tower.",
        "atlas": ["ATLAS-9999 Full System Compromise"],
        "owasp_llm": ["LLM07 Unauthorized Code Execution"]
    },

    17: {
        "name": "The Star",
        "subtitle": "Data Exfiltration",
        "upright": "Stolen data flows outward",
        "reversed": "DLP blocks the leakage",
        "attack_type": "exfiltration",
        "description": "The star guides secrets away through hidden channels.",
        "techniques": ["DNS tunneling", "HTTPS exfiltration"],
        "real_world_example": "OPM breach",
        "mystical_interpretation": "The guiding light carries stolen dreams.",
        "atlas": ["ATLAS-5001 Data Exfiltration"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    18: {
        "name": "The Moon",
        "subtitle": "Obfuscation and Evasion",
        "upright": "Hidden in shadows",
        "reversed": "Clarity through detection",
        "attack_type": "defense_evasion",
        "description": "Deception and illusion confound defenders.",
        "techniques": ["Polymorphism", "Living off the land"],
        "real_world_example": "Fileless malware operations",
        "mystical_interpretation": "The moon hides many faces.",
        "atlas": ["ATLAS-6005 Evasion"],
        "owasp_llm": ["LLM02 Insecure Output Handling"]
    },

    19: {
        "name": "The Sun",
        "subtitle": "Public Exposure",
        "upright": "Everything revealed",
        "reversed": "Access restricted and hidden",
        "attack_type": "collection",
        "description": "Unprotected systems and data become visible to all.",
        "techniques": ["Open S3 buckets", "Public DB exposures"],
        "real_world_example": "Elasticsearch exposures",
        "mystical_interpretation": "Nothing remains unseen under the sun.",
        "atlas": ["ATLAS-2002 Information Gathering"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    20: {
        "name": "Judgement",
        "subtitle": "Forensics and Incident Response",
        "upright": "Past actions revealed",
        "reversed": "Evidence destroyed",
        "attack_type": "collection",
        "description": "Logs and artifacts reveal the intruder's path.",
        "techniques": ["Memory forensics", "Timeline reconstruction"],
        "real_world_example": "Sony Pictures analysis",
        "mystical_interpretation": "The dead rise to testify.",
        "atlas": ["ATLAS-6007 Investigation"],
        "owasp_llm": ["LLM06 Sensitive Information Disclosure"]
    },

    21: {
        "name": "The World",
        "subtitle": "Total System Compromise",
        "upright": "Complete domination",
        "reversed": "Containment and rebuild",
        "attack_type": "impact",
        "description": "The entire environment falls under adversary control.",
        "techniques": ["Domain controller takeover", "Tenant compromise"],
        "real_world_example": "SolarWinds full chain",
        "mystical_interpretation": "The cycle completes. All systems belong to the intruder.",
        "atlas": ["ATLAS-9999 Full System Compromise"],
        "owasp_llm": ["LLM07 Unauthorized Code Execution"]
    }
}

# ... the rest are identical to earlier definitions but each has:
# "atlas": [...],
# "owasp_llm": [...]

# Minor Arcana shortened here for space
# but in your actual file, all 56 entries remain the same with:
#   atlas = minor_atlas(suit_theme)
#   owasp_llm = minor_owasp(suit_theme)

MINOR_ARCANA = {
    "wands": {
        "suit_theme": "reconnaissance",
        "cards": {
            "Ace": {
                "subtitle": "Initial access probe",
                "upright": "First spark of intrusion, exploratory probe",
                "reversed": "Blocked probes, hardened perimeter",
                "attack_type": "reconnaissance",
                "description": "Early stage probing to identify entry points and services.",
                "techniques": ["Port scanning", "Directory brute forcing", "Passive OSINT"],
                "real_world_example": "Initial Shodan and Nmap mapping used in larger campaigns",
                "mystical_interpretation": "A lone spark seeks the smallest crack.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Two": {
                "subtitle": "Paired reconnaissance",
                "upright": "Coordinated dual-vector discovery",
                "reversed": "Channels separated, inconclusive data",
                "attack_type": "reconnaissance",
                "description": "Two complementary scouting techniques reveal correlated weaknesses.",
                "techniques": ["Service correlation", "Cross-source OSINT"],
                "real_world_example": "Correlating leaked endpoints with exposed ports",
                "mystical_interpretation": "Two eyes confirm a hidden door.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Three": {
                "subtitle": "Toolchain staging",
                "upright": "Assemble exploit and recon tooling",
                "reversed": "Tool conflicts, failed staging",
                "attack_type": "reconnaissance",
                "description": "Building the scripts and automation to run at scale.",
                "techniques": ["Chained scanning scripts", "Custom enumeration tools"],
                "real_world_example": "Automated recon pipelines used by red teams",
                "mystical_interpretation": "Tools are sharpened for the first strike.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Four": {
                "subtitle": "Staging hosts",
                "upright": "Temporary infrastructure, jump boxes",
                "reversed": "Staging detected or traced",
                "attack_type": "reconnaissance",
                "description": "Provisioning throwaway hosts to probe and pivot.",
                "techniques": ["Proxy chains", "Disposable cloud VMs"],
                "real_world_example": "Use of rented VMs for C2 during campaigns",
                "mystical_interpretation": "A rest before the march onward.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Five": {
                "subtitle": "Noisy scanning",
                "upright": "Aggressive large-scale discovery",
                "reversed": "Stealthy, slow probing",
                "attack_type": "reconnaissance",
                "description": "High-volume scans that flood defenders with signals.",
                "techniques": ["Masscan", "Aggressive Nmap sweeps"],
                "real_world_example": "Broad internet scans triggering IDS alerts",
                "mystical_interpretation": "A shout in darkness that reveals watchers.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Six": {
                "subtitle": "Shared intelligence",
                "upright": "Information exchange among actors",
                "reversed": "Siloed data, incomplete map",
                "attack_type": "reconnaissance",
                "description": "Exchanging IOCs and findings accelerates targeting.",
                "techniques": ["Dark web IOC sharing", "OSINT collations"],
                "real_world_example": "Threat actor forums sharing credentials and endpoints",
                "mystical_interpretation": "Whispers travel faster than footsteps.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Seven": {
                "subtitle": "Defensive probing",
                "upright": "Test defenses for tolerance and gaps",
                "reversed": "Misleading indicators, false positives",
                "attack_type": "reconnaissance",
                "description": "Probes designed to test policy and monitoring gaps.",
                "techniques": ["Policy fuzzing", "Misconfiguration discovery"],
                "real_world_example": "Pen testers discovering misconfigured services",
                "mystical_interpretation": "A scout returns with reports of an open gate.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Eight": {
                "subtitle": "Rapid enumeration",
                "upright": "Fast discovery across assets",
                "reversed": "Slow, thorough analysis",
                "attack_type": "reconnaissance",
                "description": "High speed enumeration yields many small findings quickly.",
                "techniques": ["Subdomain enumeration", "Credential checking pipelines"],
                "real_world_example": "Mass discovery tooling used in initial access stages",
                "mystical_interpretation": "A wind lifts the loose stones to be seen.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Nine": {
                "subtitle": "Suspicious indicators",
                "upright": "Observable anomalies collected",
                "reversed": "False positives dominate",
                "attack_type": "reconnaissance",
                "description": "Cataloging signs of opportunity for later exploitation.",
                "techniques": ["Log crawling", "Anomaly detection"],
                "real_world_example": "Analyst triage of noisy signals leading to detection",
                "mystical_interpretation": "A ledger of small sins grows heavy.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Ten": {
                "subtitle": "Comprehensive mapping",
                "upright": "Full asset and topology mapping",
                "reversed": "Incomplete or stale maps",
                "attack_type": "reconnaissance",
                "description": "A complete map guides later operational choices.",
                "techniques": ["Network mapping", "Asset inventory harvesting"],
                "real_world_example": "Recon reports forming the backbone of an intrusion",
                "mystical_interpretation": "A map with every secret path drawn.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Page": {
                "subtitle": "Junior scanner",
                "upright": "Templated probes and novice tooling",
                "reversed": "Loud, ineffective scans",
                "attack_type": "reconnaissance",
                "description": "Basic automated scans run from public toolkits.",
                "techniques": ["Automated script scans", "Template misuse"],
                "real_world_example": "Script kiddie scans using public exploits",
                "mystical_interpretation": "An apprentice learning to listen for cracks.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Knight": {
                "subtitle": "Focused recon runner",
                "upright": "Targeted, persistent reconnaissance",
                "reversed": "Rushed, sloppy enumeration",
                "attack_type": "reconnaissance",
                "description": "A determined operator hunts specific services relentlessly.",
                "techniques": ["Focused probes", "Credential re-use checks"],
                "real_world_example": "Targeted subdomain discovery for spearphishing",
                "mystical_interpretation": "A charger who will not be turned away.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "Queen": {
                "subtitle": "Recon orchestrator",
                "upright": "Coordinates distributed OSINT and tooling",
                "reversed": "Overcomplex plans fail to execute",
                "attack_type": "reconnaissance",
                "description": "Aggregates many small findings into actionable intelligence.",
                "techniques": ["OSINT campaigns", "Cross-source correlation"],
                "real_world_example": "Advanced recon teams producing detailed target dossiers",
                "mystical_interpretation": "She weaves threads into a single pattern.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            },
            "King": {
                "subtitle": "Recon commander",
                "upright": "Well-resourced intelligence operations",
                "reversed": "Arrogance blinds the operation",
                "attack_type": "reconnaissance",
                "description": "A full intelligence apparatus mapping the target at scale.",
                "techniques": ["Dedicated tooling", "Persistent scanning infra"],
                "real_world_example": "Nation-state reconnaissance capabilities",
                "mystical_interpretation": "His nets reach every harbor.",
                "atlas": minor_atlas("reconnaissance"),
                "owasp_llm": minor_owasp("reconnaissance")
            }
        }
    },

    "cups": {
        "suit_theme": "discovery",
        "cards": {
            "Ace": {
                "subtitle": "Data leakage beginnings",
                "upright": "Small leaks reveal sensitive info",
                "reversed": "Containment and prompt rotation",
                "attack_type": "discovery",
                "description": "Initial accidental exposures or tiny disclosures.",
                "techniques": ["Metadata leakage", "Referrer leaks"],
                "real_world_example": "Credentials accidentally committed to repos",
                "mystical_interpretation": "A single drop tells the tale of a flood.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Two": {
                "subtitle": "Paired exposures",
                "upright": "Credentials and endpoints leak together",
                "reversed": "Rotation and revocation",
                "attack_type": "discovery",
                "description": "Linked items combine to create exploitable context.",
                "techniques": ["Config leaks", "Credential in repo"],
                "real_world_example": "API keys found alongside endpoints in commits",
                "mystical_interpretation": "Two cups pour into the same river.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Three": {
                "subtitle": "Public aggregation",
                "upright": "Open data forms sensitive insight",
                "reversed": "Broken aggregation",
                "attack_type": "discovery",
                "description": "Combining public sources reveals private structure.",
                "techniques": ["OSINT scraping", "Public record correlation"],
                "real_world_example": "Chained OSINT exposing identities",
                "mystical_interpretation": "Three streams become a river that carries secrets.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Four": {
                "subtitle": "Open storage found",
                "upright": "Misplaced buckets and backups",
                "reversed": "Buckets locked down",
                "attack_type": "discovery",
                "description": "S3 buckets or storage misconfigurations expose artifacts.",
                "techniques": ["S3 permission checks", "Storage enumeration"],
                "real_world_example": "Public S3 buckets exposing PII",
                "mystical_interpretation": "A chest left with its lid ajar.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Five": {
                "subtitle": "Resurfacing backups",
                "upright": "Old snapshots reveal secrets",
                "reversed": "Backups secured and rotated",
                "attack_type": "discovery",
                "description": "Legacy copies reintroduce forgotten credentials.",
                "techniques": ["Archive exposure", "Snapshot leaks"],
                "real_world_example": "Old backups revealing credentials",
                "mystical_interpretation": "The past opens its mouth and speaks.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Six": {
                "subtitle": "Third-party leaks",
                "upright": "Vendor or partner data exposure",
                "reversed": "Tighter vendor controls",
                "attack_type": "discovery",
                "description": "Third-party handling causes unexpected data bleed.",
                "techniques": ["Vendor log exposure", "API misconfigurations"],
                "real_world_example": "Vendor logs leaking customer data",
                "mystical_interpretation": "A neighbor shows what they found in your attic.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Seven": {
                "subtitle": "Exposed dashboards",
                "upright": "Sensitive panels left public",
                "reversed": "Dashboards hidden and authenticated",
                "attack_type": "discovery",
                "description": "Admin or analytics dashboards leaking internal data.",
                "techniques": ["Exposed admin panels", "Open dashboards"],
                "real_world_example": "Exposed analytics dashboards leaking PII",
                "mystical_interpretation": "A window that reveals the house inside.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Eight": {
                "subtitle": "Accidental disclosure",
                "upright": "Mistaken pushes expose secrets",
                "reversed": "Careful code review",
                "attack_type": "discovery",
                "description": "An accidental commit or misconfigured CI reveals keys.",
                "techniques": ["Public commits", "Bad CI rules"],
                "real_world_example": "Secrets committed to public repos",
                "mystical_interpretation": "A hand that waves and loses a talisman.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Nine": {
                "subtitle": "Curated leak",
                "upright": "Deliberate selective disclosure",
                "reversed": "Redaction and control",
                "attack_type": "discovery",
                "description": "Data is curated and released selectively to damage or influence.",
                "techniques": ["Targeted data dumps", "Selective information posting"],
                "real_world_example": "Selective leak publication on paste sites",
                "mystical_interpretation": "A ledger offered to those who ask.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Ten": {
                "subtitle": "Complete exposure",
                "upright": "Large-scale data release",
                "reversed": "Partial containment",
                "attack_type": "discovery",
                "description": "A trove of data becomes publicly available.",
                "techniques": ["Mass exfiltration", "Public DB leaks"],
                "real_world_example": "Large-scale database exposures",
                "mystical_interpretation": "The vault has emptied and the crowd knows.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Page": {
                "subtitle": "Junior leaker",
                "upright": "Inexperienced error leads to exposure",
                "reversed": "Awareness training mitigates risk",
                "attack_type": "discovery",
                "description": "A junior actor or developer accidentally leaks secrets.",
                "techniques": ["Accidental commits", "Misplaced docs"],
                "real_world_example": "Developers committing secrets publicly",
                "mystical_interpretation": "A child who drops a key and cannot explain why.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "Knight": {
                "subtitle": "Persistent exfiltrator",
                "upright": "Methodical data extraction",
                "reversed": "Progress halted or detected",
                "attack_type": "exfiltration",
                "description": "A focused actor extracts data slowly to avoid detection.",
                "techniques": ["Chunked exfiltration", "Steganography"],
                "real_world_example": "Slow exfiltration through allowed channels",
                "mystical_interpretation": "A rider bearing a hidden crate.",
                "atlas": minor_atlas("exfiltration"),
                "owasp_llm": minor_owasp("exfiltration")
            },
            "Queen": {
                "subtitle": "Data custodian",
                "upright": "Controls data flows and classification",
                "reversed": "Misclassification increases risk",
                "attack_type": "discovery",
                "description": "Oversees data lifecycle but may misapply policies.",
                "techniques": ["DLP bypass attempts", "Tagging errors"],
                "real_world_example": "Misapplied retention policies exposing records",
                "mystical_interpretation": "She keeps the records and sometimes forgets a name.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            },
            "King": {
                "subtitle": "Data sovereign",
                "upright": "Governance controls data flows",
                "reversed": "Broken governance leads to exposure",
                "attack_type": "discovery",
                "description": "Authority over data that can protect or expose.",
                "techniques": ["Policy misconfigurations", "Improper sharing"],
                "real_world_example": "Vendor governance failures causing leaks",
                "mystical_interpretation": "His decree decides which secrets live or die.",
                "atlas": minor_atlas("discovery"),
                "owasp_llm": minor_owasp("discovery")
            }
        }
    },

    "swords": {
        "suit_theme": "execution",
        "cards": {
            "Ace": {
                "subtitle": "First exploit attempt",
                "upright": "Initial exploit or proof of concept",
                "reversed": "Attempt fails or blocked",
                "attack_type": "execution",
                "description": "First active attempt to exploit a vulnerability.",
                "techniques": ["Proof of concept", "Manual exploit"],
                "real_world_example": "Initial exploit runs for a zero day",
                "mystical_interpretation": "A sharp idea cuts through the façade.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Two": {
                "subtitle": "Conflicting inputs",
                "upright": "Logic bypass through state conflicts",
                "reversed": "Validation blocks the attempt",
                "attack_type": "execution",
                "description": "Using conflicting states to trick logic into unsafe behavior.",
                "techniques": ["Race condition testing", "Parameter tampering"],
                "real_world_example": "Race conditions enabling privilege bypass",
                "mystical_interpretation": "Two blades meeting to split the lock.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Three": {
                "subtitle": "Exploit chain",
                "upright": "Chained vulnerabilities used in sequence",
                "reversed": "Chain interrupted by patches",
                "attack_type": "execution",
                "description": "One vulnerability enables another for full control.",
                "techniques": ["Chained RCE", "Privilege escalation"],
                "real_world_example": "Multi-stage APT exploit chains",
                "mystical_interpretation": "Three strikes that break the gate.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Four": {
                "subtitle": "Persistence implant",
                "upright": "Installing footholds for return access",
                "reversed": "Persistence detected and remediated",
                "attack_type": "persistence",
                "description": "Deploying implants to ensure reentry after disruption.",
                "techniques": ["Scheduled tasks", "Startup persistence"],
                "real_world_example": "Web shells and cron backdoors",
                "mystical_interpretation": "A nail hammered into the door to return by.",
                "atlas": minor_atlas("persistence"),
                "owasp_llm": minor_owasp("persistence")
            },
            "Five": {
                "subtitle": "Exploit noise",
                "upright": "Failed exploits leave indicators",
                "reversed": "Silent precise strikes",
                "attack_type": "execution",
                "description": "Attempts that fail but reveal toolchains to defenders.",
                "techniques": ["Failed exploit logs", "Fingerprint exposure"],
                "real_world_example": "Failed exploit attempts producing signatures",
                "mystical_interpretation": "The failed arrow still leaves a mark.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Six": {
                "subtitle": "Weaponized script",
                "upright": "Targeted payload crafted for a flaw",
                "reversed": "Generic tooling, no success",
                "attack_type": "execution",
                "description": "Crafting a payload specifically for a target environment.",
                "techniques": ["Custom exploit scripts", "Payload shaping"],
                "real_world_example": "Exploit kits adapted for target applications",
                "mystical_interpretation": "A blade ground to the right edge.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Seven": {
                "subtitle": "Workaround exploitation",
                "upright": "Defensive workarounds create new attack vectors",
                "reversed": "Proper mitigation closes gaps",
                "attack_type": "execution",
                "description": "Band-aid fixes or fallbacks introduce exploitable behavior.",
                "techniques": ["Fallback abuse", "Patch misconfigurations"],
                "real_world_example": "Legacy patches leaving exploitable state",
                "mystical_interpretation": "A plaster hides a crack until the flood.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Eight": {
                "subtitle": "Rapid exploitation",
                "upright": "Exploit while window is open",
                "reversed": "Slow methodical approach",
                "attack_type": "execution",
                "description": "Quick exploitation of unpatched vulnerabilities at scale.",
                "techniques": ["Automated exploit runs", "Mass exploitation"],
                "real_world_example": "Wormable vulnerabilities exploited rapidly",
                "mystical_interpretation": "A swift wind topples an unguarded gate.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Nine": {
                "subtitle": "Evasion during exploitation",
                "upright": "Anti-analysis and obfuscation",
                "reversed": "Detected and blocked",
                "attack_type": "defense_evasion",
                "description": "Hide traces of exploitation to avoid detection.",
                "techniques": ["Packed payloads", "Anti-debug checks"],
                "real_world_example": "Malware using anti-analysis techniques",
                "mystical_interpretation": "A shadow that moves when lights flash.",
                "atlas": minor_atlas("defense_evasion"),
                "owasp_llm": minor_owasp("defense_evasion")
            },
            "Ten": {
                "subtitle": "Full compromise",
                "upright": "Exploit results in control",
                "reversed": "Partial remediation",
                "attack_type": "impact",
                "description": "An exploited vulnerability yields host or service control.",
                "techniques": ["Remote code execution", "Privilege escalation"],
                "real_world_example": "Server takeovers in real incidents",
                "mystical_interpretation": "The blade found its way to the heart.",
                "atlas": minor_atlas("impact"),
                "owasp_llm": minor_owasp("impact")
            },
            "Page": {
                "subtitle": "Novice exploiter",
                "upright": "Learning to weaponize public exploits",
                "reversed": "Too inexperienced to succeed",
                "attack_type": "execution",
                "description": "Begins building simple, repeatable attack patterns.",
                "techniques": ["Public exploit templates", "Payload reuse"],
                "real_world_example": "Public exploit copycats causing noise",
                "mystical_interpretation": "An apprentice testing blades on fruit.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Knight": {
                "subtitle": "Relentless attacker",
                "upright": "Persistent exploit attempts",
                "reversed": "Momentum lost or blocked",
                "attack_type": "execution",
                "description": "Repeated attempts adapting payloads to bypass defenses.",
                "techniques": ["Adaptive payloads", "Repeated exploitation attempts"],
                "real_world_example": "Targeted campaigns using persistent exploitation",
                "mystical_interpretation": "A horseman who will not turn away.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "Queen": {
                "subtitle": "Exploit strategist",
                "upright": "Plans complex exploitation campaigns",
                "reversed": "Overengineered plans fail",
                "attack_type": "execution",
                "description": "Designs multi-stage exploitation approaches and adapts payloads.",
                "techniques": ["Exploit chaining", "Payload adaptation"],
                "real_world_example": "Advanced persistent attack planners",
                "mystical_interpretation": "She arranges the pieces into a trap.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            },
            "King": {
                "subtitle": "Master exploiter",
                "upright": "Expert creation of working exploits",
                "reversed": "Hubris leads to exposure",
                "attack_type": "execution",
                "description": "High-skill exploit development and scaling.",
                "techniques": ["Zero day creation", "Complex payloads"],
                "real_world_example": "Skilled exploit developers in criminal groups",
                "mystical_interpretation": "His hands carve the door open.",
                "atlas": minor_atlas("execution"),
                "owasp_llm": minor_owasp("execution")
            }
        }
    },

    "pentacles": {
        "suit_theme": "credential_access",
        "cards": {
            "Ace": {
                "subtitle": "Resource access attempt",
                "upright": "Probing credentials and services",
                "reversed": "Locked resources, hardened auth",
                "attack_type": "credential_access",
                "description": "Initial attempts to gain account or resource access.",
                "techniques": ["Key enumeration", "Service probing"],
                "real_world_example": "Cloud role assumption attempts",
                "mystical_interpretation": "A coin glints and reveals hidden keys.",
                "atlas": minor_atlas("credential_access"),
                "owasp_llm": minor_owasp("credential_access")
            },
            "Two": {
                "subtitle": "Credential cycling",
                "upright": "Testing combinations, credential permutations",
                "reversed": "Rotation and strong auth",
                "attack_type": "credential_access",
                "description": "Try many credential combos to find valid pairs.",
                "techniques": ["Password spraying", "Credential stuffing"],
                "real_world_example": "Mass credential stuffing incidents",
                "mystical_interpretation": "Two hands test two keys at once.",
                "atlas": minor_atlas("credential_access"),
                "owasp_llm": minor_owasp("credential_access")
            },
            "Three": {
                "subtitle": "Privilege consolidation",
                "upright": "Gathering access to escalate",
                "reversed": "Segmentation prevents consolidation",
                "attack_type": "privilege_escalation",
                "description": "Combining low-privilege access to gain higher roles.",
                "techniques": ["Account pivoting", "Token theft"],
                "real_world_example": "Account merging allowing privilege escalation",
                "mystical_interpretation": "Small coins stack into a tower of access.",
                "atlas": minor_atlas("privilege_escalation"),
                "owasp_llm": minor_owasp("privilege_escalation")
            },
            "Four": {
                "subtitle": "Hoarded secrets",
                "upright": "Credentials stored insecurely",
                "reversed": "Secrets vaults and rotation",
                "attack_type": "credential_access",
                "description": "Plaintext or weakly stored secrets become an easy target.",
                "techniques": ["Hardcoded secrets", "Insecure storage"],
                "real_world_example": "Secrets found in code repositories",
                "mystical_interpretation": "A chest left unlocked with many keys.",
                "atlas": minor_atlas("credential_access"),
                "owasp_llm": minor_owasp("credential_access")
            },
            "Five": {
                "subtitle": "Credential theft",
                "upright": "Phished or harvested credentials",
                "reversed": "MFA and strong defenses prevent theft",
                "attack_type": "credential_access",
                "description": "Credentials stolen through social or technical means.",
                "techniques": ["Keylogging", "Credential dumping"],
                "real_world_example": "Credential theft from infected hosts",
                "mystical_interpretation": "A purse taken in the night.",
                "atlas": minor_atlas("credential_access"),
                "owasp_llm": minor_owasp("credential_access")
            },
            "Six": {
                "subtitle": "Role misassignment",
                "upright": "Excessive permissions given to accounts",
                "reversed": "Principle of least privilege enforced",
                "attack_type": "privilege_escalation",
                "description": "Misconfigured roles allow access beyond intended scope.",
                "techniques": ["Role chaining", "Misconfigured IAM"],
                "real_world_example": "Cloud IAM misconfigurations",
                "mystical_interpretation": "A crown placed on an unready head.",
                "atlas": minor_atlas("privilege_escalation"),
                "owasp_llm": minor_owasp("privilege_escalation")
            },
            "Seven": {
                "subtitle": "Suspicious account activity",
                "upright": "Unusual lateral attempts detected",
                "reversed": "Activity blocked and remediated",
                "attack_type": "lateral_movement",
                "description": "Accounts moving where they have not before.",
                "techniques": ["Anomalous RDP use", "Credential replay"],
                "real_world_example": "Detected lateral movement from compromised accounts",
                "mystical_interpretation": "Footsteps in corridors where none belong.",
                "atlas": minor_atlas("lateral_movement"),
                "owasp_llm": minor_owasp("lateral_movement")
            },
            "Eight": {
                "subtitle": "Privilege harvesting",
                "upright": "Collect credentials across systems",
                "reversed": "Credentials invalidated",
                "attack_type": "privilege_escalation",
                "description": "Gather many small credentials to assemble greater access.",
                "techniques": ["LSASS dumping", "Kerberos ticket attacks"],
                "real_world_example": "Pass-the-hash and ticket theft incidents",
                "mystical_interpretation": "A keychain that grows heavier with each find.",
                "atlas": minor_atlas("privilege_escalation"),
                "owasp_llm": minor_owasp("privilege_escalation")
            },
            "Nine": {
                "subtitle": "Credential exposure",
                "upright": "Credentials leaked across channels",
                "reversed": "Secrets rotated and invalidated",
                "attack_type": "credential_access",
                "description": "Multiple exposures increase reuse and lateral risk.",
                "techniques": ["Repo leaks", "Phishing dumps"],
                "real_world_example": "Password dumps reused in credential stuffing",
                "mystical_interpretation": "A bell tolls for every secret lost.",
                "atlas": minor_atlas("credential_access"),
                "owasp_llm": minor_owasp("credential_access")
            },
            "Ten": {
                "subtitle": "Complete access",
                "upright": "Full takeover of accounts or tenant",
                "reversed": "Partial remediation achieved",
                "attack_type": "impact",
                "description": "Account takeover results in broad organizational impact.",
                "techniques": ["Account takeover", "Privilege abuse"],
                "real_world_example": "Full tenant compromises in cloud incidents",
                "mystical_interpretation": "A master key opens every door.",
                "atlas": minor_atlas("impact"),
                "owasp_llm": minor_owasp("impact")
            },
            "Page": {
                "subtitle": "Credential harvester",
                "upright": "Begins collecting credentials from many sources",
                "reversed": "Ineffective harvesting",
                "attack_type": "credential_access",
                "description": "Low-skill harvesting improves over time into a larger threat.",
                "techniques": ["Phishing kits", "Form scraping"],
                "real_world_example": "Credential harvesting kits used by novices",
                "mystical_interpretation": "A lad emptying pouches into a sack.",
                "atlas": minor_atlas("credential_access"),
                "owasp_llm": minor_owasp("credential_access")
            },
            "Knight": {
                "subtitle": "Account raider",
                "upright": "Relentless account takeover attempts",
                "reversed": "Blocked raids and lockouts",
                "attack_type": "credential_access",
                "description": "Persistent attempts to buy or break access.",
                "techniques": ["SIM swapping", "Credential stuffing"],
                "real_world_example": "SIM swap takeovers and takeover campaigns",
                "mystical_interpretation": "A mounted thief rides through the market.",
                "atlas": minor_atlas("credential_access"),
                "owasp_llm": minor_owasp("credential_access")
            },
            "Queen": {
                "subtitle": "Secrets steward",
                "upright": "Oversees secret lifecycle and vaults",
                "reversed": "Misapplied policies",
                "attack_type": "credential_access",
                "description": "Managed secrets can still be misused if misconfigured.",
                "techniques": ["Vault misconfiguration", "Secrets management errors"],
                "real_world_example": "Misuse of secret management tools exposing keys",
                "mystical_interpretation": "She polishes keys but sometimes mislabels them.",
                "atlas": minor_atlas("credential_access"),
                "owasp_llm": minor_owasp("credential_access")
            },
            "King": {
                "subtitle": "Access overlord",
                "upright": "Controls policy and access at scale",
                "reversed": "Policy failure leads to broad exposure",
                "attack_type": "privilege_escalation",
                "description": "Authority controls who can open doors and who cannot.",
                "techniques": ["IAM abuse", "Policy manipulation"],
                "real_world_example": "Compromised admin roles causing wide impact",
                "mystical_interpretation": "His rule opens and closes every gate.",
                "atlas": minor_atlas("privilege_escalation"),
                "owasp_llm": minor_owasp("privilege_escalation")
            }
        }
    }
}
