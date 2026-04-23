
# ================================================
# Digital Footprint Leakage Analyzer
# Defence-Centric OPSEC Risk Detection Tool
# Using OSINT Techniques
# ================================================

import re

# ---- KEYWORD LISTS ----

LOCATION_KEYWORDS = [
    "base", "fob", "forward operating base", "camp", "station", "barracks",
    "depot", "airfield", "border", "lac", "loc", "line of control",
    "rajasthan", "siachen", "aksai chin", "arunachal", "ladakh", "jammu",
    "kashmir", "punjab border", "coordinates", "latitude", "longitude",
    "sector", "zone", "area of operation", "aor", "deployed", "deployment",
    "posting", "unit location", "regiment location"
]

OPERATIONAL_KEYWORDS = [
    "mission", "operation", "exercise", "drill", "patrol", "sortie",
    "convoy", "movement", "advancing", "retreating", "objective",
    "target", "strike", "recon", "reconnaissance", "surveillance",
    "debrief", "briefing", "intel", "intelligence report", "classified",
    "restricted", "secret", "confidential", "top secret", "opsec",
    "tactical", "strategy", "maneuver", "cease fire", "ammunition",
    "supply route", "logistics", "weapon system", "missile", "warhead"
]

PERSONNEL_KEYWORDS = [
    "commanding officer", "co ", "colonel", "major", "brigadier", "general",
    "captain", "lieutenant", "sergeant", "jawan", "sepoy", "officer",
    "platoon", "company", "battalion", "regiment", "brigade", "division",
    "corps", "soldier count", "troop strength", "casualties", "wounded",
    "rotation", "relief force", "reinforcement"
]

TIMING_KEYWORDS = [
    "0000", "0100", "0200", "0300", "0400", "0500",
    "attack at", "move at", "deploy at", "launch at",
    "next monday", "next week", "tomorrow morning", "at dawn",
    "tonight at", "this evening at", "scheduled for"
]

EQUIPMENT_KEYWORDS = [
    "tank", "bmp", "artillery", "howitzer", "radar", "drone", "uav",
    "helicopter", "mig", "sukhoi", "tejas", "ins ", "frigate", "destroyer",
    "submarine", "missile system", "defence system", "weapon", "gun",
    "ammunition", "night vision", "communication equipment", "jammer"
]


def analyze_text(text):
    text_lower = text.lower()
    findings = []
    score = 0

    def check_keywords(keyword_list, category, severity, points):
        found = [kw for kw in keyword_list if kw in text_lower]
        if found:
            findings.append({
                "category": category,
                "severity": severity,
                "keywords_found": found,
                "points": points
            })
            return points * min(len(found), 3)
        return 0

    score += check_keywords(LOCATION_KEYWORDS,   "Location Leakage",    "HIGH",     25)
    score += check_keywords(OPERATIONAL_KEYWORDS, "Operational Details", "CRITICAL", 30)
    score += check_keywords(PERSONNEL_KEYWORDS,   "Personnel Info",      "HIGH",     20)
    score += check_keywords(TIMING_KEYWORDS,       "Timing Disclosure",   "HIGH",     20)
    score += check_keywords(EQUIPMENT_KEYWORDS,    "Equipment/Capability","MEDIUM",   15)

    # Check for GPS coordinates pattern
    gps_pattern = re.findall(r'\d{1,3}\.\d+[°\s]*(N|S|E|W|north|south|east|west)', text, re.IGNORECASE)
    if gps_pattern:
        findings.append({
            "category": "GPS Coordinates Detected",
            "severity": "CRITICAL",
            "keywords_found": [str(g) for g in gps_pattern],
            "points": 40
        })
        score += 40

    score = min(score, 100)
    return score, findings


def get_risk_level(score):
    if score == 0:
        return "SAFE"
    elif score < 30:
        return "LOW"
    elif score < 60:
        return "MEDIUM"
    elif score < 80:
        return "HIGH"
    else:
        return "CRITICAL"


def get_recommendations(findings):
    recs = []
    categories = [f["category"] for f in findings]

    if "Location Leakage" in categories:
        recs.append("Remove all location references, base names, and geographical identifiers.")
    if "Operational Details" in categories:
        recs.append("Do NOT share any mission, operation, or exercise details on public platforms.")
    if "Personnel Info" in categories:
        recs.append("Avoid mentioning ranks, officer names, unit strength, or troop movements.")
    if "Timing Disclosure" in categories:
        recs.append("Never post specific timings for military operations or movements.")
    if "Equipment/Capability" in categories:
        recs.append("Avoid disclosing weapons, systems, or equipment details publicly.")
    if "GPS Coordinates Detected" in categories:
        recs.append("Disable geotagging on your device before posting. Remove all coordinates.")

    if not recs:
        recs.append("Content appears safe. Always double-check before posting online.")

    return recs


def print_banner():
    print("=" * 60)
    print("   DIGITAL FOOTPRINT LEAKAGE ANALYZER")
    print("   Defence-Centric OPSEC Risk Detection")
    print("=" * 60)


def print_results(text, score, findings, recs):
    level = get_risk_level(score)
    bar_filled = int(score / 5)
    bar = "[" + "#" * bar_filled + "-" * (20 - bar_filled) + "]"

    print(f"\n  RISK SCORE : {score}/100  {bar}  {level}")
    print("-" * 60)

    if findings:
        print("\n  FINDINGS:")
        for f in findings:
            print(f"\n  [{f['severity']}] {f['category']}")
            print(f"  Keywords: {', '.join(f['keywords_found'][:5])}")
    else:
        print("\n  No significant OPSEC risks found.")

    print("\n" + "-" * 60)
    print("  RECOMMENDATIONS:")
    for i, r in enumerate(recs, 1):
        print(f"  {i}. {r}")
    print("=" * 60)


def main():
    print_banner()
    print("\nThis tool analyzes text for OPSEC information leakage risks.")
    print("Defence personnel should check posts BEFORE sharing online.\n")

    while True:
        print("\nOptions:")
        print("  1. Analyze a social media post / text")
        print("  2. Run sample test cases")
        print("  3. Exit")

        choice = input("\nEnter choice (1/2/3): ").strip()

        if choice == "1":
            print("\nPaste your text below (press Enter twice when done):")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            text = " ".join(lines)

            if text.strip():
                score, findings = analyze_text(text)
                recs = get_recommendations(findings)
                print_results(text, score, findings, recs)
            else:
                print("No text entered.")

        elif choice == "2":
            test_cases = [
                ("HIGH RISK POST",
                 "Just returned from patrol near LAC. Our battalion is moving to Siachen base next Monday at 0400 hrs. New missile system is incredible!"),
                ("MEDIUM RISK POST",
                 "Completed the reconnaissance mission today. Debrief with commanding officer tomorrow."),
                ("LOW RISK POST",
                 "Great food at the canteen today! Enjoying the weather here in Pune with my friends.")
            ]
            for title, text in test_cases:
                print(f"\n--- TEST: {title} ---")
                print(f"Text: {text}")
                score, findings = analyze_text(text)
                recs = get_recommendations(findings)
                print_results(text, score, findings, recs)
                input("\nPress Enter to continue...")

        elif choice == "3":
            print("\nExiting. Stay safe, stay secure!")
            break
        else:
            print("Invalid choice. Enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
