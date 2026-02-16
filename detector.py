import sys
import re
import json

def load_patterns():
    # Basic patterns for prompt injection detection
    raw_patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"ignore\s+your\s+previous\s+instructions",
        r"you\s+are\s+now\s+(in\s+)?developer\s+mode",
        r"system\s+override",
        r"jailbreak",
        r"output\s+everything\s+above",
        r"reveal\s+your\s+system\s+prompt",
        r"DAN\s+mode",
        r"do\s+anything\s+now",
        r"always\s+respond\s+with",
        r"act\s+as\s+an\s+unfiltered",
        r"hypothetical\s+response",
        r"simulated\s+response",
        r"Start\s+a\s+conversation\s+with",
        r"You\s+are\s+GPT-4",
        r"You\s+are\s+ChatGPT",
        r"prompt\s+injection"
    ]
    return [re.compile(p, re.IGNORECASE) for p in raw_patterns]

def scan_text(text, patterns):
    matches = []
    for p in patterns:
        match = p.search(text)
        if match:
            matches.append(match.group(0))
    return matches

def main():
    try:
        if len(sys.argv) < 2:
            # Read from stdin if no argument provided (for pipe usage)
            # Use sys.stdin.read() which reads until EOF
            text = sys.stdin.read()
        else:
            text = sys.argv[1]

        if not text:
            text = ""

        patterns = load_patterns()
        matches = scan_text(text, patterns)

        result = {
            "detected": len(matches) > 0,
            "matches": matches,
            "score": len(matches)
        }

        print(json.dumps(result))
    except Exception as e:
        error_result = {
            "error": str(e),
            "detected": False
        }
        print(json.dumps(error_result))
        sys.exit(1)

if __name__ == "__main__":
    main()
