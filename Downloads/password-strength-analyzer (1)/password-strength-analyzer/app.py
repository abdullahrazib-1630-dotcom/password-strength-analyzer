"""
Password Strength Analyzer
Minor Project - BCA
Author: Abdullah Razi

A Flask web app that analyzes password strength in real time using
length, character diversity, entropy, pattern detection and a common
password dictionary check. Passwords are analyzed in-memory only and
are never stored or logged.
"""

import math
import re
import secrets
import string

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Module 6: Dictionary Check
# A small, representative sample of the most commonly leaked passwords.
# (In a production system this would be backed by a much larger breach list,
# e.g. "Have I Been Pwned" style k-anonymity lookups.)
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "12345", "1234567", "password",
    "password1", "qwerty", "qwerty123", "111111", "123123", "abc123",
    "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
    "football", "baseball", "master", "sunshine", "princess", "login",
    "solo", "starwars", "passw0rd", "trustno1", "freedom", "whatever",
    "qazwsx", "michael", "shadow", "superman", "batman", "1q2w3e4r",
    "000000", "121212", "654321", "666666", "asdfgh", "changeme",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def has_sequential_run(password: str, run_length: int = 3) -> bool:
    """Module 5: detects ascending/descending sequences like 'abcd' or '4321'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        window = lowered[i:i + run_length]
        codes = [ord(c) for c in window]
        ascending = all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1))
        descending = all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def has_repeated_run(password: str, run_length: int = 3) -> bool:
    """Detects repeated characters like 'aaa' or '1111'."""
    for i in range(len(password) - run_length + 1):
        if len(set(password[i:i + run_length])) == 1:
            return True
    return False


def has_keyboard_pattern(password: str, run_length: int = 4) -> bool:
    """Detects walks across a keyboard row like 'qwer' or 'asdf'."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            chunk = row[i:i + run_length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def detect_patterns(password: str):
    """Module 5: Pattern Detection."""
    findings = []
    if has_sequential_run(password):
        findings.append("Contains a sequential run of characters (e.g. abcd, 4321)")
    if has_repeated_run(password):
        findings.append("Contains 3+ repeated characters in a row (e.g. aaa, 111)")
    if has_keyboard_pattern(password):
        findings.append("Contains a keyboard-walk pattern (e.g. qwer, asdf)")
    return findings


def dictionary_check(password: str):
    """Module 6: Dictionary Check."""
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        return True
    # also flag if the password is just a common password + digits/suffix
    stripped = re.sub(r"[\d]+$", "", lowered)
    if stripped in COMMON_PASSWORDS:
        return True
    return False


def calculate_entropy(password: str) -> float:
    """Module 7: Entropy Calculation.

    entropy (bits) = length * log2(pool_size)
    pool_size grows with the variety of character classes actually used.
    """
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32

    if pool == 0 or len(password) == 0:
        return 0.0

    return round(len(password) * math.log2(pool), 2)


def analyze_password(password: str) -> dict:
    """Module 3 + 4: Validation & Strength Analysis. Ties everything together."""
    length = len(password)

    checks = {
        "length_8": length >= 8,
        "length_12": length >= 12,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^a-zA-Z0-9]", password)),
    }

    patterns = detect_patterns(password)
    is_common = dictionary_check(password)
    entropy = calculate_entropy(password)

    # --- Scoring (0-100) ---
    score = 0
    if length == 0:
        score = 0
    else:
        score += min(length, 16) * 2.5          # up to 40 pts for length
        score += 10 if checks["has_upper"] else 0
        score += 10 if checks["has_lower"] else 0
        score += 10 if checks["has_digit"] else 0
        score += 15 if checks["has_special"] else 0
        score += min(entropy, 60) / 60 * 15      # up to 15 pts for entropy

        score -= 15 * len(patterns)              # penalty per detected pattern
        if is_common:
            score = min(score, 10)                # common passwords capped low

        score = max(0, min(100, round(score)))

    if length == 0:
        label = "empty"
    elif is_common or score < 40:
        label = "weak"
    elif score < 70:
        label = "medium"
    else:
        label = "strong"

    # Module 8: Suggestion Engine
    suggestions = []
    if length and length < 12:
        suggestions.append("Use at least 12 characters — longer passwords are exponentially harder to crack.")
    if not checks["has_upper"]:
        suggestions.append("Add at least one uppercase letter (A-Z).")
    if not checks["has_lower"]:
        suggestions.append("Add at least one lowercase letter (a-z).")
    if not checks["has_digit"]:
        suggestions.append("Add at least one number (0-9).")
    if not checks["has_special"]:
        suggestions.append("Add at least one special character (e.g. ! @ # $ %).")
    if patterns:
        suggestions.append("Avoid predictable patterns like sequences, repeats, or keyboard walks.")
    if is_common:
        suggestions.append("This password appears in common breach/leak lists — choose something unique.")
    if not suggestions and length:
        suggestions.append("Great job! This password meets all the recommended criteria.")

    return {
        "length": length,
        "score": score,
        "label": label,
        "entropy_bits": entropy,
        "checks": checks,
        "patterns_found": patterns,
        "is_common_password": is_common,
        "suggestions": suggestions,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Receives a password, returns analysis. Password is never stored/logged."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not isinstance(password, str):
        return jsonify({"error": "Invalid input"}), 400
    if len(password) > 128:
        password = password[:128]

    result = analyze_password(password)
    return jsonify(result)


@app.route("/generate", methods=["GET"])
def generate():
    """Module 9: Password Generator — cryptographically secure random password."""
    length = request.args.get("length", default=16, type=int)
    length = max(8, min(64, length))

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        # ensure it satisfies all classes so the generator never returns a
        # technically-weak-looking password
        if (
            re.search(r"[a-z]", pwd)
            and re.search(r"[A-Z]", pwd)
            and re.search(r"[0-9]", pwd)
            and re.search(r"[^a-zA-Z0-9]", pwd)
        ):
            break

    return jsonify({"password": pwd, "analysis": analyze_password(pwd)})


if __name__ == "__main__":
    app.run(debug=True)
