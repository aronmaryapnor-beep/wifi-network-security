"""Passphrase strength estimator. The passphrase is read with getpass and is never
stored, logged or written to a report."""

import math
import string

COMMON = {
    "password", "123456", "12345678", "123456789", "qwerty", "abc123", "letmein",
    "welcome", "admin", "iloveyou", "monkey", "dragon", "football", "login",
    "wifi", "wifipassword", "internet", "router", "default", "changeme",
    "11111111", "00000000", "password1", "passw0rd", "qwertyuiop", "india123",
}
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm"]


def _pool_size(pw):
    pool = 0
    if any(c in string.ascii_lowercase for c in pw):
        pool += 26
    if any(c in string.ascii_uppercase for c in pw):
        pool += 26
    if any(c in string.digits for c in pw):
        pool += 10
    if any(c in string.punctuation for c in pw):
        pool += 32
    if any(c == " " for c in pw):
        pool += 1
    return pool or 1


def _has_sequence(pw, run=4):
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - run + 1):
                if s[i:i + run] in low:
                    return True
    return False


def evaluate(pw):
    issues = []
    length = len(pw)
    entropy = length * math.log2(_pool_size(pw))
    if length < 12:
        issues.append("Shorter than 12 characters.")
    if pw.lower() in COMMON or any(c in pw.lower() for c in COMMON if len(c) >= 6):
        issues.append("Contains a very common password or word.")
        entropy = min(entropy, 20)
    if len(set(pw)) <= max(3, length // 4):
        issues.append("Too many repeated characters.")
        entropy *= 0.5
    if _has_sequence(pw):
        issues.append("Contains an obvious keyboard/alphabet/number sequence.")
        entropy *= 0.7
    if pw.isdigit():
        issues.append("Only digits.")
    entropy = round(entropy, 1)
    if entropy >= 80 and length >= 16:
        rating = "Strong"
    elif entropy >= 60 and length >= 12:
        rating = "Good"
    elif entropy >= 40:
        rating = "Fair"
    else:
        rating = "Weak"
    return {"length": length, "entropy_bits": entropy, "rating": rating, "issues": issues}
