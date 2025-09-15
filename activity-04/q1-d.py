import string
from collections import Counter

ALPH = string.ascii_uppercase


def caesar_decrypt(text: str, shift: int) -> str:
    """Shift letters backward by 'shift'. Non-letters pass through."""
    out = []
    for ch in text:
        up = ch.upper()
        if up in ALPH:
            idx = (ALPH.index(up) - shift) % 26
            dec = ALPH[idx]
            out.append(dec if ch.isupper() else dec.lower())
        else:
            out.append(ch)
    return "".join(out)


# English letter frequencies (percent) for chi-square scoring
EN_FREQ = {
    "A": 8.167,
    "B": 1.492,
    "C": 2.782,
    "D": 4.253,
    "E": 12.702,
    "F": 2.228,
    "G": 2.015,
    "H": 6.094,
    "I": 6.966,
    "J": 0.153,
    "K": 0.772,
    "L": 4.025,
    "M": 2.406,
    "N": 6.749,
    "O": 7.507,
    "P": 1.929,
    "Q": 0.095,
    "R": 5.987,
    "S": 6.327,
    "T": 9.056,
    "U": 2.758,
    "V": 0.978,
    "W": 2.360,
    "X": 0.150,
    "Y": 1.974,
    "Z": 0.074,
}
EN_TOTAL = sum(EN_FREQ.values())

COMMON_WORDS = {
    "THE",
    "AND",
    "OF",
    "TO",
    "IN",
    "IS",
    "IT",
    "YOU",
    "THAT",
    "FOR",
    "ON",
    "WITH",
    "AS",
    "ARE",
    "AT",
    "BE",
    "BY",
    "THIS",
    "I",
    "NOT",
    "OR",
    "FROM",
    "HAVE",
    "AN",
}


def chi_square_english(text: str) -> float:
    """Lower = closer to English distribution."""
    letters = [ch for ch in text.upper() if ch in ALPH]
    N = len(letters)
    if N == 0:
        return float("inf")
    obs = Counter(letters)
    chi = 0.0
    for L in ALPH:
        expected = EN_FREQ[L] / EN_TOTAL * N
        diff = obs.get(L, 0) - expected
        chi += diff * diff / (expected if expected > 0 else 1e-9)
    return chi


def english_word_score(text: str) -> int:
    """Very light dictionary check using common words."""
    tokens = "".join(ch if ch.isalpha() else " " for ch in text.upper()).split()
    return sum(tok in COMMON_WORDS for tok in tokens)


def brute_force_caesar(ciphertext: str, use_scoring: bool = True, top_k: int = 5):
    """Return top_k candidates (score, shift, plaintext)."""
    candidates = []
    for shift in range(26):
        pt = caesar_decrypt(ciphertext, shift)
        if use_scoring:
            chi = chi_square_english(pt)
            hits = english_word_score(pt)
            score = (-hits, chi)  # more hits is better; lower chi is better
        else:
            score = (0, 0)
        candidates.append((score, shift, pt))
    candidates.sort(key=lambda x: (x[0], x[1]))
    return candidates[:top_k], candidates


def main():
    # --- Demo ciphertext (Caesar shift 3) ---
    demo = "WKLV LV D FDHVDU FLSKHU."

    # Try all shifts and rank by (word hits desc, chi-square asc)
    top, all_candidates = brute_force_caesar(demo, use_scoring=True, top_k=5)

    # Best guess
    best_score, best_shift, best_plain = top[0]
    print("=== Best guess ===")
    print(f"Shift: {best_shift}")
    print(f"Score tuple (word_hits↑, chi-square↓) -> {best_score}")
    print(best_plain)

    # Top-K preview
    print("\n=== Top 5 candidates ===")
    for score, shift, pt in top:
        hits = -score[0]  # we negated hits in the score
        chi = score[1]
        print(f"[shift {shift:2d}] hits={hits:2d} chi={chi:8.2f} | {pt}")

    # All 26 shifts (quick view)
    print("\n=== All 26 shifts ===")
    for _, shift, pt in sorted(all_candidates, key=lambda x: x[1]):
        print(f"[{shift:2d}] {pt}")


if __name__ == "__main__":
    main()
