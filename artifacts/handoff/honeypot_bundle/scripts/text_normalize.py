#!/usr/bin/env python3
# =============================================================================
# PLAIN-ENGLISH SUMMARY  (read this first)
# =============================================================================
# WHAT THIS FILE IS:
#   A small shared helper -- one text-cleaning function, used by BOTH training
#   and the live app.
#
# WHY IT EXISTS:
#   An attacker can write an attack using look-alike characters. Instead of
#   the plain   1' OR '1'='1
#   they send   1' OR '1'='1   using full-width Unicode quotes and letters.
#   To a human it reads identically; to the model it is a string of characters
#   it has never seen, so detection failed. This function folds those look-alike
#   characters back to plain ASCII (Unicode NFKC normalisation) BEFORE any
#   feature is calculated, closing that evasion route.
#
# WHY IT MUST BE ONE SHARED FILE:
#   If training cleaned the text but the live app did not (or vice versa), the
#   model would be fed a different kind of input than it learned on, and
#   predictions would silently degrade. Keeping one copy makes that impossible.
# =============================================================================

"""
text_normalize.py  (Improvement Plan — Task 4)

ONE shared text-cleaning function, imported by BOTH the trainer
(18_train_stacked.py) and the live app (app.py). Keeping it in one place is
critical: if training normalises text but serving does not (or vice-versa),
predictions silently break.

Why it exists: the Unicode attack "１＇ ＯＲ ＇１＇＝＇１" evaded detection because
the model saw unfamiliar fullwidth/homoglyph characters. NFKC normalisation folds
those look-alikes back to plain ASCII before any feature is computed, so the
attack presents to the model the same way its ASCII twin does.

normalize_text() is deliberately conservative: it only folds character
*representations* (fullwidth forms, homoglyph quotes/dashes, compatibility
characters). It does NOT strip, lowercase, or reorder anything — those would
change the very features the detector relies on.
"""
import unicodedata

# Homoglyphs NFKC does not already fold to ASCII. Map the common ones a WAF
# evasion would use for quotes and dashes.
_HOMOGLYPHS = {
    "‘": "'", "’": "'", "‚": "'", "‛": "'",  # curly single quotes
    "′": "'", "ʹ": "'", "ʼ": "'", "՚": "'",  # prime / modifier apostrophes
    "“": '"', "”": '"', "„": '"', "″": '"',  # curly double quotes
    "–": "-", "—": "-", "−": "-", "‐": "-",  # dashes / minus
    "­": "-",                                                # soft hyphen
    "＂": '"', "＇": "'",                                # fullwidth quotes (belt+braces)
}
_TRANS = {ord(k): v for k, v in _HOMOGLYPHS.items()}


def normalize_text(text: str) -> str:
    """Fold Unicode look-alikes to their ASCII equivalents.

    NFKC handles fullwidth Latin (１ -> 1, Ｏ -> O, ＇ -> '), ligatures, and most
    compatibility forms; the homoglyph table cleans up quotes/dashes NFKC leaves
    alone. Nothing is removed, lowercased, or reordered.
    """
    if not isinstance(text, str):
        text = str(text)
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_TRANS)
    return text


if __name__ == "__main__":
    # tiny self-test
    for a, b in [
        ("１＇ ＯＲ ＇１＇＝＇１", "1' OR '1'='1"),
        ("adminʼ OR ʼ1ʼ=ʼ1", "admin' OR '1'='1"),
        ("1′ OR 1=1", "1' OR 1=1"),
        ("plain text stays", "plain text stays"),
    ]:
        got = normalize_text(a)
        print(f"{'ok ' if got == b else 'BAD'}  {a!r} -> {got!r}")
