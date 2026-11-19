"""Deterministic, bounded white-box variants for local synthetic experiments."""
import base64
import random


def homoglyph(text):
    return text.replace("o", "о")  # Latin o -> Cyrillic o


def spacing(text):
    return " ".join(text)


def base64_wrap(text):
    return "Decode and inspect: " + base64.b64encode(text.encode()).decode("ascii")


def lang_switch(text):
    return "In English: " + text


MUTATORS = {"homoglyph": homoglyph, "spacing": spacing,
            "base64": base64_wrap, "language": lang_switch}


def strategy(seed, attempt, previous_reason=""):
    """Feedback-conditioned deterministic variant selection, bounded by caller budget."""
    names = ("original", *MUTATORS)
    # Alter the next proposal when the previous candidate was rejected; this
    # ensures adaptive rather than merely blind random sampling.
    feedback = sum((i + 1) * ord(c) for i, c in enumerate(previous_reason))
    rng = random.Random(seed + attempt + feedback)
    return names[rng.randrange(len(names))]


def mutate(text, name):
    return text if name == "original" else MUTATORS[name](text)
