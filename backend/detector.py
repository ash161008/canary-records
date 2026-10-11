"""Canary and personal-data detector.

Pure functions. Nothing here makes a network call, writes a file, or decides
what happens next: it reports what it found, and the gateway decides.

Five jobs:

1. **Type-specific canonicalisation.** There is deliberately no single global
   normaliser. A phone is canonicalised as a phone, inside phone-shaped tokens
   only; an email is lowercased and trimmed; staff ids, API keys and contract
   numbers match exactly, case-insensitively; names collapse whitespace and
   lowercase. Normalising everything the same way would either miss
   "9 8 2 3 1 7 6 4" or match digits inside unrelated text.
2. **Bounded decoding.** ``decode_candidates`` looks one level deep for
   base64, hex and URL-encoded content, with hard caps so a hostile input
   cannot make detection expensive.
3. **Canary confidence**: STRONG, WEAK or NONE per registered decoy.
4. **Personal item extraction**, for the gateway's per-message and
   per-session limits.
5. **Owner lookup** by unique identifier only.

``scan(text)`` is the gateway's single entry point: it prepares the text once
and returns one ``ScanResult`` carrying the canary confidence, the matches,
the personal items, their count and the truncation flag. ``find_canaries``
and ``extract_personal`` remain available where only one half is wanted.

NONE does not mean the content is safe. It means no registered decoy was
found. Every other outbound policy still applies.

Only this module and ``backend/seeder.py`` may reach vault/registry.db.
"""

import base64
import binascii
import csv
import logging
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

from rapidfuzz import fuzz

from backend import config, database
from backend.models import Canary

logger = logging.getLogger(__name__)

# Confidence levels.
STRONG = "STRONG"
WEAK = "WEAK"
NONE = "NONE"

# Owner lookup outcome when an identifier matches more than one record.
AMBIGUOUS = "AMBIGUOUS"

# Value kinds, which decide how a value is matched.
KIND_EMAIL = "email"
KIND_PHONE = "phone"
KIND_IDENTIFIER = "identifier"
KIND_POSTAL = "postal_code"
KIND_AMOUNT = "amount"
KIND_NAME = "name"
KIND_TEXT = "text"

# Bounds on decoding, so a large or hostile input cannot make this expensive.
# The input cap is applied to the string's length in characters.
MAX_INPUT_BYTES = 200 * 1024
MAX_CANDIDATES = 50
MIN_BLOCK_CHARS = 16
MAX_BLOCK_CHARS = 4096

# Fuzzy name matching. Names are only ever weak evidence.
NAME_MATCH_THRESHOLD = 90

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# A phone-shaped token: an optional +65, then eight to eleven digits that may
# be separated by spaces, dashes, dots or brackets. Canonicalisation happens
# inside these tokens only, never across the whole text.
#
# Every quantifier here is bounded. An unbounded one (`\s*` before the 65, or
# `[\s.\-()]*` between digits) makes this pattern quadratic on long runs of
# whitespace: a hostile 200 KB message took 86 seconds before the bounds were
# added. Three separators is more than any real formatting needs.
#
# The digit count runs to 24, not 11, so that a number padded or prefixed with
# other digits is still captured as one token; ``phone_variants`` then picks
# the plausible eight-digit numbers out of it.
_PHONE_TOKEN = re.compile(r"(?:\+?[ ]{0,2}65[\s.\-()]{0,3})?(?:\d[\s.\-()]{0,3}){8,24}")

# Bounded to the RFC maximums (64-character local part, 255-character domain)
# for the same reason as the phone pattern: an unbounded leading `+` makes the
# match quadratic on a long run of characters that never reaches an '@'.
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}")
_STAFF_ID = re.compile(r"(?<![A-Za-z0-9])LC-\d{4}(?![A-Za-z0-9])", re.IGNORECASE)
_POSTAL = re.compile(r"(?<!\d)\d{6}(?!\d)")

# Amounts come in two shapes: plain runs of digits, and groups separated by
# thousands commas. Both are canonicalised the same way, so "$6,450" in a
# message matches a stored amount of 6450.
_DIGIT_RUN = re.compile(r"(?<![\d.,])\d{1,9}(?:\.\d+)?(?![\d])")
_GROUPED_AMOUNT = re.compile(r"(?<![\d,.])\d{1,3}(?:,\d{3})+(?:\.\d+)?(?![\d,])")

# A letter, seven digits and a letter: the shape of an NRIC or FIN. The
# dataset contains none; this exists so the gateway would catch one.
_NRIC = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]\d{7}[A-Za-z](?![A-Za-z0-9])")

_BASE64_BLOCK = re.compile(
    rf"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{{{MIN_BLOCK_CHARS},{MAX_BLOCK_CHARS}}}={{0,2}}"
)
_HEX_BLOCK = re.compile(
    rf"(?<![A-Za-z0-9])[0-9a-fA-F]{{{MIN_BLOCK_CHARS},{MAX_BLOCK_CHARS}}}(?![A-Za-z0-9])"
)
_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")

_WORD = re.compile(r"[A-Za-z0-9'@.+\-]+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Written-out separators, used to smuggle an address past a scanner:
# "someone [at] example [dot] com". Quantifiers are bounded, for the same
# reason as everywhere else in this module.
# The whitespace around a bracketed form is consumed too: "a [at] b" has to
# become "a@b", not "a @ b", or the email pattern still will not match it.
_OBFUSCATED_AT = re.compile(
    r"\s{0,2}(?:\[\s{0,2}at\s{0,2}\]|\(\s{0,2}at\s{0,2}\))\s{0,2}|\s{1,4}at\s{1,4}",
    re.IGNORECASE,
)
_OBFUSCATED_DOT = re.compile(
    r"\s{0,2}(?:\[\s{0,2}dot\s{0,2}\]|\(\s{0,2}dot\s{0,2}\))\s{0,2}|\s{1,4}dot\s{1,4}",
    re.IGNORECASE,
)

# Invisible characters that can be dropped inside a value to break an exact
# match: zero-width space, joiners, soft hyphen, word joiner, byte-order mark.
# Everything in Unicode category Cf is removed as well.
_INVISIBLE_CHARS = frozenset(
    "\u00ad"              # soft hyphen
    "\u200b\u200c\u200d"  # zero-width space, non-joiner, joiner
    "\u200e\u200f"        # left-to-right / right-to-left marks
    "\u2060\u2061\u2062\u2063\u2064"  # word joiner, invisible operators
    "\ufeff"              # byte-order mark
)


def _prepare(text: str) -> str:
    """Normalise text before anything scans it.

    Two transport-level unwrappings, applied to the whole input:

    * NFKC normalisation, so full-width and other compatibility forms fold to
      their ASCII equivalents - "＋６５９８２３１７６４" becomes
      "+6598231764", and "＠" becomes "@";
    * removal of zero-width and format characters, so an invisible character
      dropped inside an email address or a staff id cannot break the match.

    This is not the same thing as the type-specific canonicalisation further
    down, and does not undermine it. This step only undoes ways of writing the
    *same characters*; how a phone, an email or a name is then compared still
    depends on its kind.

    ASCII input is returned unchanged: it is already NFKC-stable and contains
    no format characters, so the common case costs one scan of the string.
    """
    if not text or text.isascii():
        return text

    normalised = unicodedata.normalize("NFKC", text)
    return "".join(
        char
        for char in normalised
        if char not in _INVISIBLE_CHARS and unicodedata.category(char) != "Cf"
    )


def exceeds_scan_limit(text: str) -> bool:
    """True when content is too large to scan in full.

    The gateway must fail closed on this: withhold a read result and
    hard-deny an outbound message rather than act on a partial scan.
    """
    return bool(text) and len(text) > MAX_INPUT_BYTES


def _mask_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Blank out the given spans in one pass.

    Masking consumed matches stops the same digits being counted twice, for
    instance a phone number's digits also being read as a postal code.
    Rebuilding the string per match would be quadratic, so all spans are
    applied together.
    """
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for position in range(start, min(end, len(chars))):
            chars[position] = " "
    return "".join(chars)


# ---------------------------------------------------------------------------
# Type-specific canonicalisation
# ---------------------------------------------------------------------------


def canonicalise_phone(token: str) -> str | None:
    """Eight digits, or None if the token is not an SG mobile number.

    Strips +65, spaces, dashes, dots and brackets from inside the token. This
    is what catches "+65 9246 3318", "9246-3318" and "9 2 4 6 3 3 1 8".
    """
    if not token:
        return None
    digits = re.sub(r"\D", "", token)
    if len(digits) == 10 and digits.startswith("65"):
        digits = digits[2:]
    if len(digits) == 8 and digits[0] in "89":
        return digits
    return None


# A phone-shaped token may absorb neighbouring digits: "ref 2" immediately
# before "9 8 2 3 1 7 6 4" yields nine digits, which is not a valid number, so
# a strict reading finds nothing and the number slips through. For *matching a
# known value* every plausible eight-digit window inside the run is therefore
# considered. Bounded, so a long numeric blob is not expanded.
MAX_PHONE_RUN_DIGITS = 24


def phone_variants(token: str) -> set[str]:
    """Every eight-digit number a phone-shaped token could be expressing.

    Used only to answer "is this *particular* known number present?", where a
    spurious extra candidate costs nothing. Enumerating personal items uses
    the strict reading in ``canonicalise_phone`` instead, because inventing
    numbers there would inflate the outbound counts and hold innocent
    messages.
    """
    digits = re.sub(r"\D", "", token or "")
    if not digits or len(digits) > MAX_PHONE_RUN_DIGITS:
        return set()

    variants: set[str] = set()

    exact = canonicalise_phone(digits)
    if exact:
        variants.add(exact)

    if len(digits) > 8:
        for start in range(len(digits) - 7):
            window = digits[start : start + 8]
            if window[0] in "89":
                variants.add(window)

    return variants


def canonicalise_email(value: str) -> str:
    """Lowercase and trimmed."""
    return value.strip().lower()


def canonicalise_identifier(value: str) -> str:
    """Staff ids, API keys and contract numbers match exactly, ignoring case."""
    return value.strip().lower()


def canonicalise_name(value: str) -> str:
    """Whitespace collapsed, lowercased."""
    return " ".join(value.split()).lower()


def canonicalise_amount(value: str) -> str:
    """Digits only, so "$6,450" and "6450.00" both become "6450".

    Strips currency symbols, thousands separators and whitespace, and drops a
    decimal part that is all zeros. A salary written as "$6,450" in a message
    has to match an amount stored as "6450".
    """
    cleaned = re.sub(r"[^\d.]", "", value.strip())
    if not cleaned:
        return ""
    if "." in cleaned:
        whole, _, fraction = cleaned.partition(".")
        fraction = fraction.rstrip("0")
        return whole if not fraction else f"{whole}.{fraction}"
    return cleaned


def canonicalise_text(value: str) -> str:
    """For free text such as an address: lowercase, punctuation folded."""
    return _NON_ALNUM.sub(" ", value.lower()).strip()


def classify_value(value: str) -> str:
    """Which kind of value this is, and therefore how it must be matched."""
    candidate = value.strip()
    if not candidate:
        return KIND_TEXT
    if "@" in candidate:
        return KIND_EMAIL
    if canonicalise_phone(candidate):
        return KIND_PHONE
    if re.fullmatch(r"\d{6}", candidate):
        return KIND_POSTAL
    if re.fullmatch(r"\d{1,9}(?:\.\d+)?", candidate):
        return KIND_AMOUNT
    if " " not in candidate and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._\-]{2,}", candidate):
        return KIND_IDENTIFIER
    if re.fullmatch(r"[A-Za-z][A-Za-z'\-]*(?: [A-Za-z][A-Za-z'\-]*){1,3}", candidate):
        return KIND_NAME
    return KIND_TEXT


# ---------------------------------------------------------------------------
# Bounded decoding
# ---------------------------------------------------------------------------


def _is_mostly_printable(raw: bytes) -> bool:
    if not raw:
        return False
    printable = sum(1 for byte in raw if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(raw) >= 0.85


def _decode_bytes(raw: bytes) -> str | None:
    if not _is_mostly_printable(raw):
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def decode_candidates(text: str) -> list[str]:
    """Decoded strings hidden inside ``text``, one level deep.

    Bounded on purpose: the input is capped at 200 KB, at most 50 candidates
    are returned, blocks must be 16 to 4096 characters, and a candidate is
    never itself decoded again. That keeps the cost of scanning a hostile
    message predictable.
    """
    if not text:
        return []

    source = _prepare(text)[:MAX_INPUT_BYTES]
    candidates: list[str] = []
    seen: set[str] = {source}

    def offer(decoded: str | None) -> bool:
        """Returns False once the candidate cap is reached."""
        if len(candidates) >= MAX_CANDIDATES:
            return False
        if decoded and decoded not in seen and len(decoded.strip()) >= 4:
            seen.add(decoded)
            candidates.append(decoded)
        return True

    # URL-encoded content. Decoding the whole text once covers every escaped
    # part of it, including inside a URL's query string.
    if _PERCENT_ESCAPE.search(source):
        offer(urllib.parse.unquote(source))
        offer(urllib.parse.unquote_plus(source))

    # Written-out separators: "someone [at] example [dot] com".
    deobfuscated = _OBFUSCATED_DOT.sub(".", _OBFUSCATED_AT.sub("@", source))
    if deobfuscated != source:
        offer(deobfuscated)

    for match in _BASE64_BLOCK.finditer(source):
        block = match.group(0)
        padded = block + "=" * (-len(block) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not offer(_decode_bytes(raw)):
            return candidates

    for match in _HEX_BLOCK.finditer(source):
        block = match.group(0)
        if len(block) % 2:
            block = block[:-1]
        try:
            raw = bytes.fromhex(block)
        except ValueError:
            continue
        if not offer(_decode_bytes(raw)):
            return candidates

    return candidates


# ---------------------------------------------------------------------------
# One scanned text, indexed by value kind
# ---------------------------------------------------------------------------


class _TextIndex:
    """Everything extractable from one piece of text, computed once.

    Built per scanned text so that matching twenty canaries costs one pass,
    not twenty.
    """

    def __init__(self, text: str):
        self.raw = text[:MAX_INPUT_BYTES]
        self.lowered = self.raw.lower()
        self.folded = canonicalise_text(self.raw)

        self.emails = {canonicalise_email(m.group(0)) for m in _EMAIL.finditer(self.raw)}

        self.phones = set()
        phone_spans: list[tuple[int, int]] = []
        for match in _PHONE_TOKEN.finditer(self.raw):
            variants = phone_variants(match.group(0))
            if variants:
                self.phones.update(variants)
                phone_spans.append(match.span())

        # Postal codes are read from text with phone tokens masked out, so
        # digits inside a phone number are never claimed as a postal code.
        self.postals = {
            m.group(0) for m in _POSTAL.finditer(_mask_spans(self.raw, phone_spans))
        }

        # Both amount shapes are reduced to digits, so a stored amount matches
        # however the message wrote it: 6450, 6,450, $6,450 or $6,450.00.
        self.amounts = {
            canonicalise_amount(match.group(0))
            for pattern in (_DIGIT_RUN, _GROUPED_AMOUNT)
            for match in pattern.finditer(self.raw)
        }
        self.amounts.discard("")

        self.words = [word.lower() for word in _WORD.findall(self.raw)]
        self.word_set = set(self.words)

    def ngrams(self, size: int):
        for start in range(0, max(0, len(self.words) - size + 1)):
            yield " ".join(self.words[start : start + size])

    def contains(self, value: str) -> bool:
        """Does this text contain ``value``, matched the way its kind requires?"""
        kind = classify_value(value)

        if kind == KIND_EMAIL:
            return canonicalise_email(value) in self.emails

        if kind == KIND_PHONE:
            return canonicalise_phone(value) in self.phones

        if kind == KIND_POSTAL:
            return value.strip() in self.postals

        if kind == KIND_AMOUNT:
            return canonicalise_amount(value) in self.amounts

        if kind == KIND_IDENTIFIER:
            pattern = re.compile(
                rf"(?<![A-Za-z0-9]){re.escape(canonicalise_identifier(value))}(?![A-Za-z0-9])"
            )
            return bool(pattern.search(self.lowered))

        if kind == KIND_NAME:
            return self._contains_name(value)

        folded = canonicalise_text(value)
        return bool(folded) and folded in self.folded

    def _contains_name(self, value: str) -> bool:
        """Fuzzy name match, token_sort_ratio >= 90.

        Fuzzy so that reordered or lightly reformatted names still match. A
        name is only ever weak evidence, so a near miss cannot block anything
        on its own.
        """
        target = canonicalise_name(value)
        parts = target.split()
        if not parts:
            return False
        # Cheap prefilter: a near-identical name shares at least one word.
        if not any(part in self.word_set for part in parts):
            return False
        for ngram in self.ngrams(len(parts)):
            if fuzz.token_sort_ratio(target, ngram) >= NAME_MATCH_THRESHOLD:
                return True
        return False


# ---------------------------------------------------------------------------
# Canary detection
# ---------------------------------------------------------------------------


@dataclass
class CanaryMatch:
    """One decoy found in the scanned content."""

    canary_id: str
    canary_type: str
    location: str
    record_ref: str | None
    confidence: str
    matched_values: list[str] = field(default_factory=list)


@dataclass
class Findings:
    """What a scan found.

    ``confidence`` is the strongest level across every decoy: STRONG if any
    decoy matched strongly, else WEAK, else NONE. NONE means no registered
    decoy was present, not that the content is safe.

    ``truncated`` is True when the content was larger than the scan limit, so
    only its first 200 KB was examined. A NONE result with ``truncated`` set
    means "nothing found in the part that was scanned", which is not the same
    as "nothing there". The gateway must fail closed on it: withhold the read
    result, hard-deny the outbound message. Never act on a partial scan.
    """

    confidence: str = NONE
    matches: list[CanaryMatch] = field(default_factory=list)
    truncated: bool = False

    @property
    def is_strong(self) -> bool:
        return self.confidence == STRONG

    @property
    def is_weak(self) -> bool:
        return self.confidence == WEAK

    @property
    def canary_ids(self) -> list[str]:
        return [match.canary_id for match in self.matches]

    @property
    def locations(self) -> list[str]:
        """Which files the matched decoys came from, for the alert."""
        seen: list[str] = []
        for match in self.matches:
            if match.location not in seen:
                seen.append(match.location)
        return seen


def load_active_canaries() -> list[Canary]:
    """Every decoy currently planted in the workspace.

    After an unseed there are none, so previously planted values stop
    matching.
    """
    return database.list_canaries(status="active")


def load_canary(canary_id: str) -> Canary | None:
    """One decoy, used to name the file a leak came from in an alert."""
    return database.get_canary(canary_id)


def find_canaries(text: str) -> Findings:
    """Scan ``text`` and every decoded candidate inside it for decoys.

    * STRONG: a value unique to a decoy is present.
    * WEAK: two or more of one decoy's weak values are present, and no
      strong value. A name alone is never even WEAK.
    * NONE: neither.

    The text is NFKC normalised and stripped of invisible characters first,
    and ``Findings.truncated`` reports whether it was too large to scan in
    full. A caller must not treat a truncated NONE as a clean result.
    """
    if not text:
        return Findings()

    truncated = exceeds_scan_limit(text)
    prepared = _prepare(text)[:MAX_INPUT_BYTES]
    confidence, matches = _match_canaries(prepared)
    return Findings(confidence=confidence, matches=matches, truncated=truncated)


def _match_canaries(
    prepared: str, candidates: list[str] | None = None
) -> tuple[str, list[CanaryMatch]]:
    """Match every active decoy against already-prepared text.

    Split out so that ``scan`` can prepare the text once, decode it once, and
    run both the canary match and the personal-item extraction over the same
    material.
    """
    canaries = load_active_canaries()
    if not canaries:
        return NONE, []

    if candidates is None:
        candidates = decode_candidates(prepared)

    indexes = [_TextIndex(prepared)]
    indexes.extend(_TextIndex(candidate) for candidate in candidates)

    matches: list[CanaryMatch] = []
    for canary in canaries:
        matched_strong = [
            value
            for value in canary.strong_values()
            if any(index.contains(value) for index in indexes)
        ]
        if matched_strong:
            matches.append(
                CanaryMatch(
                    canary_id=canary.id,
                    canary_type=canary.canary_type,
                    location=canary.location,
                    record_ref=canary.record_ref,
                    confidence=STRONG,
                    matched_values=matched_strong,
                )
            )
            continue

        matched_weak = [
            value
            for value in canary.weak_values()
            if any(index.contains(value) for index in indexes)
        ]
        if len(matched_weak) >= 2:
            matches.append(
                CanaryMatch(
                    canary_id=canary.id,
                    canary_type=canary.canary_type,
                    location=canary.location,
                    record_ref=canary.record_ref,
                    confidence=WEAK,
                    matched_values=matched_weak,
                )
            )

    if not matches:
        return NONE, []

    confidence = STRONG if any(m.confidence == STRONG for m in matches) else WEAK
    return confidence, matches


# ---------------------------------------------------------------------------
# Personal item extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PersonalItem:
    """One piece of personal data found in content."""

    kind: str
    value: str


def extract_personal(text: str) -> list[PersonalItem]:
    """Personal data items in ``text`` as written, deduplicated.

    This reads the text literally: it does not decode base64, hex or
    URL-encoded content. ``scan()`` is what the gateway calls, and it does
    collect items from decoded candidates too. Use this where literal
    position matters - asking whether a value appears *inside a URL*, for
    instance - and ``scan()`` for a decision.

    Phones, emails, staff ids, six-digit postal codes and NRIC/FIN-shaped
    strings. Matched spans are masked as they are consumed, so digits inside a
    phone number are not also counted as a postal code.

    The text is NFKC normalised and stripped of invisible characters first, so
    a full-width or zero-width-padded value is still found. Content past the
    scan limit is not examined; call ``exceeds_scan_limit`` and fail closed
    rather than trusting a short result from a huge input.

    The dataset contains no NRICs; that pattern is here so the gateway would
    catch one if it ever appeared.
    """
    if not text:
        return []

    return _extract_personal(_prepare(text)[:MAX_INPUT_BYTES])


def _extract_personal(source: str) -> list[PersonalItem]:
    """Extract personal items from already-prepared text."""
    items: list[PersonalItem] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            items.append(PersonalItem(kind=kind, value=value))

    # NRIC first: its shape overlaps nothing else, and masking it keeps its
    # seven digits from being read as something else. Each pass masks what it
    # consumed, in one go, so the next pass cannot double-count it.
    nric_spans: list[tuple[int, int]] = []
    for match in _NRIC.finditer(source):
        add("nric", match.group(0).upper())
        nric_spans.append(match.span())
    working = _mask_spans(source, nric_spans)

    for match in _EMAIL.finditer(working):
        add("email", canonicalise_email(match.group(0)))
    working = _EMAIL.sub(lambda m: " " * len(m.group(0)), working)

    for match in _STAFF_ID.finditer(working):
        add("staff_id", match.group(0).upper())
    working = _STAFF_ID.sub(lambda m: " " * len(m.group(0)), working)

    phone_spans: list[tuple[int, int]] = []
    for match in _PHONE_TOKEN.finditer(working):
        phone = canonicalise_phone(match.group(0))
        if phone:
            add("phone", phone)
            phone_spans.append(match.span())
    working = _mask_spans(working, phone_spans)

    for match in _POSTAL.finditer(working):
        add("postal_code", match.group(0))

    return items


def count_personal(text: str) -> int:
    """How many distinct personal items the content carries."""
    return len(extract_personal(text))


# ---------------------------------------------------------------------------
# One scan, one result
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Everything one pass over a piece of content found.

    The gateway's single call site. ``truncated`` is the fail-closed signal:
    when it is True only the first ``MAX_INPUT_BYTES`` were examined, so the
    gateway must withhold a read result or hard-deny an outbound message
    rather than trust ``confidence`` or ``personal_count``.
    """

    confidence: str = NONE
    matches: list[CanaryMatch] = field(default_factory=list)
    personal: list[PersonalItem] = field(default_factory=list)
    truncated: bool = False

    @property
    def personal_count(self) -> int:
        """Distinct personal items, for the per-message and session limits."""
        return len(self.personal)

    @property
    def is_strong(self) -> bool:
        return self.confidence == STRONG

    @property
    def is_weak(self) -> bool:
        return self.confidence == WEAK

    @property
    def canary_ids(self) -> list[str]:
        return [match.canary_id for match in self.matches]

    @property
    def locations(self) -> list[str]:
        """Which files the matched decoys came from, for the alert."""
        seen: list[str] = []
        for match in self.matches:
            if match.location not in seen:
                seen.append(match.location)
        return seen

    @property
    def fully_scanned(self) -> bool:
        """False when the content was too large to examine in full."""
        return not self.truncated


def scan(text: str) -> ScanResult:
    """Scan content once for decoys and personal data.

    This is what the gateway calls: it normalises and truncates the text a
    single time, then runs the canary match and the personal-item extraction
    over the same prepared string, so the two can never disagree about what
    was examined.
    """
    if not text:
        return ScanResult()

    truncated = exceeds_scan_limit(text)
    prepared = _prepare(text)[:MAX_INPUT_BYTES]
    candidates = decode_candidates(prepared)

    confidence, matches = _match_canaries(prepared, candidates)

    # Personal items are collected from the decoded candidates as well as the
    # text as written. Without this, encoding a customer list as hex or base64
    # would hide it from the outbound volume limit and the data-owner rule,
    # even though the very same decoding already exposes a decoy to the canary
    # match. The two halves have to see the same material or the asymmetry is
    # itself the evasion.
    personal: list[PersonalItem] = []
    seen: set[tuple[str, str]] = set()
    for source in (prepared, *candidates):
        for item in _extract_personal(source):
            key = (item.kind, item.value)
            if key not in seen:
                seen.add(key)
                personal.append(item)

    return ScanResult(
        confidence=confidence,
        matches=matches,
        personal=personal,
        truncated=truncated,
    )


# ---------------------------------------------------------------------------
# Owner lookup
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Owner:
    """The record a personal item belongs to."""

    record_type: str  # "customer" or "staff"
    record_id: str
    name: str
    email: str


def _load_records() -> tuple[list[dict], list[dict]]:
    customers_path = config.WORKSPACE_DIR / "customers" / "customer_contacts.csv"
    staff_path = config.WORKSPACE_DIR / "hr" / "employees.csv"

    def read(path):
        if not path.is_file():
            return []
        with path.open(newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    return read(customers_path), read(staff_path)


def _owner_index() -> dict[str, list[Owner]]:
    """Unique identifiers mapped to the records that carry them.

    Only email, phone, customer id and staff id are indexed. Postal codes and
    names are deliberately absent: they are not unique, so they must never
    decide who owns a piece of data.
    """
    customers, staff = _load_records()
    index: dict[str, list[Owner]] = {}

    def register(key: str | None, owner: Owner) -> None:
        if not key:
            return
        index.setdefault(key, [])
        if owner not in index[key]:
            index[key].append(owner)

    for row in customers:
        owner = Owner(
            record_type="customer",
            record_id=row["customer_id"],
            name=row["name"],
            email=row["email"],
        )
        register(canonicalise_email(row["email"]), owner)
        register(canonicalise_phone(row["phone"]), owner)
        register(canonicalise_identifier(row["customer_id"]), owner)

    for row in staff:
        owner = Owner(
            record_type="staff",
            record_id=row["staff_id"],
            name=row["name"],
            email=row["email"],
        )
        register(canonicalise_email(row["email"]), owner)
        register(canonicalise_identifier(row["staff_id"]), owner)

    return index


def _record_postal_codes() -> set[str]:
    customers, _staff = _load_records()
    return {row["postal_code"].strip() for row in customers if row.get("postal_code")}


def matches_record(item: PersonalItem) -> bool:
    """Is this item a value that actually appears in the customer or staff records?

    Wider than ``owner_lookup`` on purpose. Ownership is decided by unique
    identifiers only, so a postal code never has an owner - but a postal code
    taken from a customer record is still that customer's data, and a message
    made only of such values must still count as a disclosure. An address that
    no record holds (an attacker's own, say) does not.
    """
    if item.kind in ("email", "phone", "staff_id", "identifier"):
        found = next(iter(owner_lookup([item]).values()))
        return found is not None
    if item.kind == "postal_code":
        return item.value in _record_postal_codes()
    # NRIC-shaped strings appear in no record, but nothing legitimate sends one.
    return item.kind == "nric"


def owner_lookup(items) -> dict[str, Owner | str | None]:
    """Map each item to the record that owns it.

    * an ``Owner`` when exactly one record carries that identifier;
    * ``AMBIGUOUS`` when more than one record does;
    * ``None`` when nothing does, or when the item is not a unique
      identifier at all (a postal code or a name).

    Keys in the returned mapping are the canonical forms of the items.
    """
    index = _owner_index()
    results: dict[str, Owner | str | None] = {}

    for item in items:
        if isinstance(item, PersonalItem):
            kind, raw = item.kind, item.value
        else:
            raw = str(item)
            kind = {
                KIND_EMAIL: "email",
                KIND_PHONE: "phone",
                KIND_IDENTIFIER: "identifier",
                KIND_POSTAL: "postal_code",
            }.get(classify_value(raw), "other")

        if kind == "email":
            key = canonicalise_email(raw)
        elif kind == "phone":
            key = canonicalise_phone(raw) or raw
        elif kind in ("staff_id", "identifier"):
            key = canonicalise_identifier(raw)
        else:
            # Postal codes, names and anything else never decide ownership.
            results[raw] = None
            continue

        owners = index.get(key, [])
        if not owners:
            results[key] = None
        elif len(owners) > 1:
            results[key] = AMBIGUOUS
        else:
            results[key] = owners[0]

    return results
