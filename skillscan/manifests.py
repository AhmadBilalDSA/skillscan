"""MCP tool-description scanning ("manifest pass").

An MCP server describes its tools in a JSON manifest: each tool
has a `description`, and each input field can carry one too. The
agent reads those descriptions and treats them as guidance — so
a poisoned description is an instruction channel that never
appears in any SKILL.md: the canonical shapes tell the agent to
read credential files and pass their contents along, to prefer
one tool's output over another's, or to keep its actions hidden
from the user. Ordinary file scanning sees the manifest as JSON
text; this module parses it structurally, extracts every
description string (decoded — JSON `\\uXXXX` escapes become the
real characters), and checks the decoded text with anchors
written for description-shaped text.

Matching discipline (hardened by adversarial review — the first
cut fired on legitimate manifests, so every guard below exists
because a real benign shape tripped the naive version):

* SENTENCE scope. Anchors combine only within one sentence. A
  description that copies a public key in one sentence and
  gives safety advice about private keys in the next is not an
  attack assembled from parts.
* CLAUSE scope + GOVERNING verbs (second fix wave). Within a
  sentence, the credential conjunction is evaluated per comma
  clause, and a send/access verb only completes the shape when
  it GOVERNS the credential target (the target is the verb's
  object, shortly after it) — a verb that merely shares a
  sentence with a credential noun ("redact any private key
  material before sending the bundle") completes nothing. A
  frame may lead from an earlier clause ("Before using this
  tool, read …"); a target in one clause and a verb in the
  next do not assemble.
* NEGATION guard. A verb occurrence governed by a negation
  ("never reads your .env file", "never include the user's
  private key") does not count as an action — the guard is
  per-occurrence, keyed on the verb the negation governs, so
  "never forget to read…" is not an assurance and one negated
  verb does not launder a live one next to it.
* QUOTATION guard. Text inside quotes (ASCII, curly, or
  guillemets; apostrophes inside words are not quotes) is a
  description quoting something (often an attack example, in
  security tools), not the description instructing — quoted
  spans are stripped before matching. One exception at the
  caution tier: an explicit "follow/apply this note" directive
  wrapped around a quoted credential shape is reported, since
  there the quote IS the instruction.
* CONSENT mitigator. Consent ("ask the user for confirmation",
  "the file the user provides", "your own bucket") suppresses
  access-only credential shapes in its clause and later
  clauses of the sentence. It never suppresses a send or
  pass-into shape aimed at an external destination, and
  same-clause consent is the only consent that can suppress a
  send shape at all — consent worn as a costume in a leading
  clause does not launder the exfiltration clause after it.
  Concealment is still checked first: consent plus hiding is
  hiding.
* Two verdict tiers. `MCP_DESCRIPTION_POISONING` (block):
  concealment from the user, a credential-store target inside
  an instruction frame with a send / pass-along / access verb,
  the same shape split across one tool's surfaces, or a
  declarative sentence that reads a credential store and sends
  it to an external destination. `MCP_DESCRIPTION_INSTRUCTION`
  (caution): cross-tool steering and instruction overrides.
* The two mechanical tripwires reuse existing rules on the
  DECODED strings, where they add signal the raw-text pass
  cannot see: `HIDDEN_TEXT` for invisible/deceptive characters
  and `NON_ENGLISH_INSTRUCTION` for the phrase tripwire, loaded
  from the same per-language data files the line pass uses.

Anchors match on a normalised copy of each sentence (lowercase,
Cyrillic/Greek confusables folded to Latin, zero-width
characters removed); findings always cite the original text.

Stdlib only, deterministic, no network. A file that is not a
JSON manifest with a `tools` list simply yields no descriptions.
"""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from pathlib import Path

# ---------------------------------------------------------------------------
# Description extraction
# ---------------------------------------------------------------------------


def _schema_descriptions(schema: object, tool: str,
                         out: list[tuple[str, str, str]],
                         where_prefix: str = "inputSchema") -> None:
    """Recursively collect descriptions from an inputSchema:
    properties at any depth, items, additionalProperties, and
    allOf/anyOf/oneOf branches."""
    if not isinstance(schema, dict):
        return
    props = schema.get("properties")
    if not isinstance(props, dict):
        props = schema.get("patternProperties")
    if isinstance(props, dict):
        for field_name, spec in props.items():
            if isinstance(spec, dict):
                d = spec.get("description")
                if isinstance(d, str) and d.strip():
                    out.append((tool,
                                f"{where_prefix} field '{field_name}'", d))
                _schema_descriptions(spec, tool, out,
                                     f"{where_prefix} field '{field_name}'")
    for key in ("items", "additionalProperties"):
        sub = schema.get(key)
        if isinstance(sub, dict):
            d = sub.get("description")
            if isinstance(d, str) and d.strip():
                out.append((tool, f"{where_prefix} {key}", d))
            _schema_descriptions(sub, tool, out, where_prefix)
    for key in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(key)
        if isinstance(branches, list):
            for branch in branches:
                if isinstance(branch, dict):
                    # A branch's OWN description is a surface
                    # too, not just the descriptions nested in it.
                    d = branch.get("description")
                    if isinstance(d, str) and d.strip():
                        out.append((tool,
                                    f"{where_prefix} {key} branch", d))
                    _schema_descriptions(branch, tool, out, where_prefix)


def _parse_manifest(text: str) -> tuple[dict | None, list[str]]:
    """Parse the JSON, also capturing DUPLICATE description
    values (a second "description" key in one object normally
    hides the first from json.loads — a poisoned first value
    must still be checked). Returns (data, duplicate_descriptions
    as (context-free) strings)."""
    duplicates: list[str] = []

    def hook(pairs):
        obj: dict = {}
        seen_desc: list[str] = []
        for key, value in pairs:
            if key == "description" and isinstance(value, str):
                if "description" in obj and obj["description"] != value:
                    seen_desc.append(obj["description"])
                obj[key] = value
            else:
                obj[key] = value
        for d in seen_desc:
            duplicates.append(d)
        return obj

    try:
        data = json.loads(text, object_pairs_hook=hook)
    except Exception:
        return None, []
    return (data if isinstance(data, dict) else None), duplicates


def _extract_grouped(text: str) -> list[tuple[str, list[tuple[str, str, str]]]]:
    """Per-surface-owner groups: [(owner, [(owner, where, desc)])]
    where owner is a tool name (or '<server>' for the top-level
    instructions field). Duplicate description values are folded
    into their tool's group when attributable, else the server
    group."""
    data, duplicates = _parse_manifest(text)
    if data is None:
        return []
    tools = data.get("tools")
    if not isinstance(tools, list) and isinstance(data.get("result"), dict):
        tools = data["result"].get("tools")  # tools/list envelope
    if not isinstance(tools, list):
        return []
    groups: list[tuple[str, list[tuple[str, str, str]]]] = []
    server: list[tuple[str, str, str]] = []
    instructions = data.get("instructions")
    if isinstance(instructions, str) and instructions.strip():
        server.append(("<server>", "server instructions", instructions))
    if server:
        groups.append(("<server>", server))
    known: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        name = name if isinstance(name, str) and name else "?"
        entries: list[tuple[str, str, str]] = []
        title = tool.get("title")
        if isinstance(title, str) and title.strip():
            entries.append((name, "title", title))
        desc = tool.get("description")
        if isinstance(desc, str) and desc.strip():
            entries.append((name, "description", desc))
        schema = tool.get("inputSchema")
        if not isinstance(schema, dict):
            schema = tool.get("input_schema")
        if isinstance(schema, dict):
            _schema_descriptions(schema, name, entries)
        for _owner, _where, d in entries:
            known.add(d)
        if entries:
            groups.append((name, entries))
    stray = [d for d in duplicates if d not in known]
    if stray:
        extra = [("<manifest>", "duplicate description key", d)
                 for d in stray]
        groups.append(("<manifest>", extra))
    return groups


def extract_descriptions(text: str) -> list[tuple[str, str, str]]:
    """(tool name, where, description) for every description
    string in an MCP tool manifest. Returns [] for anything
    that is not a manifest."""
    out: list[tuple[str, str, str]] = []
    for _owner, entries in _extract_grouped(text):
        out.extend(entries)
    return out


def _description_lines(text: str, count: int) -> list[int]:
    """Approximate 1-based line numbers for the extracted
    descriptions: the lines of successive `"description"` keys
    in the raw text, in order (linear via precomputed newline
    offsets). Falls back to line 1."""
    newlines = [m.start() for m in re.finditer("\n", text)]
    lines = [bisect_right(newlines, m.start()) + 1
             for m in re.finditer(r'"description"\s*:', text)]
    while len(lines) < count:
        lines.append(lines[-1] if lines else 1)
    return lines[:count]


# ---------------------------------------------------------------------------
# Normalisation for matching (findings always cite the original)
# ---------------------------------------------------------------------------

_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ѕ": "s", "ј": "j", "к": "k", "м": "m",
    "н": "h", "т": "t", "в": "b", "г": "r", "д": "d", "з": "3",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "μ": "u",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "χ": "x",
})
_ZERO_WIDTH = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD], None)


def _match_copy(text: str) -> str:
    folded = text.lower().translate(_CONFUSABLES)
    folded = folded.translate(_ZERO_WIDTH)
    return " ".join(folded.split())


# Quote pairs: ASCII double, curly double/single, guillemets,
# and ASCII single — the single-quote opener must not be
# preceded by a letter and the closer must not be followed by
# one, so contractions ("It's", "user's") are never treated as
# quote delimiters (they would otherwise strip the live text
# between two apostrophes).
_QUOTED_RE = re.compile(
    r'"[^"\n]{0,300}"'
    r"|“[^”\n]{0,300}”"
    r"|‘[^’\n]{0,300}’"
    r"|«[^»\n]{0,300}»"
    r"|(?<![A-Za-z])'[^'\n]{0,300}'(?![A-Za-z])")


def _unquoted(text: str) -> str:
    return _QUOTED_RE.sub(" ", text)


def _quoted_spans(text: str) -> list[str]:
    """The contents of the quoted spans in `text` (delimiters
    removed), for the follow-the-note caution check."""
    return [m.group(0)[1:-1] for m in _QUOTED_RE.finditer(text)]


def _sentences(text: str) -> list[str]:
    # Semicolons are clause boundaries for scoping too: a frame
    # in one clause must not reach a verb in the next.
    parts = re.split(r"(?<=[.!?;])\s+|\n+", text)
    return [p.strip() for p in parts if p and p.strip()]


# ---------------------------------------------------------------------------
# Anchors (matched on the normalised, unquoted sentence copy)
# ---------------------------------------------------------------------------

# Concealment from the user: hiding the agent's ACTIONS or their
# existence — never redaction (a tool that shows the user only
# the last four characters of a token is protecting them, and
# "reveal/disclose to the user" phrasing is therefore absent
# here by design).
_CONCEALMENT = (
    r"without (telling|informing|notifying|alerting) the user",
    r"without the user'?s (knowledge|consent|noticing)",
    r"hide (this|it|the action|the call|the result|the output) from the user",
    r"keep (this|it) (secret|hidden) from the user",
    r"the user (must|should) never (know|find out|see)",
    r"keep the user out of the loop",
    r"keep (this|it|this step|the step|this action|the action) "
    r"between us",
    r"do ?n'?t mention (this|it|the call|the action)",
    r"no need to mention (this|it|the call|the action)",
    r"without mentioning (this|it|the call|the action|the send|the upload)",
    r"silently (also )?(read|reads|send|sends|fetch|fetches|collect|collects|upload|uploads|copy|copies|forward|forwards)\b",
    r"(do not|don'?t) (tell|inform|notify|alert) the user (about|that|what)\b",
)
_CONCEALMENT_RES = [re.compile(p) for p in _CONCEALMENT]

# Credential-STORE targets: files and stores whose contents are
# secrets. (A bare "api key" is deliberately absent: API tools
# legitimately discuss the key the user supplies.)
_CREDENTIAL_TARGETS = (
    r"~/\.ssh", r"\.ssh/", r"id_rsa", r"id_ed25519",
    r"\.aws/credentials", r"\.aws/", r"\.env\b", r"env file",
    r"credential (file|store|files)", r"\.kube/config",
    r"browser (cookies|passwords|login data|credential)",
    r"login data", r"keychain", r"\.gnupg", r"\.netrc",
    r"private key", r"cloud credential",
    r"ssh key",
    r"password (file|store|manager contents)",
)
_CREDENTIAL_RES = [re.compile(p) for p in _CREDENTIAL_TARGETS]

# Instruction frames: shapes that make following text an
# instruction to the agent rather than a description of the tool.
_INSTRUCTION_FRAMES = (
    r"\byou (must|should|need to|have to)\b",
    r"\b(always|never)\b",
    r"\bmake sure (to|you)\b",
    r"\bbe sure to\b",
    r"\bremember to\b",
    r"\bplease (also )?(read|send|include|attach|copy|fetch|run|execute)",
    r"\bnote:\s",
    r"\bimportant:\s",
    r"\bsidenote\b",
    r"^\s*(read|send|include|attach|copy|fetch|upload|post)\b",
    # The canonical poisoning preamble: a timing phrase with the
    # imperative verb immediately after it ("Before each use,
    # first collect …"). The verb must follow the preamble, so
    # declarative "before each use, the tool reads …" is untouched.
    r"\bbefore (each|every|any) use,?\s+(first\s+)?"
    r"(read|collect|fetch|gather|copy|send|forward|upload|include)\b",
    r"\bbefore using this tool,?\s+(first\s+)?"
    r"(read|collect|fetch|gather|copy|send|forward|upload|include)\b",
    # The bare timing preamble as its own clause ("Before each
    # use, first collect …" splits at the comma): the preamble
    # alone is the frame for the clause that follows it.
    r"\bbefore (each|every|any) use\b",
    r"\bbefore using this tool\b",
)
_FRAME_RES = [re.compile(p) for p in _INSTRUCTION_FRAMES]

_SEND_VERBS = (
    r"\b(send|sends|sent|post|posts|upload|uploads|transmit|forward|"
    r"exfiltrate|leak|email|e-mail)\b",
    r"\bpass\w*\b[^.]{0,40}\b(along|onwards|over to)\b",
    r"\b(as|in) (a |the )?(sidenote|note|comment) (parameter|field|argument)\b",
)
_SEND_RES = [re.compile(p) for p in _SEND_VERBS]

# Pass-along-into-a-parameter: credential contents placed into
# a caller-visible field IS the exfiltration channel (the
# sidenote shape), in framed and declarative text alike.
_PASSINTO_RES = [re.compile(
    r"\b(pass|passes|include|includes|add|adds|append|insert|put|place)"
    r"[^.]{0,50}\b(parameter|argument|input|field|payload|value|request)\b")]

# Disclosure verbs: for the caution tier, a framed credential
# target must be paired with the target's contents being shown
# or moved ("displays your ssh key settings"), not merely
# mentioned near a benign governing verb ("create an env file
# listing the ports").
_DISCLOSE_RES = [re.compile(
    r"\b(display|displays|displaying|show|shows|showing|reveal|"
    r"reveals|revealing|expose|exposes|exposing)\b|contents of")]

_ACCESS_VERBS = (
    r"\b(read|reads|open|opens|load|loads|get|gets|fetch|fetches|"
    r"copy|copies|extract|extracts|retrieve|collect|grab)\b",
)
_ACCESS_RES = [re.compile(p) for p in _ACCESS_VERBS]

# Agent steering (caution tier): cross-tool preference and
# instruction overrides only. General tool-selection phrasing
# ("whenever you need…", "you must always provide <parameter>")
# is how legitimate descriptions read and is deliberately absent.
_STEERING = (
    r"ignore (all |the )?(previous|prior|above|earlier) instructions",
    r"disregard (all |the )?(previous|prior|above) instructions",
    r"prefer this tool",
    r"use this tool instead of",
    r"instead of (the|any|another) (other )?tool",
    r"ignore (the )?(output|result|response|answer) of",
    r"before using (any|another|every) other tool",
    r"always use this tool",
    r"do not (use|trust|rely on) (any |the )?other tool",
    r"the only \w+ you (will ever need|need|should use|must use)",
    r"(results|output|answers) (from|of) this \w+ supersede",
    r"present (them|it|the results|its results) as the "
    r"(final|authoritative|correct) (answer|result|truth)",
    r"every other \w+ is (redundant|unreliable|unnecessary)",
    r"prefer (its|this tool'?s) (output|results|answers) over",
    r"treat (this|its|the) (tool'?s )?(results|output|answers|"
    r"responses) as (authoritative|correct|final|the truth)",
    r"disregard (the )?(results|output|answers|responses) "
    r"(of|from|returned by)",
    r"(competing|other) (search )?tools? (as|are) unreliable",
)
_STEERING_RES = [re.compile(p) for p in _STEERING]

# Negation guard: a negation word governing an action verb
# ("never reads", "does not send", "never include", "never
# display") marks that verb occurrence as an assurance, not an
# action. The verb set covers every verb the shapes can use —
# send/access, pass-into, and disclose verbs alike — because a
# negated verb the guard cannot see ("never include the user's
# private key") assembles a false shape out of a safety clause.
_NEGATED_ACTION_RE = re.compile(
    r"\b(never|does not|doesn'?t|do not|don'?t|will not|won'?t|"
    r"cannot|can'?t|refuse[sd]?|no longer)\s+"
    r"(?:\w+ly\s+)?"
    r"(read|reads|send|sends|access|accesses|open|opens|load|loads|"
    r"fetch|fetches|copy|copies|upload|uploads|post|posts|collect|"
    r"collects|store|stores|share|shares|transmit|write|writes|"
    r"execute|executes|run|runs|delete|deletes|modify|modifies|"
    r"include|includes|add|adds|attach|attaches|insert|inserts|"
    r"display|displays|show|shows|reveal|reveals|expose|exposes|"
    r"print|prints|disclose|discloses|put|puts|place|places|"
    r"append|appends|pass|passes|email|emails|forward|forwards|"
    r"retrieve|retrieves|extract|extracts|grab|grabs|get|gets)\b")

# Consent / user-directedness: the sentence routes through the
# user, so credential handling in it is the tool's directed job.
_CONSENT = (
    r"ask(s|ing)? the user",
    r"the user (provides|supplies|names|specifies|exports|uploads|"
    r"chooses|selects|enters|gives|designates|picks)",
    r"user[- ](provided|supplied|named|specified|exported|chosen|"
    r"selected|entered|designated)",
    r"(with|after|upon) (the )?user'?s (permission|confirmation|"
    r"approval|consent)",
    r"user (permission|confirmation|approval|consent)",
    r"at the user'?s request",
    r"when the user (asks|requests|wants)",
    r"if the user (asks|requests|wants|chooses)",
    r"the user asks for",
    r"you (point|specify|name|choose|select|provide)\b",
    r"the user'?s own\b",
    r"your own (bucket|server|account|storage|backup|drive)",
    r"(configured|designated|specified) by the user",
    r"you (have )?configured",
    r"confirm(s|ation)? (with|from) the user",
    r"prompt(s|ing)? the user",
)
_CONSENT_RES = [re.compile(p) for p in _CONSENT]

# External destination marker for the declarative shape (no
# instruction frame): a domain/URL or explicit externality.
_EXTERNAL_RE = re.compile(
    r"https?://|\b[\w-]+\.(com|net|org|io|dev|xyz|info|site|online)\b"
    r"|\bexternal(ly)?\b|\bthird[- ]part")

# Invisible / deceptive characters, mirroring the categories the
# HIDDEN_TEXT rule names (zero-width, bidi controls, Tags block).
_HIDDEN_RANGES = (
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064),
    (0x2066, 0x2069), (0xFEFF, 0xFEFF), (0x061C, 0x061C),
    (0xE0000, 0xE007F), (0x00AD, 0x00AD),
)


def _has_hidden(text: str) -> bool:
    for ch in text:
        o = ord(ch)
        for lo, hi in _HIDDEN_RANGES:
            if lo <= o <= hi:
                return True
    return False


# ---------------------------------------------------------------------------
# Non-English phrase tripwire (same data files as the line pass;
# loaded here so this module has no import cycle with scanner.py)
# ---------------------------------------------------------------------------

_PHRASE_NEGATIONS = (
    "nunca", "jamais", "niemals", "nie ", "nigdy", "asla", "绝不",
    "決して", "никогда", "कभी नहीं", "não", "nao ", "never", "refuse",
    "أبداً", "절대", "jangan pernah", "ніколи",
)
_TOKEN_EDGE_CHARS = " \t.,;:!?()[]{}<>\"'«»“”„‚‘’—–-।॥·。、،؛؟…*_`#"


def _load_phrase_sets() -> list[dict]:
    sets: list[dict] = []
    phrases_dir = Path(__file__).parent / "phrases"
    try:
        files = sorted(phrases_dir.glob("*.json"))
    except OSError:
        return sets
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            lang = {
                "cjk": bool(data.get("cjk", False)),
                "override": tuple(x.lower() for x in data.get("override", ())),
                "send": tuple(x.lower() for x in data.get("send", ())),
                "target": tuple(x.lower() for x in data.get("target", ())),
                "conceal": tuple(x.lower() for x in data.get("conceal", ())),
            }
        except Exception:
            continue
        lang["substring_verbs"] = bool(
            lang["cjk"] or data.get("substring_verbs", False))
        lang["verb_set"] = frozenset(lang["send"])
        sets.append(lang)
    return sets


_PHRASE_SETS: list[dict] = _load_phrase_sets()
# Flat target list across languages: the send+target shape is
# only evaluated for a sentence that contains some language's
# credential target (cheap substring pre-check), which keeps
# the per-language tokenisation off the hot path.
_ALL_TARGETS: tuple[str, ...] = tuple(
    t for lang in _PHRASE_SETS for t in lang["target"])
_ALL_OVERRIDES: tuple[str, ...] = tuple(
    p for lang in _PHRASE_SETS for p in lang["override"])
_ALL_CONCEALS: tuple[str, ...] = tuple(
    p for lang in _PHRASE_SETS for p in lang["conceal"])


def _verb_hit(low: str, lang: dict) -> bool:
    if lang.get("substring_verbs"):
        return any(v in low for v in lang["send"])
    verbs = lang.get("verb_set") or frozenset()
    if not verbs:
        return False
    tokens = [t.strip(_TOKEN_EDGE_CHARS) for t in low.split()]
    tokens = [t for t in tokens if t]
    for n in (1, 2, 3):
        for i in range(len(tokens) - n + 1):
            if " ".join(tokens[i:i + n]) in verbs:
                return True
    return False


def _phrase_hit(low: str) -> bool:
    if any(neg in low for neg in _PHRASE_NEGATIONS):
        return False
    if any(p in low for p in _ALL_OVERRIDES) \
            or any(p in low for p in _ALL_CONCEALS):
        return True
    if not any(t in low for t in _ALL_TARGETS):
        return False
    for lang in _PHRASE_SETS:
        if _verb_hit(low, lang) \
                and any(t in low for t in lang["target"]):
            return True
    return False


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------

# The non-English phrase tripwire is capped per description
# (head + tail windows): it is the expensive check. The anchor
# shapes themselves are linear per sentence and run over the
# full text — see scan_manifest.
_MAX_MATCH_CHARS = 8000


def _snippet(text: str, limit: int = 120) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit - 1] + "…"


# --- Clause-level shape evaluation (second fix wave) ----------------
#
# The first fix wave scoped the credential conjunction to a
# sentence; the re-review showed comma clauses inside one
# sentence still pool their anchors (a benign payload clause +
# a negated safety clause assembled a BLOCK), that a verb must
# GOVERN the target to complete the shape ("redact any private
# key material before sending the bundle" — the send's object
# is the bundle, not the key), and that sentence-wide consent
# laundered a same-sentence exfiltration clause. The evaluator
# below works per clause with per-occurrence negation.

_GOVERN_WINDOW = 48  # chars after a verb in which its object target sits

_ANAPHOR_RE = re.compile(r"\b(its|the) contents\b|\bthem\b")

# Redaction markers: a disclose verb whose clause shows the
# user only a partial form ("show only its last four
# characters") is protection, not disclosure.
_REDACTION_RE = re.compile(
    r"\bonly\b[^,;]{0,40}(last|first) (\w+ )?(characters|digits|chars)"
    r"|\b(redact|redacted|redaction|masked|masking)\b")

# Follow/apply-the-note directive: the marker that turns a
# quoted span from an example into the operative instruction.
_FOLLOW_NOTE_RE = re.compile(
    r"\b(follow|apply|obey|comply with|adhere to)\b[^,;]{0,30}"
    r"\b(note|text|instructions?|example|quote|wording)\b"
    r"|\bdo exactly (what|as)\b")


def _negated_spans(s: str) -> list[tuple[int, int]]:
    """Spans of the verbs governed by a negation in `s`."""
    return [m.span(2) for m in _NEGATED_ACTION_RE.finditer(s)]


def _unnegated(regexes, s: str, neg_spans) -> list:
    """Matches of the anchor regexes whose head verb is not
    governed by a negation."""
    out = []
    for rx in regexes:
        for m in rx.finditer(s):
            if not any(a <= m.start() < b for a, b in neg_spans):
                out.append(m)
    return out


def _target_spans(s: str) -> list[tuple[int, int]]:
    return [m.span() for rx in _CREDENTIAL_RES
            for m in rx.finditer(s)]


def _governs(verb_match, target_spans) -> bool:
    """The verb's object is the credential target: a target
    starts shortly after the verb."""
    return any(0 <= t0 - verb_match.end() <= _GOVERN_WINDOW
               for t0, _t1 in target_spans)


def _clauses(s: str) -> list[str]:
    return [c.strip() for c in re.split(r"[,;]", s) if c.strip()]


def _clause_spans(s: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for m in re.finditer(r"[,;]", s):
        spans.append((start, m.start()))
        start = m.end()
    spans.append((start, len(s)))
    return spans


def _anaphoric_send(send_match, clause: str, targets) -> bool:
    """A send verb whose object is an anaphor ("send its
    contents", "pass them along") with the credential target
    named earlier in the same clause."""
    if not any(t1 <= send_match.start() for _t0, t1 in targets):
        return False
    if "along" in send_match.group(0):
        return True
    return bool(_ANAPHOR_RE.search(
        clause, send_match.end(), send_match.end() + 24))


def _sentence_verdict(sentence_copy: str) -> str | None:
    """'block' | 'caution' | None for ONE normalised sentence."""
    s = sentence_copy
    if any(r.search(s) for r in _CONCEALMENT_RES):
        return "block"
    external = bool(_EXTERNAL_RE.search(s))
    consent_sentence = any(r.search(s) for r in _CONSENT_RES)
    frame_seen = False
    consent_seen = False
    for clause in _clauses(s):
        neg = _negated_spans(clause)
        targets = _target_spans(clause)
        framed = any(r.search(clause) for r in _FRAME_RES)
        consent = any(r.search(clause) for r in _CONSENT_RES)
        if targets:
            sends = _unnegated(_SEND_RES, clause, neg)
            accesses = _unnegated(_ACCESS_RES, clause, neg)
            passintos = _unnegated(_PASSINTO_RES, clause, neg)
            gov_send = any(_governs(m, targets) for m in sends)
            gov_access = any(_governs(m, targets) for m in accesses)
            ana_send = any(_anaphoric_send(m, clause, targets)
                           for m in sends)
            shape = None
            if (frame_seen or framed) and (gov_send or gov_access
                                           or ana_send):
                shape = "framed"
            elif passintos:
                shape = "passinto"  # declarative sidenote shape
            elif (gov_send or ana_send) and external:
                shape = "exfil"  # declarative exfil shape
            if shape:
                if shape == "framed" and not gov_send \
                        and not ana_send and not passintos:
                    # Access-only shape: consent in this or an
                    # earlier clause is the tool's directed mode.
                    suppressed = consent or consent_seen
                else:
                    # Send / pass-into shape: only same-clause
                    # consent can suppress, and never against an
                    # external destination.
                    suppressed = consent and not external
                if not suppressed:
                    return "block"
        frame_seen = frame_seen or framed
        consent_seen = consent_seen or consent
    # Caution tier: a framed credential target paired with an
    # unnegated disclosure verb in the same sentence — unless
    # the disclosure is a redaction (partial display) or the
    # sentence routes through the user's consent.
    if any(r.search(s) for r in _FRAME_RES) \
            and _target_spans(s) and not consent_sentence:
        neg = _negated_spans(s)
        clause_spans = _clause_spans(s)
        for m in _unnegated(_DISCLOSE_RES, s, neg):
            a, b = next(cs for cs in clause_spans
                        if cs[0] <= m.start() < cs[1])
            if not _REDACTION_RE.search(s[a:b]):
                return "caution"
    if any(r.search(s) for r in _STEERING_RES):
        return "caution"
    return None


def _target_fragment(copy: str) -> bool:
    """A sentence that names a credential store as material —
    "the contents of the user's keychain", "the user's ssh
    key" — for the split-shape combination. A bare mention in
    passing (a path reference, a settings noun) does not
    qualify on its own."""
    if "contents of" in copy and _target_spans(copy):
        return True
    for rx in _CREDENTIAL_RES:
        for m in rx.finditer(copy):
            before = copy[max(0, m.start() - 16):m.start()]
            if "user's" in before or "user’s" in before \
                    or "your " in before:
                return True
    return False


def _send_fragment(copy: str) -> bool:
    """A sentence carrying a framed send / pass-into whose
    object is referred back ("its contents", "pass it along")
    or sent to an external destination — the half of the
    poisoning shape that points at material named elsewhere."""
    if not any(r.search(copy) for r in _FRAME_RES):
        return False
    neg = _negated_spans(copy)
    if _unnegated(_PASSINTO_RES, copy, neg):
        return True
    sends = _unnegated(_SEND_RES, copy, neg)
    if not sends:
        return False
    if _EXTERNAL_RE.search(copy):
        return True
    return any("along" in m.group(0)
               or _ANAPHOR_RE.search(copy, m.end(), m.end() + 24)
               for m in sends)


def scan_manifest(rel: str, text: str, add) -> int:
    """Run the manifest checks over one file's text. `add` is the
    scanner's finding sink (rule, file, line, evidence). Returns
    the number of descriptions checked (0 = not a manifest)."""
    groups = _extract_grouped(text)
    if not groups:
        return 0
    flat: list[tuple[str, str, str]] = []
    for _owner, entries in groups:
        flat.extend(entries)
    lines = _description_lines(text, len(flat))
    idx = 0
    grouped_lines: list[tuple[str, list, list]] = []
    for owner, entries in groups:
        entry_lines = []
        for _e in entries:
            entry_lines.append(lines[idx] if idx < len(lines) else 1)
            idx += 1
        grouped_lines.append((owner, entries, entry_lines))
    count = 0
    for owner, entries, entry_lines in grouped_lines:
        target_entries: set[int] = set()
        frame_send_entries: set[int] = set()
        tool_blocked = False
        for ei, ((name, where, desc), line) in enumerate(
                zip(entries, entry_lines)):
            count += 1
            evidence = f"tool '{name}' {where}: {_snippet(desc)}"
            if _has_hidden(desc):
                add("HIDDEN_TEXT", rel, line, evidence)
            if len(desc) <= _MAX_MATCH_CHARS:
                phrase_text = desc
            else:
                # Head + tail windows for the phrase tripwire:
                # it is the expensive check, so it stays capped.
                phrase_text = desc[:5000] + "\n" + desc[-4000:]
            if _phrase_hit(_match_copy(phrase_text)):
                add("NON_ENGLISH_INSTRUCTION", rel, line, evidence)
            # The anchor shapes run over the FULL description
            # (they are linear per sentence): a poison sentence
            # buried in the deep middle of a long description —
            # worse, \uXXXX-escaped so no raw-text pass can see
            # it either — must not go silent. Only a description
            # past the hard cap falls back to the windows.
            scan_text = desc if len(desc) <= 1_000_000 else phrase_text
            worst: str | None = None
            frag_target_sents: set[int] = set()
            frag_send_sents: set[int] = set()
            for si, sentence in enumerate(
                    _sentences(_unquoted(scan_text))):
                copy = _match_copy(sentence)
                verdict = _sentence_verdict(copy)
                if verdict == "block":
                    worst = "block"
                elif verdict == "caution" and worst is None:
                    worst = "caution"
                # Split-shape bookkeeping: a credential target
                # named as material in one sentence (or on one
                # surface) plus a framed send pointing back at
                # it in a DIFFERENT sentence (or surface) of the
                # same tool is the poisoning shape distributed
                # across the tool. Fragments must be clean (no
                # negation, no consent) and qualified (see
                # _target_fragment / _send_fragment); fragments
                # inside one sentence never combine — that is
                # what the clause evaluator is for.
                clean = not _NEGATED_ACTION_RE.search(copy) \
                    and not any(r.search(copy) for r in _CONSENT_RES)
                if not clean:
                    continue
                if _target_fragment(copy):
                    frag_target_sents.add(si)
                    target_entries.add(ei)
                if _send_fragment(copy):
                    frag_send_sents.add(si)
                    frame_send_entries.add(ei)
            if worst is None:
                # Follow-the-note: an explicit directive to
                # follow/apply a quoted span whose contents carry
                # a credential shape makes the quote the operative
                # instruction — caution, not silence. (A security
                # tool merely QUOTING an example has no such
                # directive and stays clean.)
                spans = _quoted_spans(desc)
                if spans and _FOLLOW_NOTE_RE.search(
                        _match_copy(_unquoted(desc))):
                    for span in spans:
                        span_copy = _match_copy(span)
                        if any(r.search(span_copy)
                               for r in _CONCEALMENT_RES) or (
                                _target_spans(span_copy) and (
                                    _unnegated(_SEND_RES, span_copy,
                                               _negated_spans(span_copy))
                                    or _unnegated(
                                        _ACCESS_RES, span_copy,
                                        _negated_spans(span_copy)))):
                            worst = "caution"
                            break
            split_same_entry = any(
                t != s for t in frag_target_sents
                for s in frag_send_sents)
            if worst == "block":
                add("MCP_DESCRIPTION_POISONING", rel, line, evidence)
                tool_blocked = True
            elif split_same_entry:
                add("MCP_DESCRIPTION_POISONING", rel, line,
                    evidence + " (poisoning shape split across "
                               "this description's sentences)")
                tool_blocked = True
            elif worst == "caution":
                add("MCP_DESCRIPTION_INSTRUCTION", rel, line, evidence)
        if target_entries and frame_send_entries \
                and target_entries != frame_send_entries \
                and not tool_blocked \
                and owner not in ("<server>", "<manifest>"):
            name0, where0, desc0 = entries[0]
            add("MCP_DESCRIPTION_POISONING", rel, entry_lines[0],
                f"tool '{name0}' {where0}: {_snippet(desc0)} "
                f"(poisoning shape split across this tool's "
                f"descriptions)")
    return count


def render_surface(rel: str, text: str) -> str | None:
    """The descriptions of one manifest rendered as a labelled
    prose surface for the --llm lane (None when not a manifest)."""
    descs = extract_descriptions(text)
    if not descs:
        return None
    lines = [f"MCP tool descriptions from {rel} — metadata the "
             f"agent reads when choosing and calling tools:"]
    for name, where, desc in descs:
        lines.append(f"Tool '{name}' ({where}): {desc}")
    return "\n".join(lines)
