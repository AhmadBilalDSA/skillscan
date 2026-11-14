"""Claims check — "says vs does".

A skill's SKILL.md is its own sales pitch: "makes no network calls",
"read-only", "does not read your credentials". Those are checkable
statements. This module extracts the *absolute* capability claims a
skill makes about itself and checks each one against the behaviour
the deterministic scan actually observed (the findings' rule ids).

Discipline, mirroring the rest of the scanner (and hardened by the
feature's adversarial review, which judged scoped/qualified prose
the highest-risk false-positive surface):

* Only concrete capability negations count as claims. Marketing
  ("privacy-first", "designed with care") is not a claim; a claim
  that a skill does MORE than it does is never checked (an
  over-promising description is a quality issue, not a safety one).
* Verbs are precise: a promise not to *store* credentials is not a
  promise not to *read* them, and is checked only against
  store-class behaviour.
* A claim the sentence itself disclaims ("not a read-only tool",
  "not offline-only") is not a claim.
* A claim whose own sentence (or the sentence right after it)
  discloses the behaviour — a scoped component ("the preview is
  read-only; the exporter writes the files"), a destination
  qualifier ("never sends your data to third parties"), an
  exception sentence ("The single exception is…") — is a
  disclosure, not a contradiction.
* Conditional language hedges only the clause it sits in: "can
  optionally send…" discloses that clause's behaviour; the same
  words in an unrelated clause ("You can trust this skill, it
  makes no network calls") do not suppress anything.
* Quoted text (blockquotes) is discussion, not the skill's own
  claim; code fences are not prose; YAML frontmatter is parsed as
  frontmatter — only its `description:` is claim prose, at its own
  line; table rows and list items are individual claim units.
* A contradiction is a CAUTION (rule CLAIM_CONTRADICTED), except a
  no-network / no-credential claim contradicted by an
  exfiltration-class finding, which is a BLOCK
  (CLAIM_EXFIL_CONTRADICTION): the description denies the exact
  behaviour the scan proved. Every rule that can contradict is
  itself at least CAUTION and every exfil-class rule is itself
  BLOCK, so a claims finding can never lift a verdict above what
  the underlying findings already set.

Pure functions over text + rule ids; no I/O, no imports from the
scanner (capability classes are rule-id strings, kept here so this
module stands alone).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# --- observed behaviour, by capability class (rule ids) --------------------

_NETWORK_RULES = {
    "NETWORK_ACCESS", "NETWORK_SEND_DATA", "CURL_PIPE_BASH",
    "DOWNLOAD_AND_RUN", "INSTALL_FROM_URL", "RUNTIME_PACKAGE_INSTALL",
    "PROSE_DOWNLOAD_RUN", "PROSE_FETCH_EXECUTE", "PROSE_PIPE_INSTRUCTION",
    "PROSE_READ_SEND", "READ_AND_DISCLOSE", "CLOUD_METADATA_ACCESS",
    "TAINTED_SEND", "SECRET_FLOW", "EXFIL_COMBINATION",
    "CLOUD_METADATA_EXFIL",
    # A poisoned MCP tool description IS the behaviour-shaping
    # artifact: a skill claiming "no network use" while one of
    # its manifests instructs the agent to read-and-send is
    # contradicted. (Not added to EXFIL_RULES: the BLOCK upgrade
    # stays reserved for proven code-level exfiltration; the
    # poisoning finding itself already blocks the scan.)
    "MCP_DESCRIPTION_POISONING",
}
_CREDENTIAL_RULES = {
    "SSH_CREDENTIAL_READ", "AGENT_CREDENTIAL_READ",
    "CLOUD_CREDENTIAL_READ", "ENV_FILE_READ", "BROWSER_CREDENTIAL_STORE",
    "CREDENTIAL_ENUMERATION", "ENVIRON_SECRET_ACCESS",
    "EXFIL_COMBINATION", "CLOUD_METADATA_EXFIL", "TAINTED_SEND",
    "SECRET_FLOW", "MCP_DESCRIPTION_POISONING",
}
_CREDENTIAL_STORE_RULES = {
    # The skill's own files literally contain credential material:
    # that is stored credentials, whatever the prose says.
    "HARDCODED_SECRET_LIVE", "HARDCODED_SECRET_GENERIC",
}
_WRITE_RULES = {
    "HOME_OR_SYSTEM_WRITE", "AGENT_CONFIG_WRITE", "CHMOD_CHOWN",
    "FILE_DELETE", "RM_RF",
}
_DELETE_RULES = {"FILE_DELETE", "RM_RF"}
_EXEC_RULES = {
    "SHELL_SUBPROCESS", "SHELL_OS_SYSTEM", "EVAL_EXEC",
    "SUBSTITUTION_EXEC", "DECODE_AND_RUN", "DYNAMIC_IMPORT",
    "MCP_UNRESTRICTED_EXEC", "MCP_SERVER_COMMAND",
    "PACKAGE_INSTALL_SCRIPT_EXEC", "REVERSE_SHELL", "ENV_INJECTION",
    "ENV_INJECTION_INSTALL",
}
_PERSISTENCE_RULES = {"PERSISTENCE"}

# Findings that prove data actually leaves (or is staged to leave)
# with credential material in hand — the exfiltration class.
EXFIL_RULES = {"EXFIL_COMBINATION", "CLOUD_METADATA_EXFIL", "TAINTED_SEND"}


# --- claim shapes ------------------------------------------------------------

@dataclass(frozen=True)
class _ClaimKind:
    kind: str
    says: str                       # short label for the report
    patterns: tuple[re.Pattern, ...]
    contradicts: frozenset          # rule ids that contradict the claim
    disclosure: re.Pattern | None   # affirmative same-class behaviour
    #                                 stated in the claim's own sentence


def _p(*patterns: str) -> tuple[re.Pattern, ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


def _d(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


_KINDS: tuple[_ClaimKind, ...] = (
    _ClaimKind(
        "no_network", "no network use",
        _p(r"\bno network\b",
           r"\bno internet\b",
           r"\b(does not|doesn't|do not|never|won't) (access|use|contact|"
           r"connect to|talk to|reach) (the )?(network|internet|web)\b",
           r"\b(works|runs|operates) (fully |entirely |completely )?"
           r"offline\b",
           r"\boffline[ -]only\b",
           r"\b(does not|doesn't|never) sends? (any |your |the )?"
           r"(data|information|anything)\b",
           r"\bnothing (is )?(sent|uploaded|transmitted)\b",
           r"\bnothing (ever )?(leaves|sends|transmits)\b[^.;]{0,30}?\b"
           r"(your )?(machine|computer|device)\b",
           r"\bnothing leaves your (machine|computer|device)\b",
           r"\bno data (is )?(sent|uploaded|transmitted)\b",
           r"\bmakes? no (outbound|external) (calls|requests|connections)\b"),
        frozenset(_NETWORK_RULES),
        _d(r"\b(sends|posts|uploads|fetches|contacts|downloads) (data|"
           r"a |an |the |your |requests?|updates?|telemetry|results?)\b")),
    _ClaimKind(
        "no_credential", "does not read credentials",
        _p(r"\b(does not|doesn't|do not|never|won't) (read|reads|access|"
           r"accesses|touch|touches|collect|collects|see|ask for|"
           r"request|requests)\b[^.;]{0,50}?\b(credentials?|passwords?|"
           r"ssh keys?|api keys?|private keys?|tokens?|secrets?)\b",
           r"\b(credentials?|passwords?|ssh keys?|api keys?|private "
           r"keys?) (are |is )?never (read|accessed|touched|collected)\b",
           r"\bno (access to|reading of) (your )?(credentials?|"
           r"passwords?|ssh)\b"),
        frozenset(_CREDENTIAL_RULES),
        _d(r"\b(reads|accesses|loads|opens|uses) (your |the |its )?"
           r"(credentials?|passwords?|ssh|api keys?|tokens?)\b")),
    _ClaimKind(
        "no_credential_store", "does not store credentials",
        _p(r"\b(does not|doesn't|do not|never|won't) (store|stores|save|"
           r"saves|keep|keeps|retain|retains|persist|persists)\b"
           r"[^.;]{0,50}?\b(credentials?|passwords?|api keys?|tokens?|"
           r"secrets?)\b",
           r"\bno (credential|password) storage\b"),
        frozenset(_CREDENTIAL_STORE_RULES),
        _d(r"\b(stores|saves|keeps a copy of|writes down) (your |the )?"
           r"(credentials?|passwords?|api keys?|tokens?)\b")),
    _ClaimKind(
        "no_write", "does not write or change files",
        _p(r"\bread[ -]only\b",
           r"\b(does not|doesn't|do not|never) (write|writes|modify|"
           r"modifies|change|changes|alter|create|creates) (any |your |"
           r"the )?(files?|anything|data)\b",
           r"\bnever writes\b",
           r"\bwrites nothing\b",
           r"\bmakes? no changes\b",
           r"\bno file writes\b",
           r"\bleaves your files (untouched|unchanged|alone)\b"),
        frozenset(_WRITE_RULES),
        _d(r"\b(writes|modifies|creates|renames|moves) (files?|the |"
           r"your |output|a |an )\b")),
    _ClaimKind(
        "no_delete", "never deletes files",
        _p(r"\b(does not|doesn't|do not|never) (delete|deletes|remove|"
           r"removes|erase) (any |your |the )?(files?|anything|data)\b",
           r"\bnever deletes\b",
           r"\bdeletes nothing\b",
           r"\bno file deletion\b"),
        frozenset(_DELETE_RULES),
        _d(r"\b(deletes|removes|erases) (files?|the |your |them|old )\b")),
    _ClaimKind(
        "no_exec", "does not run commands or code",
        _p(r"\b(does not|doesn't|do not|never) (run|runs|execute|"
           r"executes|invoke|invokes|spawn) (shell |external |system |"
           r"any )?(commands?|programs?|processes|code|scripts?|"
           r"binaries)\b",
           r"\bruns? no (shell commands|subprocesses|external "
           r"(commands|programs))\b",
           r"\bspawns? no (subprocesses|processes)\b",
           r"\bno (shell access|subprocess|command execution)\b",
           r"\bdoes not use subprocess\b"),
        frozenset(_EXEC_RULES),
        _d(r"\b(runs|executes|invokes|spawns) (shell |external |system )?"
           r"(commands?|programs?|processes|scripts?)\b")),
    _ClaimKind(
        "no_persistence", "does not persist itself",
        _p(r"\bno persistence\b",
           r"\b(does not|doesn't|do not|never) (persist|persists|"
           r"install itself|add itself)\b"),
        frozenset(_PERSISTENCE_RULES),
        _d(r"\b(installs itself|adds itself|persists)\b")),
)

# A hedge hedges only the clause it sits in (see _clause_spans).
_HEDGE_RE = re.compile(
    r"\b(optionally|if you|when you|you can|on request|at your request|"
    r"opt[ -]?in|by default|may also|might|configured to|with your "
    r"permission|when (enabled|configured|asked)|enable (it|this|that)|"
    r"standard workflow|normal operation)\b",
    re.IGNORECASE)

# The sentence right after a claim, disclosing the exception.
_EXCEPTION_RE = re.compile(
    r"\b(exception|except|only when|only if|the separate|apart from|"
    r"apply (command|mode|step))\b", re.IGNORECASE)

# A claim phrase immediately disclaimed: "not a read-only tool",
# "isn't offline-only", "never claimed to be offline".
_DISCLAIM_WINDOW_RE = re.compile(
    r"\b(not|n't|never claimed to be|not actually|not really)\s+"
    r"(a\s+|an\s+|really\s+)?$", re.IGNORECASE)

# A send claim followed by a destination qualifier is a narrower
# claim than the scan can judge: findings do not record who owns
# the destination.
_QUALIFIER_AFTER_RE = re.compile(
    r"^\s*(to|with|for)\s+(third parties|anyone else|anybody else|"
    r"external (servers|parties|services))\b", re.IGNORECASE)

_NEGATED_BEFORE_RE = re.compile(
    r"\b(never|not|n't|does not|doesn't|do not|cannot|can't|no)\s+"
    r"(?:\w+\s+){0,2}$", re.IGNORECASE)

_CLAUSE_SPLIT_RE = re.compile(r"[,;]|\s+(?:and|but|while|although)\s+",
                              re.IGNORECASE)


@dataclass
class Claim:
    kind: str
    says: str
    quote: str          # the sentence the claim was found in
    file: str
    line: int


@dataclass
class ClaimCheck:
    claim: Claim
    status: str                          # "matches" | "contradicted"
    contradicted_by: list[dict] = field(default_factory=list)
    exfil: bool = False                  # block-tier contradiction

    def to_dict(self) -> dict:
        return {
            "kind": self.claim.kind,
            "says": self.claim.says,
            "quote": self.claim.quote,
            "file": self.claim.file,
            "line": self.claim.line,
            "status": self.status,
            "contradicted_by": self.contradicted_by,
            "tier": ("block" if self.exfil else
                     "caution" if self.status == "contradicted" else None),
        }


def _split_frontmatter(text: str) -> tuple[str | None, int, str]:
    """Split a leading YAML frontmatter block off the body.

    Returns (description value or None, description line, body text
    with the frontmatter lines blanked so body line numbers are
    preserved). Only `description:` is claim prose — the rest of the
    frontmatter is metadata, not statements about behaviour."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, 0, text
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            end = i
            break
    if end is None:
        return None, 0, text
    description: str | None = None
    description_line = 0
    i = 1
    while i < end:
        m = re.match(r"^description\s*:\s*(.*)$", lines[i])
        if m:
            description_line = i + 1
            parts = [m.group(1).strip().strip("'\"")]
            j = i + 1
            while j < end and (lines[j].startswith((" ", "\t")) or
                               not lines[j].strip()):
                if lines[j].strip():
                    parts.append(lines[j].strip())
                j += 1
            description = " ".join(p for p in parts if p) or None
            break
        i += 1
    blanked = [""] * (end + 1) + lines[end + 1:]
    return description, description_line, "\n".join(blanked)


def _paragraphs(text: str) -> list[list[tuple[int, str]]]:
    """Prose paragraphs as (line number, text) line lists. Fenced code
    blocks and blockquote lines are not the skill's own prose claims.
    Table rows and list items are individual claim units: each is a
    self-contained statement with its own line."""
    paras: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []

    def flush() -> None:
        nonlocal current
        if current:
            paras.append(current)
            current = []

    in_fence = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            flush()
            continue
        if in_fence or stripped.startswith(">"):
            continue
        if not stripped:
            flush()
            continue
        if stripped.startswith("|"):
            flush()
            paras.append([(lineno, " ".join(
                p.strip() for p in stripped.strip("|").split("|")))])
            continue
        if re.match(r"^([-*•]|\d+[.)])\s", stripped):
            flush()
            paras.append([(lineno,
                            re.sub(r"^([-*•]|\d+[.)])\s+", "", stripped))])
            continue
        cleaned = re.sub(r"^\s*#{1,6}\s+", "", raw)
        current.append((lineno, cleaned.strip()))
    flush()
    return paras


def _sentences(para: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Split a paragraph into (start line, sentence) pairs. Semicolons
    do NOT split: what follows one is usually the claim's own scope."""
    joined_parts: list[str] = []
    starts: list[tuple[int, int]] = []     # (offset, line number)
    offset = 0
    for lineno, line_text in para:
        starts.append((offset, lineno))
        joined_parts.append(line_text)
        offset += len(line_text) + 1
    joined = " ".join(joined_parts)
    out: list[tuple[int, str]] = []
    for m in re.finditer(r"[^.!?]+(?:[.!?]+|$)", joined):
        sentence = m.group(0).strip()
        if len(sentence) < 8:
            continue
        line = para[0][0]
        for off, lineno in starts:
            if off <= m.start():
                line = lineno
            else:
                break
        out.append((line, sentence))
    return out


def _clause_spans(sentence: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    start = 0
    for m in _CLAUSE_SPLIT_RE.finditer(sentence):
        spans.append((start, m.start()))
        start = m.end()
    spans.append((start, len(sentence)))
    return spans


def _match_text(sentence: str) -> str:
    """The sentence with markdown emphasis and simple HTML tags
    removed, for matching: '**never** sends data' and
    '<em>never</em> sends data' make the same claim as 'never sends
    data'. The original sentence is kept for the report's quote.
    Character offsets shift, so matching runs entirely on this
    normalised copy (spans never cross back to the original)."""
    text = re.sub(r"<[^>]{1,40}>", " ", sentence)
    text = re.sub(r"[*_`]+", "", text)
    return re.sub(r"\s+", " ", text)


def _disclosed_in_sentence(kind: _ClaimKind, matched: str,
                           claim_span: tuple[int, int]) -> bool:
    """The claim's own sentence affirmatively states the behaviour
    (scoped to another component, or stated outright): a disclosure,
    not a contradiction. The claim's own span is masked out, and a
    'disclosure' that is itself negated does not count."""
    if kind.disclosure is None:
        return False
    masked = (matched[:claim_span[0]] + " " * (claim_span[1] - claim_span[0])
              + matched[claim_span[1]:])
    for m in kind.disclosure.finditer(masked):
        window = masked[max(0, m.start() - 36):m.start()]
        if _NEGATED_BEFORE_RE.search(window):
            continue
        return True
    return False


def _claims_in_sentence(rel: str, line: int, sentence: str,
                        seen: set) -> list[Claim]:
    matched = _match_text(sentence)
    clauses = _clause_spans(matched)
    out: list[Claim] = []
    for kind in _KINDS:
        for pattern in kind.patterns:
            m = pattern.search(matched)
            if m is None:
                continue
            window = matched[max(0, m.start() - 36):m.start()]
            if _DISCLAIM_WINDOW_RE.search(window):
                continue            # "not a read-only tool"
            if _QUALIFIER_AFTER_RE.match(matched[m.end():m.end() + 48]):
                continue            # "never sends data to third parties"
            clause = next((s for s in clauses
                           if s[0] <= m.start() < s[1]), clauses[-1])
            if _HEDGE_RE.search(matched[clause[0]:clause[1]]):
                continue            # hedged in its own clause = disclosed
            if _disclosed_in_sentence(kind, matched, m.span()):
                continue            # scope stated in the same breath
            key = (kind.kind, sentence)
            if key not in seen:
                seen.add(key)
                out.append(Claim(kind=kind.kind, says=kind.says,
                                 quote=sentence[:160], file=rel,
                                 line=line))
            break                   # one claim per kind/sentence
    return out


def extract_claims(rel: str, text: str) -> list[Claim]:
    """All absolute capability claims in one SKILL.md text."""
    claims: list[Claim] = []
    seen: set[tuple[str, str]] = set()
    description, description_line, body = _split_frontmatter(text)
    if description:
        for _line, sentence in _sentences([(description_line,
                                            description)]):
            if not sentence.endswith("?"):
                claims += _claims_in_sentence(
                    rel, description_line, sentence, seen)
    for para in _paragraphs(body):
        sentences = _sentences(para)
        for idx, (line, sentence) in enumerate(sentences):
            if sentence.endswith("?"):
                continue                    # a question is not a claim
            if idx + 1 < len(sentences) and \
                    _EXCEPTION_RE.search(sentences[idx + 1][1]):
                continue                    # exception stated next
            claims += _claims_in_sentence(rel, line, sentence, seen)
    return claims


def check_claims(claims: list[Claim], findings) -> list[ClaimCheck]:
    """Check extracted claims against the scan's findings (any objects
    with .rule/.file/.line attributes — the scanner's Finding works)."""
    observed = {f.rule for f in findings}
    by_rule: dict[str, object] = {}
    for f in findings:
        by_rule.setdefault(f.rule, f)
    kinds = {k.kind: k for k in _KINDS}
    checks: list[ClaimCheck] = []
    for claim in claims:
        kind = kinds[claim.kind]
        hits = sorted(observed & kind.contradicts)
        exfil = claim.kind in ("no_network", "no_credential") and \
            bool(observed & EXFIL_RULES)
        if hits:
            checks.append(ClaimCheck(
                claim=claim, status="contradicted",
                contradicted_by=[
                    {"rule": r, "file": by_rule[r].file,
                     "line": by_rule[r].line} for r in hits],
                exfil=exfil))
        else:
            checks.append(ClaimCheck(claim=claim, status="matches"))
    return checks
