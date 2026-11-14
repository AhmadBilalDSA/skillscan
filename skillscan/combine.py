"""Combination scan: judge a folder of skills as a set.

A solo scan judges one skill at a time. But an agent rarely
runs one skill: it runs a set, and a harmful capability can
be split across two members of the set — one skill reads
credentials, another sends data off the machine; one deletes
files, another installs persistence. Each is a CAUTION on its
own; together they are the shape of an attack.

``--combine`` scans every skill folder inside a parent
folder, reports each member's own verdict exactly as a solo
scan would (unchanged, never softened, never raised), and
adds a caution-class section listing the cross-skill
capability pairs it found. A member is an immediate
subfolder containing a SKILL.md in any form — a symlinked
or otherwise unreadable SKILL.md still makes the folder a
member, and the member's own scan reports it honestly
(e.g. SCAN_INCOMPLETE) rather than the member silently
vanishing from a set that then reads PASS. A combination
is reported only when the two halves live in DIFFERENT
skills: a single skill holding both halves is the solo
scan's business (and rules like EXFIL_COMBINATION already
judge it there), so the combination scan never
double-counts it and never becomes a back door for raising
a solo verdict. If one member's scan fails outright, the
whole set scan fails (exit 3) — deliberate: a set verdict
built on a partial scan would be a false all-clear.

Capabilities are derived from the scan's findings, using
rule sets kept deliberately tight, with three refinements
so the plain-English labels stay honest:

- a finding in a documentation file (the scanner's own doc
  extensions) does not by itself create a capability,
  unless the rule is a prose/instruction rule: a guide that
  *mentions* a credential path, or shows `os.remove` in a
  code fence, is not the skill doing it — while prose that
  *instructs* the agent (PROSE_* rules, manifest
  poisoning) is behaviour;
- `ENVIRON_SECRET_ACCESS` counts as credential-read only
  when a secret-shaped variable name appears among the
  finding's hits (the scanner's own `SECRET_NAME_RE`
  discipline, applied to every hit via
  `ScanResult.gate_signals`, not just the first hit's
  evidence snippet): reading `APP_MODE` is configuration,
  not credentials. (One limit: a JavaScript environ
  accessor whose argument wraps onto the next line is not
  gate-visible — JS has no AST layer in the scanner; the
  Python equivalent is covered via the AST pass.)
- `BROWSER_CREDENTIAL_STORE` counts only when some hit
  names credential-store material (the store alternatives
  of the rule's own pattern — a `Login Data` file,
  `logins.json`, a wallet file, a profile Cookies file —
  again judged across all hits via the gate signals):
  merely launching a browser is not reading its store.

- ``credential-read``: rules that read the user's
  credential material (SSH keys, agent/cloud credentials,
  browser credential stores, .env files, environment
  secrets), plus MCP_DESCRIPTION_POISONING (whose
  definition is read-a-credential-store-and-pass-it-along)
  and MCP_UNRESTRICTED_READ (an any-file read tool can
  read credential stores by construction).
- ``network-send``: rules that move data off the machine
  (payload sends, tainted sends, read-and-disclose flows),
  plus the scanner's send-channel marker (see below). A
  bare network fetch (``NETWORK_ACCESS``) is NOT a send.
- ``credential-store-read`` + ``network-access``: the
  store readers (SSH keys, browser/agent stores,
  unrestricted-read tools) are never a benign-configuration
  pattern, so next to them even a bare network capability
  completes the pair.
- ``file-delete`` and ``persistence``: the two rule
  families themselves.

The send half also uses the scanner's own send-channel
marker (`ScanResult.has_send_channel`): a resolved socket
or HTTP send is a send channel for pairing even when no
single rule names it — the same flag the solo
EXFIL_COMBINATION rule uses. One documented limit: an
untainted `smtplib` send is not a send channel anywhere in
SkillScan, solo or set (SMTP counts as a channel in the
solo scanner only when credential data flows into it,
which produces TAINTED_SEND — and that does count here).
Widening it would change solo EXFIL_COMBINATION behaviour,
so it stays a base-scanner decision, not this feature's.

Coverage is reported, not implied: subfolders that are not
members but contain skills below the top level, members
containing nested skill folders, excluded hidden/pruned/
symlinked folders holding a SKILL.md, and members whose
scan skipped suspicious files all appear as coverage
notes, and the "no combinations" line is scoped to the
members actually scanned.

The set's exit code is the worst member's exit code,
raised to 1 (caution) if combinations were found and
every member passed — combinations are caution-class
reporting and can never produce a BLOCK on their own.
"""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path

from .rules import RULES
from .scanner import (DOC_EXTENSIONS, DOC_NAMES, SECRET_NAME_RE,
                      SKIP_DIRS, STORE_MATERIAL_RE, ScanResult,
                      scan_folder)

SET_FORMAT = "skillscan-set/1"

# Evidence token used when a member's send capability comes
# from the scanner's send-channel marker rather than a rule.
SEND_CHANNEL = "SEND_CHANNEL"

_EVIDENCE_LABELS = {
    SEND_CHANNEL: "a resolved send channel in code "
                  "(socket/HTTP send)",
}


class SetError(Exception):
    """The target is not a folder of skills this mode can scan."""


CAPABILITY_RULES: dict[str, frozenset[str]] = {
    "credential-read": frozenset({
        "SSH_CREDENTIAL_READ", "AGENT_CREDENTIAL_READ",
        "CLOUD_CREDENTIAL_READ", "ENV_FILE_READ",
        "BROWSER_CREDENTIAL_STORE", "CREDENTIAL_ENUMERATION",
        "ENVIRON_SECRET_ACCESS", "MCP_DESCRIPTION_POISONING",
        "MCP_UNRESTRICTED_READ",
    }),
    "network-send": frozenset({
        "NETWORK_SEND_DATA", "TAINTED_SEND", "SECRET_FLOW",
        "READ_AND_DISCLOSE", "PROSE_READ_SEND",
        "CLOUD_METADATA_EXFIL",
    }),
    "network-access": frozenset({"NETWORK_ACCESS"}),
    "file-delete": frozenset({"FILE_DELETE", "RM_RF"}),
    "persistence": frozenset({"PERSISTENCE"}),
}

_STORE_READ_RULES = frozenset({
    "SSH_CREDENTIAL_READ", "AGENT_CREDENTIAL_READ",
    "CLOUD_CREDENTIAL_READ", "BROWSER_CREDENTIAL_STORE",
    "MCP_UNRESTRICTED_READ",
})

# Rules that ARE prose behaviour (instructions to the agent),
# so their findings create capabilities even in doc files.
_PROSE_RULES = frozenset(
    {r.id for r in RULES if r.id.startswith("PROSE_")}
    | {"READ_AND_DISCLOSE", "SECRET_FLOW",
       "MCP_DESCRIPTION_POISONING", "MCP_DESCRIPTION_INSTRUCTION"})

CAPABILITY_LABELS = {
    "credential-read": "read credentials",
    "credential-store-read": "read stored credentials",
    "network-send": "send data over the network",
    "network-access": "reach the network",
    "file-delete": "delete files",
    "persistence": "install persistence",
}

_STORE_PAIR_NOTE = (
    "One of these skills reads stored credentials (SSH "
    "keys, browser or agent credential stores) and the "
    "other can send data over the network — read with one, "
    "send with the other is the shape of a credential "
    "theft.")
_STORE_PAIR_NOTE_FETCH_ONLY = (
    "One of these skills reads stored credentials (SSH "
    "keys, browser or agent credential stores) and the "
    "other can reach the network at all. Reading stored "
    "credentials is the first half of a credential theft; "
    "any send added to the other skill would complete it.")

# (pair id, family, left capability, left rules or None for
# the capability's own set, right capability, right rules or
# None, plain-English note). Within one family, an ordered
# pair of skills is reported once — the first matching pair
# wins — so the credential-exfiltration story is never told
# twice about the same two skills at two strengths.
PAIRS = (
    (
        "credential-read + network-send", "exfil",
        "credential-read", None,
        "network-send", None,
        "Run together in one agent, these two could read "
        "credentials with one skill and send them off this "
        "machine with the other.",
    ),
    (
        "credential-store-read + network-access", "exfil",
        "credential-store-read", _STORE_READ_RULES,
        "network-access",
        CAPABILITY_RULES["network-access"]
        | CAPABILITY_RULES["network-send"],
        _STORE_PAIR_NOTE,
    ),
    (
        "file-delete + persistence", "destroy",
        "file-delete", None,
        "persistence", None,
        "Run together in one agent, these two could delete "
        "files with one skill while the other keeps a "
        "foothold on the machine afterwards.",
    ),
)

_VERDICT_RANK = {"PASS": 0, "CAUTION": 1, "BLOCK": 2}
_RENDER_CAP = 50


def _safe(name: str) -> str:
    """Make a folder-controlled name safe to print: control
    and Unicode format characters become '?', so a hostile
    name cannot forge lines, inject escapes, or reorder
    text with bidi controls."""
    return "".join(
        ch if (32 <= ord(ch) and ord(ch) != 127
               and unicodedata.category(ch) != "Cf") else "?"
        for ch in name)


def _is_doc_file(rel: str) -> bool:
    path = Path(rel)
    return (path.suffix.lower() in DOC_EXTENSIONS
            or path.name.upper() in DOC_NAMES)


def _finding_counts(finding, rule_set: frozenset[str],
                    signals: dict) -> bool:
    """Does this finding evidence the capability `rule_set`
    describes? Applies the doc-tier, secret-name, and
    store-evidence refinements from the module docstring.
    The secret-name and store gates judge ALL hits of the
    finding via the scanner's gate signals (a benign first
    hit must not mask a credential hit later in the same
    file); the finding's own evidence snippet is the
    fallback for findings built outside the scan's add()
    path, which carry no signals."""
    if finding.rule not in rule_set:
        return False
    if finding.rule == "ENVIRON_SECRET_ACCESS":
        entry = signals.get((finding.rule, finding.file))
        named = ("secret-name" in entry) if entry is not None \
            else bool(SECRET_NAME_RE.search(finding.evidence))
        if not named:
            return False
    if finding.rule == "BROWSER_CREDENTIAL_STORE":
        entry = signals.get((finding.rule, finding.file))
        material = ("store-material" in entry) \
            if entry is not None \
            else bool(STORE_MATERIAL_RE.search(finding.evidence))
        if not material:
            return False
    if _is_doc_file(finding.file) \
            and finding.rule not in _PROSE_RULES:
        return False
    return True


class Member:
    def __init__(self, path: Path, result: ScanResult):
        self.name = path.name
        self.path = path
        self.result = result

    def rules_for(self, rule_set: frozenset[str],
                  allow_channel: bool = False) -> list[str]:
        matched = sorted({
            f.rule for f in self.result.findings
            if _finding_counts(f, rule_set,
                               self.result.gate_signals)})
        if allow_channel and not matched \
                and self.result.has_send_channel:
            matched = [SEND_CHANNEL]
        return matched

    def capabilities(self) -> dict[str, list[str]]:
        caps = {}
        for cap, rule_set in CAPABILITY_RULES.items():
            matched = self.rules_for(
                rule_set, allow_channel=(cap == "network-send"))
            if matched:
                caps[cap] = matched
        if "network-send" in caps:
            # "can reach the network" adds nothing next to
            # "can send data over the network" in a summary.
            caps.pop("network-access", None)
        return caps

    @property
    def finding_count(self) -> int:
        return sum(max(1, f.count) for f in self.result.findings)


class Combination:
    def __init__(self, pair_id: str, left: Member, left_cap: str,
                 left_rules: list[str], right: Member,
                 right_cap: str, right_rules: list[str],
                 note: str):
        self.pair = pair_id
        self.left = left
        self.left_cap = left_cap
        self.left_rules = left_rules
        self.right = right
        self.right_cap = right_cap
        self.right_rules = right_rules
        self.note = note


class SetResult:
    def __init__(self, root: Path, members: list[Member],
                 combinations: list[Combination],
                 notices: list[str]):
        self.root = root
        self.members = members
        self.combinations = combinations
        self.notices = notices
        worst = max((m.result.verdict for m in members),
                    key=_VERDICT_RANK.__getitem__, default="PASS")
        if combinations and worst == "PASS":
            # Defensive: unreachable with today's severities
            # (every capability rule is block/caution, so a
            # capability holder is never PASS), but the class
            # contract is "combinations are at least caution".
            worst = "CAUTION"
        self.verdict = worst
        self.exit_code = max(
            [m.result.exit_code for m in members]
            + [1 if combinations else 0])

    def to_dict(self) -> dict:
        return {
            "format": SET_FORMAT,
            "target": str(self.root),
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "skills": [
                {
                    "name": m.name,
                    "verdict": m.result.verdict,
                    "exit_code": m.result.exit_code,
                    "findings": m.finding_count,
                    "capabilities": m.capabilities(),
                }
                for m in self.members
            ],
            "combinations": [
                {
                    "pair": c.pair,
                    "skills": [c.left.name, c.right.name],
                    "capabilities": [c.left_cap, c.right_cap],
                    "rules": {
                        c.left.name: c.left_rules,
                        c.right.name: c.right_rules,
                    },
                    "note": c.note,
                }
                for c in self.combinations
            ],
            "notices": list(self.notices),
        }


def _has_skill_md(folder: Path) -> bool:
    """A SKILL.md entry in any form (file, symlink, dangling)."""
    return os.path.lexists(folder / "SKILL.md")


def _nested_skill_dirs(folder: Path,
                       max_depth: int = 3) -> tuple[list[str], bool]:
    """(relative paths of directories below `folder` that
    hold a SKILL.md, whether the search hit its depth limit
    with more below). Bounded, never follows symlinks,
    prunes the scanner's own skip dirs."""
    found = []
    truncated = False
    base_depth = len(folder.parts)
    for dirpath, dirnames, _filenames in os.walk(
            folder, followlinks=False):
        current = Path(dirpath)
        depth = len(current.parts) - base_depth
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS
                       and not d.startswith(".")]
        if depth >= max_depth:
            if dirnames:
                truncated = True
            dirnames[:] = []
        if depth >= 1 and _has_skill_md(current):
            found.append(current.relative_to(folder).as_posix())
    return sorted(found), truncated


def scan_set(root: Path) -> SetResult:
    try:
        children = sorted(
            (c for c in root.iterdir() if c.is_dir()
             or c.is_symlink()),
            key=lambda p: p.name)
    except OSError as exc:
        raise SetError(f"could not read the folder {root}: "
                       f"{exc.strerror or exc}") from exc

    notices: list[str] = []
    if _has_skill_md(root):
        notices.append(
            "the folder itself is also a skill (it has a "
            "SKILL.md); --combine judged only its subfolders — "
            "scan it on its own to judge it.")

    members: list[Member] = []
    for child in children:
        name = child.name
        excluded_reason = None
        if child.is_symlink():
            excluded_reason = "it is a symlink"
        elif name.startswith("."):
            excluded_reason = "it is a hidden folder"
        elif name in SKIP_DIRS:
            excluded_reason = "its name is one the scanner prunes"
        if excluded_reason is not None:
            nested, truncated = _nested_skill_dirs(child)
            if _has_skill_md(child):
                notices.append(
                    f"not scanned: {name}/ holds a SKILL.md "
                    f"but was left out because {excluded_reason}; "
                    "scan it directly to judge it.")
            elif nested:
                notices.append(
                    f"not scanned: {name}/ contains skill "
                    f"folder(s) below the top level "
                    f"({', '.join(nested[:3])}) but was left out "
                    f"because {excluded_reason}; scan it "
                    "directly to judge them.")
            if truncated:
                notices.append(
                    f"the coverage search inside {name}/ "
                    "stopped at depth 3; deeper skill folders, "
                    "if any, are not listed here.")
            continue
        if _has_skill_md(child):
            result = scan_folder(child)
            member = Member(child, result)
            members.append(member)
            nested, truncated = _nested_skill_dirs(child)
            if nested:
                notices.append(
                    f"member {name} contains nested skill "
                    f"folder(s) ({', '.join(nested[:3])}); they "
                    f"were scanned as part of {name}, not as "
                    "separate members.")
            if truncated:
                notices.append(
                    f"the coverage search inside member {name} "
                    "stopped at depth 3; deeper nested skill "
                    "folders, if any, are not listed here.")
            suspicious = [s for s in result.skipped if s.suspicious]
            if suspicious:
                notices.append(
                    f"member {name}: the scan skipped "
                    f"{len(suspicious)} suspicious file(s) it "
                    "could not read; a solo scan of the member "
                    "lists them.")
            for pruned in sorted(SKIP_DIRS):
                pruned_path = child / pruned
                try:
                    if pruned_path.is_dir() and any(
                            pruned_path.iterdir()):
                        notices.append(
                            f"member {name} contains a "
                            f"{pruned}/ folder, whose contents "
                            "the scan does not read.")
                except OSError:
                    continue
        else:
            nested, truncated = _nested_skill_dirs(child)
            if nested:
                notices.append(
                    f"not scanned: {name}/ has no SKILL.md of "
                    f"its own but contains skill folder(s) "
                    f"below the top level ({', '.join(nested[:3])}); "
                    f"--combine does not scan into it — run "
                    f"--combine on {name}/ itself to judge them.")
            if truncated:
                notices.append(
                    f"the coverage search inside {name}/ "
                    "stopped at depth 3; deeper skill folders, "
                    "if any, are not listed here.")

    if not members:
        hint = ""
        if notices:
            hint = (" (Coverage notes: "
                    + notices[0] + ")")
        raise SetError(
            f"no skill folders found in {root}: --combine "
            "expects a folder whose immediate subfolders are "
            "skills (each containing a SKILL.md). Scan a "
            "single skill by pointing at its own folder "
            f"instead.{hint}")

    combinations: list[Combination] = []
    claimed: set[tuple[str, str, str]] = set()
    for pair_id, family, lcap, lrules, rcap, rrules, note in PAIRS:
        left_set = lrules if lrules is not None \
            else CAPABILITY_RULES[lcap]
        right_set = rrules if rrules is not None \
            else CAPABILITY_RULES[rcap]
        for left in members:
            left_matched = left.rules_for(left_set)
            if not left_matched:
                continue
            for right in members:
                if right is left:
                    continue
                key = (family, left.name, right.name)
                if key in claimed:
                    continue
                right_matched = right.rules_for(
                    right_set,
                    allow_channel=rcap in ("network-send",
                                           "network-access"))
                if right_matched:
                    claimed.add(key)
                    pair_note = note
                    if pair_id.startswith("credential-store-read") \
                            and right_matched == ["NETWORK_ACCESS"]:
                        pair_note = _STORE_PAIR_NOTE_FETCH_ONLY
                    combinations.append(Combination(
                        pair_id, left, lcap, left_matched,
                        right, rcap, right_matched, pair_note))
    return SetResult(root, members, combinations, notices)


def _display_names(members: list[Member]) -> dict[int, str]:
    """Sanitised member names for text output, disambiguated
    when two different folders sanitise to the same string.
    A suffix is never allowed to collide with another
    member's own sanitised name (a folder literally named
    `a?b [2]` keeps its name; the suffixed member moves on
    to [3])."""
    bases = [_safe(m.name) for m in members]
    base_set = set(bases)
    used: set[str] = set()
    counts: dict[str, int] = {}
    display: dict[int, str] = {}
    for m, base in zip(members, bases):
        if base not in used:
            used.add(base)
            counts[base] = 1
            display[id(m)] = base
            continue
        n = counts.get(base, 1) + 1
        candidate = f"{base} [{n}]"
        while candidate in used or candidate in base_set:
            n += 1
            candidate = f"{base} [{n}]"
        counts[base] = n
        used.add(candidate)
        display[id(m)] = candidate
    return display


def _evidence_text(rules: list[str]) -> str:
    return ", ".join(_EVIDENCE_LABELS.get(r, r) for r in rules)


def render_set(result: SetResult) -> str:
    display = _display_names(result.members)
    lines = [
        f"Combination scan of {_safe(result.root.name)} — "
        f"{len(result.members)} skill folder(s), each judged on "
        "its own first:",
        "",
    ]
    for m in result.members:
        caps = m.capabilities()
        cap_text = ""
        if caps:
            labels = [CAPABILITY_LABELS[c] for c in caps]
            cap_text = f" — can {'; '.join(labels)}"
        lines.append(
            f"  {display[id(m)]} — {m.result.verdict} "
            f"({m.finding_count} finding(s)){cap_text}")
    if result.notices:
        lines.append("")
        lines.append("Coverage notes (what this scan did not "
                     "judge as a member):")
        for notice in result.notices[:_RENDER_CAP]:
            lines.append(f"  - {_safe(notice)}")
        if len(result.notices) > _RENDER_CAP:
            lines.append(
                f"  … and {len(result.notices) - _RENDER_CAP} "
                "more coverage notes (see --format json for "
                "the full list)")
    lines.append("")
    if result.combinations:
        lines.append(
            "Combinations across skills (caution class — "
            "capabilities that only become dangerous together; "
            "no solo verdict above is changed by this section):")
        shown = result.combinations[:_RENDER_CAP]
        for c in shown:
            lines.append(
                f"  * {display[id(c.left)]} can "
                f"{CAPABILITY_LABELS[c.left_cap]} "
                f"({_evidence_text(c.left_rules)}) and "
                f"{display[id(c.right)]} can "
                f"{CAPABILITY_LABELS[c.right_cap]} "
                f"({_evidence_text(c.right_rules)}). {c.note}")
        if len(result.combinations) > _RENDER_CAP:
            lines.append(
                f"  … and {len(result.combinations) - _RENDER_CAP} "
                "more (see --format json for the full list)")
    else:
        lines.append(
            "No cross-skill combinations found among the "
            f"{len(result.members)} member(s) scanned: no "
            "dangerous capability pair is split across two "
            "of them.")
    lines.append("")
    lines.append(f"Set verdict: {result.verdict}")
    return "\n".join(lines)
