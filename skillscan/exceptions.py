"""Exceptions with reasons: let a project accept a finding,
on the record.

A scanner that cannot be argued with gets routed around:
people stop running it, or fork the result by hand. The
middle path is an exceptions file — per project, in JSON —
where each accepted finding is named by rule and path,
carries a human reason, and expires on a date. Nothing is
silently dropped:

- an excepted finding leaves the verdict computation but
  stays fully visible in an "Excepted findings" section of
  every report (in JSON it keeps its full finding shape,
  flagged, with the reason and expiry attached; in SARIF it
  is a result with an external suppression whose
  justification is the reason);
- the verdict and exit code are recomputed from the
  findings that remain;
- an expired exception stops applying — the finding counts
  again — and the expired exception is itself reported;
- an exception that matches nothing is reported as
  possibly stale, so the file cannot quietly rot;
- a malformed exceptions file fails the run visibly
  (exit 3, a plain error, never a traceback and never a
  scan that silently ignored the file).

Format (`skillscan-exceptions/1`):

    {
      "format": "skillscan-exceptions/1",
      "exceptions": [
        {"rule": "ENV_FILE_READ", "path": "tools/dev_*.py",
         "reason": "Dev-only helper; reads the project's own
                    example .env, never a user's.",
         "expires": "2027-03-01"}
      ]
    }

A bare JSON list of the same entry objects is also
accepted. Every entry needs all four fields: `rule` (a
rule id this scanner knows — a typo fails the run rather
than silently never matching), `path` (a glob matched
against the finding's file path inside the skill, `/`
separators; `*` matches any file), `reason` (non-empty —
an exception without a reason is exactly what this
feature exists to prevent), and `expires` (an ISO date;
the exception applies through that date and stops the
day after). Duplicate (rule, path) entries and unknown
keys are rejected for the same reason typos are: the
file is a record people rely on, so it is validated like
one.

Exceptions apply to the deterministic scan result, before
the optional `--llm` review (the review then sees what
remains). They cannot be combined with `--pin` /
`--check-pin` (a pin fingerprints the raw scan) or
`--combine` (set members are reported raw). Keep the
exceptions file OUTSIDE the scanned folder: inside, it
would be scanned as an ordinary file like any other.
"""

from __future__ import annotations

import fnmatch
import json
import re
import stat
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .rules import RULES_BY_ID

EXCEPTIONS_FORMAT = "skillscan-exceptions/1"
_MAX_EXCEPTIONS_BYTES = 4_000_000
_ENTRY_KEYS = {"rule", "path", "reason", "expires"}
_TOP_KEYS = {"format", "exceptions"}
_DATE_SHAPE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class ExceptionsError(Exception):
    """The exceptions file cannot be used."""


@dataclass
class ExceptionEntry:
    rule: str
    path: str
    reason: str
    expires: date

    def matches(self, rule: str, file: str) -> bool:
        if rule != self.rule:
            return False
        posix = file.replace("\\", "/")
        return (fnmatch.fnmatchcase(posix, self.path)
                or fnmatch.fnmatchcase(file, self.path))


@dataclass
class ExceptedFinding:
    """A finding set aside by an exception: the full finding
    plus the record of why."""
    finding: object  # scanner.Finding (duck-typed)
    reason: str
    expires: str  # ISO date, as written in the file


def load_exceptions(path: Path) -> list[ExceptionEntry]:
    try:
        mode = path.stat().st_mode
    except OSError:
        mode = None  # read_bytes below produces the read error
    if mode is not None and not stat.S_ISREG(mode):
        # Never block on a FIFO or read a device as if it were
        # a file: the exceptions file must be a regular file
        # (a symlink TO one is fine — stat follows it).
        raise ExceptionsError(
            f"the exceptions file {path} is not a regular file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ExceptionsError(
            f"could not read the exceptions file {path}: "
            f"{exc.strerror or exc}") from exc
    if len(raw) > _MAX_EXCEPTIONS_BYTES:
        raise ExceptionsError(
            f"the exceptions file {path} is too large "
            f"({len(raw)} bytes; the limit is "
            f"{_MAX_EXCEPTIONS_BYTES})")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ExceptionsError(
            f"the exceptions file {path} is not valid UTF-8: "
            f"{exc}") from exc
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ExceptionsError(
            f"the exceptions file {path} is not valid JSON: "
            f"{exc}") from exc
    if isinstance(data, dict):
        unknown_top = sorted(set(data) - _TOP_KEYS)
        if unknown_top:
            raise ExceptionsError(
                f"the exceptions file {path} has unknown "
                f"top-level key(s): {', '.join(unknown_top)} "
                f"(allowed: {', '.join(sorted(_TOP_KEYS))})")
        fmt = data.get("format")
        if fmt is not None and fmt != EXCEPTIONS_FORMAT:
            raise ExceptionsError(
                f"the exceptions file {path} declares format "
                f"{fmt!r}; this scanner reads "
                f"{EXCEPTIONS_FORMAT!r}")
        entries = data.get("exceptions")
        if entries is None:
            raise ExceptionsError(
                f"the exceptions file {path} has no "
                "\"exceptions\" list")
    elif isinstance(data, list):
        entries = data
    else:
        raise ExceptionsError(
            f"the exceptions file {path} must hold a JSON "
            "object with an \"exceptions\" list (or a bare "
            "list of exception entries)")
    if not isinstance(entries, list):
        raise ExceptionsError(
            f"the \"exceptions\" value in {path} is not a list")
    parsed: list[ExceptionEntry] = []
    seen: set[tuple[str, str]] = set()
    for i, item in enumerate(entries):
        where = f"exception #{i + 1} in {path}"
        if not isinstance(item, dict):
            raise ExceptionsError(f"{where} is not a JSON object")
        unknown = sorted(set(item) - _ENTRY_KEYS)
        if unknown:
            raise ExceptionsError(
                f"{where} has unknown key(s): "
                f"{', '.join(unknown)} (allowed: "
                f"{', '.join(sorted(_ENTRY_KEYS))})")
        missing = sorted(_ENTRY_KEYS - set(item))
        if missing:
            raise ExceptionsError(
                f"{where} is missing field(s): "
                f"{', '.join(missing)} — every exception needs "
                "a rule, a path, a reason, and an expiry date")
        rule, pat, reason, expires = (
            item["rule"], item["path"], item["reason"],
            item["expires"])
        for name, value in (("rule", rule), ("path", pat),
                            ("reason", reason),
                            ("expires", expires)):
            if not isinstance(value, str) or not value.strip():
                raise ExceptionsError(
                    f"{where}: field \"{name}\" must be a "
                    "non-empty string")
        if rule not in RULES_BY_ID:
            raise ExceptionsError(
                f"{where}: unknown rule id {rule!r} — this "
                "scanner has no such rule, so the exception "
                "could never apply; fix the id or remove the "
                "entry")
        if not _DATE_SHAPE_RE.fullmatch(expires.strip()):
            raise ExceptionsError(
                f"{where}: \"expires\" must be a date in "
                f"YYYY-MM-DD form: {expires!r}")
        try:
            expiry = date.fromisoformat(expires.strip())
        except ValueError:
            raise ExceptionsError(
                f"{where}: \"expires\" is not a real calendar "
                f"date: {expires!r}") from None
        key = (rule, pat)
        if key in seen:
            raise ExceptionsError(
                f"{where}: duplicate exception for rule "
                f"{rule} on path {pat!r} — merge the two "
                "entries into one")
        seen.add(key)
        parsed.append(ExceptionEntry(
            rule=rule, path=pat, reason=reason.strip(),
            expires=expiry))
    return parsed


def apply_exceptions(result, entries: list[ExceptionEntry],
                     today: date) -> None:
    """Apply `entries` to a ScanResult in place: matched
    findings move to result.excepted, the verdict is
    recomputed from what remains, expired / unmatched /
    shadowed exceptions are recorded in
    result.exception_notes, and claim checks whose
    contradicting finding was excepted are marked as such
    (the claim's status itself never changes — the scan DID
    find what it found; the exception is a separate record).
    Every note is computed against the final kept set, so a
    note never claims a finding is counted when another
    exception set it aside."""
    active: list[ExceptionEntry] = []
    expired: list[ExceptionEntry] = []
    for entry in entries:
        (expired if today > entry.expires else active).append(entry)
    kept = []
    excepted: list[ExceptedFinding] = []
    won: set[int] = set()
    matched_any: dict[int, int] = {}
    for finding in result.findings:
        hit = None
        for idx, entry in enumerate(active):
            if entry.matches(finding.rule, finding.file):
                matched_any[idx] = matched_any.get(idx, 0) + 1
                if hit is None:
                    hit = idx
        if hit is None:
            kept.append(finding)
        else:
            won.add(hit)
            entry = active[hit]
            excepted.append(ExceptedFinding(
                finding=finding, reason=entry.reason,
                expires=entry.expires.isoformat()))
    notes: list[str] = []
    for entry in expired:
        covered = sum(
            1 for f in kept if entry.matches(f.rule, f.file))
        note = (
            f"expired exception: {entry.rule} on "
            f"{entry.path} expired on "
            f"{entry.expires.isoformat()} and no longer "
            "applies")
        if covered:
            note += (f" — {covered} finding(s) it would have "
                     "covered are counted in the verdict")
        notes.append(note + f" (reason was: {entry.reason})")
    for idx, entry in enumerate(active):
        if idx not in matched_any:
            notes.append(
                f"unmatched exception: {entry.rule} on "
                f"{entry.path} matched no findings — it may "
                "be stale (the finding is gone, or the rule "
                "or path no longer matches)")
        elif idx not in won:
            notes.append(
                f"shadowed exception: {entry.rule} on "
                f"{entry.path} matched "
                f"{matched_any[idx]} finding(s) that an "
                "earlier exception already set aside — it "
                "has no additional effect")
    result.findings = kept
    result.excepted = excepted
    result.exception_notes = notes
    if excepted and getattr(result, "claims", None):
        aside = {(e.finding.rule, e.finding.file)
                 for e in excepted}
        for chk in result.claims:
            for hit in getattr(chk, "contradicted_by", []):
                if (hit.get("rule"), hit.get("file")) in aside:
                    hit["excepted"] = True
    severities = {f.severity for f in kept}
    if "block" in severities:
        result.verdict = "BLOCK"
    elif "caution" in severities:
        result.verdict = "CAUTION"
    else:
        result.verdict = "PASS"
