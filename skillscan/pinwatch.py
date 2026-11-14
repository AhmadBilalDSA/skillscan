"""Change watch: pin a skill folder's fingerprint and check it later.

``build_pin`` records a scan result together with a sha256 fingerprint of
EVERY entry in the folder — regular files of every type (not only the ones
the scanner parses, because a rug pull can arrive as a file the scanner
does not read), directories, symlinks (by target text AND by the content
behind the link when it resolves to a regular file — the content is what
an agent would actually read), and special files (fifos, sockets,
devices) by kind. File entries also record the permission bits, so a
quiet ``chmod +x`` (or a setuid bit) shows up. ``diff_pin`` later
compares a fresh scan and
fingerprint against the pin and classifies the outcome:

- ``unchanged``     — every entry identical, verdict and findings
                      identical (exit 0; a scanner version/rules change
                      alone is noted but does not change the class);
- ``files-changed`` — entries on disk changed (or the pin names a
                      different folder), but the scan result — verdict
                      and findings — is identical (exit 1);
- ``changed``       — the scan result changed: verdict differs, or the
                      set of findings differs (exit 2).

Findings are identified by (rule, file, hash of the finding's evidence
text) counted as a multiset — NOT by line number. A comment inserted
above a flagged line moves the line but not the finding; changing what
a flagged line points at (a different host, a different path) changes
the evidence and IS a scan-result change.

A pin is a plain JSON file (format ``skillscan-pin/1``) meant to live
NEXT TO the skill it describes (or in a pins directory) and to be
re-checked before the skill is trusted again. It is tamper-evident
only if it is stored somewhere the skill's folder cannot rewrite:
a pin kept inside the folder it fingerprints can be re-made by the
same hand that changed the folder, and ``--pin`` warns when asked to
write one there.

Loading a pin validates the whole schema and raises :class:`PinError`
on anything unexpected, so a bad pin is reported plainly (exit 3),
never as a traceback. Fingerprinting a folder that cannot be walked
or read likewise raises :class:`PinError`: a guard that read nothing
must never report "no changes".
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections import Counter
from pathlib import Path

from . import __version__
from .rules import RULES
from .scanner import ScanResult

PIN_FORMAT = "skillscan-pin/1"

# Symlink targets larger than this are recorded by link text (and
# resolved path) only; the content hash exists to catch swaps of
# skill-sized payload files, not to fingerprint a mounted filesystem.
_TARGET_HASH_CAP = 512 * 1024 * 1024

# Rendered diff lists are capped so a huge (or hostile) pin cannot
# flood the terminal; the full counts are always shown.
_RENDER_CAP = 50


class PinError(Exception):
    """A pin could not be written, read, or trusted."""


def _hash_stream(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _evidence_key(evidence: str) -> str:
    return _hash_text(evidence)[:12]


def _resolve_quiet(path: Path) -> Path | None:
    try:
        return path.resolve()
    except (OSError, RuntimeError, ValueError):
        return None


# Public alias: __main__ uses it for the in-folder pin warning.
resolve_quiet = _resolve_quiet


def _target_content_hash(target: Path | None) -> str | None:
    """Hash the regular file a symlink ultimately points at, if any."""
    if target is None:
        return None
    try:
        if not target.is_file():
            return None
        if target.stat().st_size > _TARGET_HASH_CAP:
            return None
        return _hash_stream(target)
    except OSError:
        return None


def _link_entry(link_path: Path) -> dict:
    """Fingerprint a symlink: target text, resolved path, content."""
    try:
        target_text = os.readlink(link_path)
    except OSError as exc:
        raise PinError(f"could not read the folder: {link_path}: "
                       f"{exc.strerror or exc}") from exc
    target = _resolve_quiet(link_path)
    return {
        "link": True,
        "sha256": _hash_text(target_text),
        "target_resolved": str(target) if target is not None else None,
        "target_sha256": _target_content_hash(target),
    }


def _special_kind(mode: int) -> str:
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        return "device"
    return "other"


def fingerprint_folder(root: Path, exclude: set[Path]) -> dict[str, dict]:
    """Fingerprint every entry under ``root`` (see module docstring).

    ``exclude`` holds resolved paths to leave out (the pin file itself,
    when it lives inside the folder). Walk and read failures raise
    :class:`PinError` — the fingerprint never silently under-records.
    """
    excluded = set()
    for path in exclude:
        resolved = _resolve_quiet(path)
        if resolved is not None:
            excluded.add(resolved)

    entries: dict[str, dict] = {}

    def _walk_error(err: OSError) -> None:
        raise PinError(f"could not read the folder: {err.filename}: "
                       f"{err.strerror or err}")

    for dirpath, dirnames, filenames in os.walk(
            root, onerror=_walk_error, followlinks=False):
        base = Path(dirpath)
        kept_dirs = []
        for name in sorted(dirnames):
            full = base / name
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                entry = _link_entry(full)
                entry["kind"] = "dir"
                entries[rel] = entry
                continue  # never descend through a linked directory
            entries[rel] = {"kind": "dir"}
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for name in sorted(filenames):
            full = base / name
            resolved = _resolve_quiet(full)
            if resolved is not None and resolved in excluded:
                continue
            rel = full.relative_to(root).as_posix()
            try:
                info = os.lstat(full)
            except OSError as exc:
                raise PinError(f"could not read the folder: {full}: "
                               f"{exc.strerror or exc}") from exc
            if stat.S_ISLNK(info.st_mode):
                entries[rel] = _link_entry(full)
            elif stat.S_ISREG(info.st_mode):
                try:
                    digest = _hash_stream(full)
                except OSError as exc:
                    raise PinError(f"could not read the folder: {full}: "
                                   f"{exc.strerror or exc}") from exc
                entries[rel] = {
                    "sha256": digest,
                    "size": info.st_size,
                    "mode": info.st_mode & 0o7777,
                }
            else:
                entries[rel] = {"kind": _special_kind(info.st_mode)}
    return entries


def _folder_has_entries(root: Path) -> bool:
    try:
        with os.scandir(root) as it:
            return next(it, None) is not None
    except OSError as exc:
        raise PinError(f"could not read the folder: {root}: "
                       f"{exc.strerror or exc}") from exc


def build_pin(root: Path, result: ScanResult, pin_path: Path,
              created: str) -> dict:
    files = fingerprint_folder(root, exclude={pin_path})
    if not files and _folder_has_entries(root):
        raise PinError(f"could not fingerprint any file in {root}; "
                       "refusing to write an empty pin")
    findings = []
    for finding in result.findings:
        for _ in range(max(1, finding.count)):
            findings.append({
                "rule": finding.rule,
                "file": finding.file,
                "line": finding.line,
                "ev": _evidence_key(finding.evidence),
            })
    findings.sort(key=lambda f: (f["file"], f["rule"], f["line"], f["ev"]))
    return {
        "format": PIN_FORMAT,
        "created": created,
        "tool": {"version": __version__, "rules": len(RULES)},
        "target": root.name,
        "verdict": result.verdict,
        "files": files,
        "findings": findings,
    }


def write_pin(pin: dict, pin_path: Path) -> None:
    try:
        pin_path.write_text(
            json.dumps(pin, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    except OSError as exc:
        raise PinError(f"could not write the pin file {pin_path}: "
                       f"{exc.strerror or exc}") from exc


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_file_entry(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if "sha256" in value and not isinstance(value["sha256"], str):
        return False
    if "sha256" not in value and "kind" not in value:
        return False
    if "size" in value and not _is_int(value["size"]):
        return False
    if "mode" in value and not _is_int(value["mode"]):
        return False
    if "link" in value and not isinstance(value["link"], bool):
        return False
    if "kind" in value and not isinstance(value["kind"], str):
        return False
    if "target_sha256" in value and not (
            value["target_sha256"] is None
            or isinstance(value["target_sha256"], str)):
        return False
    if "target_resolved" in value and not (
            value["target_resolved"] is None
            or isinstance(value["target_resolved"], str)):
        return False
    return True


def _valid_finding_entry(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if not isinstance(value.get("rule"), str):
        return False
    if not isinstance(value.get("file"), str):
        return False
    line = value.get("line")
    if not isinstance(line, int) or isinstance(line, bool):
        return False
    if "ev" in value and not isinstance(value["ev"], str):
        return False
    return True


def check_pin_path(pin_path: Path) -> None:
    """Refuse pin paths that are not usable files (a fifo pin path
    would hang the read/write forever). A symlink is followed: its
    target must be a regular file too. A missing path is fine here:
    the read/write itself reports it plainly."""
    try:
        info = os.lstat(pin_path)
    except OSError:
        return
    if stat.S_ISLNK(info.st_mode):
        try:
            info = os.stat(pin_path)
        except OSError:
            return  # dangling link: the read/write reports it
    if not stat.S_ISREG(info.st_mode):
        raise PinError(f"the pin path {pin_path} is not a regular "
                       "file; refusing to use it as a pin")


def load_pin(pin_path: Path) -> dict:
    """Load and fully validate a pin; PinError on anything unexpected."""
    try:
        text = pin_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PinError(f"could not read the pin file {pin_path}: "
                       f"{exc.strerror or exc}") from exc
    except UnicodeDecodeError as exc:
        raise PinError(f"the pin file {pin_path} is not valid UTF-8 text; "
                       "it is not a pin this tool can check") from exc
    try:
        pin = json.loads(text)
    except RecursionError:
        raise PinError(f"the pin file {pin_path} is nested too deeply "
                       "to read; it is not a pin this tool can "
                       "check") from None
    except ValueError:
        raise PinError(f"the pin file {pin_path} is not valid JSON; "
                       "it is not a pin this tool can check") from None
    if not isinstance(pin, dict) or pin.get("format") != PIN_FORMAT:
        raise PinError(f"the pin file {pin_path} is not a {PIN_FORMAT} pin; "
                       "it may be corrupt or from another tool")
    files = pin.get("files")
    if not isinstance(files, dict) or not all(
            isinstance(k, str) and _valid_file_entry(v)
            for k, v in files.items()):
        raise PinError(f"the pin file {pin_path} has a damaged 'files' "
                       "section; it cannot be checked")
    findings = pin.get("findings")
    if not isinstance(findings, list) or not all(
            _valid_finding_entry(f) for f in findings):
        raise PinError(f"the pin file {pin_path} has a damaged 'findings' "
                       "section; it cannot be checked")
    if not isinstance(pin.get("verdict"), str):
        raise PinError(f"the pin file {pin_path} is missing its verdict; "
                       "it is an incomplete pin and cannot be checked")
    if "tool" in pin and not isinstance(pin["tool"], dict):
        raise PinError(f"the pin file {pin_path} has a damaged 'tool' "
                       "section; it cannot be checked")
    for key in ("created", "target"):
        if key in pin and not isinstance(pin[key], str):
            raise PinError(f"the pin file {pin_path} has a damaged "
                           f"'{key}' section; it cannot be checked")
    return pin


def _finding_key(entry: dict) -> tuple[str, str, str]:
    return (entry["rule"], entry["file"], entry.get("ev", ""))


def diff_pin(pin: dict, result: ScanResult, files_now: dict[str, dict],
             folder_name: str) -> dict:
    files_then: dict[str, dict] = pin["files"]
    added_files = sorted(set(files_now) - set(files_then))
    removed_files = sorted(set(files_then) - set(files_now))
    changed_files = sorted(
        name for name in set(files_then) & set(files_now)
        if files_then[name] != files_now[name])

    then_counter: Counter = Counter()
    then_line: dict[tuple[str, str, str], int] = {}
    for entry in pin["findings"]:
        key = _finding_key(entry)
        then_counter[key] += 1
        then_line.setdefault(key, entry["line"])
    now_counter: Counter = Counter()
    now_line: dict[tuple[str, str, str], int] = {}
    for finding in result.findings:
        key = (finding.rule, finding.file,
               _evidence_key(finding.evidence))
        now_counter[key] += max(1, finding.count)
        now_line.setdefault(key, finding.line)

    def _expand(counter_diff: Counter,
                lines: dict[tuple[str, str, str], int]) -> list[dict]:
        out = []
        for (rule, file, _ev), count in sorted(counter_diff.items()):
            for _ in range(count):
                out.append({"rule": rule, "file": file,
                            "line": lines.get((rule, file, _ev), 0)})
        return out

    findings_added = _expand(now_counter - then_counter, now_line)
    findings_removed = _expand(then_counter - now_counter, then_line)
    verdict_changed = pin["verdict"] != result.verdict
    scan_changed = bool(verdict_changed or findings_added
                        or findings_removed)
    target_mismatch = bool(pin.get("target")) and pin["target"] != folder_name

    tool_then = pin.get("tool") or {}
    scanner_changed = (
        tool_then.get("version") not in (None, __version__)
        or tool_then.get("rules") not in (None, len(RULES)))

    files_changed = bool(added_files or removed_files or changed_files
                         or target_mismatch)
    if scan_changed:
        classification = "changed"
    elif files_changed:
        classification = "files-changed"
    else:
        classification = "unchanged"

    return {
        "format": pin["format"],
        "target": pin.get("target", ""),
        "folder_name": folder_name,
        "target_mismatch": target_mismatch,
        "classification": classification,
        "verdict_before": pin["verdict"],
        "verdict_now": result.verdict,
        "scanner_changed": scanner_changed,
        "tool_before": tool_then,
        "tool_now": {"version": __version__, "rules": len(RULES)},
        "added_files": added_files,
        "removed_files": removed_files,
        "changed_files": changed_files,
        "findings_added": findings_added,
        "findings_removed": findings_removed,
    }


_CLASSIFICATION_EXIT = {"unchanged": 0, "files-changed": 1, "changed": 2}


def classification_exit(diff: dict) -> int:
    return _CLASSIFICATION_EXIT[diff["classification"]]


def _append_capped(lines: list[str], items: list, render) -> None:
    for item in items[:_RENDER_CAP]:
        lines.append(render(item))
    if len(items) > _RENDER_CAP:
        lines.append(f"  … and {len(items) - _RENDER_CAP} more")


def _display(name: str) -> str:
    """Make a folder-controlled name safe to print: control
    characters (including newline and ESC) become '?', so a hostile
    file name cannot forge output lines or inject terminal escapes."""
    return "".join(
        ch if 32 <= ord(ch) and ord(ch) != 127 else "?"
        for ch in name)


def render_diff(diff: dict, pin_name: str) -> str:
    lines = []
    if diff["classification"] == "unchanged":
        lines.append(
            f"No changes: every entry in the folder is identical to "
            f"the pin ({pin_name}), and the scan result is the same "
            f"(verdict {diff['verdict_now']}).")
    elif diff["classification"] == "files-changed":
        lines.append("Files changed on disk — same scan result "
                     "(verdict and findings identical).")
    else:
        lines.append("CHANGED since the pin — review before trusting "
                     "this skill again.")
        lines.append(f"  verdict then: {diff['verdict_before']}  →  "
                     f"now: {diff['verdict_now']}")
    if diff.get("target_mismatch"):
        lines.append(f"  note: this pin is for a folder named "
                     f"'{_display(diff['target'])}'; the folder you "
                     f"checked is named "
                     f"'{_display(diff['folder_name'])}'.")
    if diff["scanner_changed"]:
        before = diff["tool_before"]
        now = diff["tool_now"]
        lines.append(
            f"  note: the scanner itself changed since the pin "
            f"(tool {before.get('version', '?')}, {before.get('rules', '?')} "
            f"rules → {now['version']}, {now['rules']} rules); a changed "
            "result may be the scanner's doing, not the skill's.")
    if diff["classification"] != "unchanged":
        groups = (
            ("Added files", diff["added_files"],
             lambda n: f"  + {_display(n)}"),
            ("Removed files", diff["removed_files"],
             lambda n: f"  - {_display(n)}"),
            ("Changed files", diff["changed_files"],
             lambda n: f"  ~ {_display(n)}"),
            ("New findings", diff["findings_added"],
             lambda f: f"  + {f['rule']} in {_display(f['file'])} "
                       f"(line {f['line']})"),
            ("Gone findings", diff["findings_removed"],
             lambda f: f"  - {f['rule']} in {_display(f['file'])} "
                       f"(line {f['line']})"),
        )
        for label, items, render in groups:
            if items:
                lines.append(f"{label} ({len(items)}):")
                _append_capped(lines, items, render)
    return "\n".join(lines)
