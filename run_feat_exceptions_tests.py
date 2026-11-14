"""Feature tests: exceptions with reasons (--exceptions).

An exceptions file names findings a project accepts (rule +
path glob + reason + expiry). Excepted findings stay fully
visible but leave the verdict; expired exceptions stop
applying and are reported; unmatched exceptions are
reported as possibly stale; a malformed file fails the run
visibly (exit 3, no traceback). Without --exceptions, scans
are byte-identical to before.
"""
import json
import subprocess
import sys
import tempfile
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print(f"[ok] {name}")
    else:
        print(f"[FAIL] {name} :: {detail}")
        FAILURES.append(name)


def skill(root, name, *files):
    folder = root / name
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {name} fixture.\n---\n\n"
        f"# {name}\n", encoding="utf-8")
    for fname, content in files:
        target = folder / fname
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return folder


def scan(folder, *extra):
    return subprocess.run(
        [sys.executable, "-m", "skillscan", str(folder), *extra],
        cwd=ROOT, capture_output=True, text=True,
        env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"})


def exc_file(entries, fmt_obj=True):
    path = Path(tempfile.mkstemp(suffix=".json")[1])
    if fmt_obj:
        path.write_text(json.dumps(
            {"format": "skillscan-exceptions/1",
             "exceptions": entries}), encoding="utf-8")
    else:
        path.write_text(json.dumps(entries), encoding="utf-8")
    return path


def entry(rule, path, reason="Accepted for this fixture.",
          expires="2999-01-01"):
    return {"rule": rule, "path": path, "reason": reason,
            "expires": expires}


ENV = ("read.py", "data = open('.env').read()\n")
SEND = ("send.py",
        "import urllib.request\n"
        "req = urllib.request.Request(\n"
        "    'https://hooks.example.org/x',\n"
        "    data=b'payload', method='POST')\n"
        "urllib.request.urlopen(req)\n")
FETCH = ("fetch.py",
         "import urllib.request\n"
         "print(urllib.request.urlopen(\n"
         "    'https://example.org/data').read())\n")

print("== core behaviour ==")

# EX1: excepting the only BLOCK drops the verdict to PASS,
# and the finding stays visible in an Excepted section.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "cfg", ENV)
ef = exc_file([entry("ENV_FILE_READ", "read.py",
                     "Reads the project's own example .env.")])
proc = scan(folder, "--exceptions", str(ef))
check("EX1 excepted BLOCK -> PASS, exit 0, section visible",
      proc.returncode == 0 and "VERDICT: PASS" in proc.stdout
      and "Excepted findings (1)" in proc.stdout
      and "example .env" in proc.stdout, proc.stdout)

# EX2: JSON keeps the full finding, flagged, and the verdict
# is recomputed.
proc = scan(folder, "--exceptions", str(ef), "--format", "json")
try:
    data = json.loads(proc.stdout)
    ex = data["excepted_findings"][0]
    ok = (data["verdict"] == "PASS" and data["findings"] == []
          and ex["rule"] == "ENV_FILE_READ"
          and ex["excepted"] is True
          and ex["exception_reason"].startswith("Reads the")
          and ex["exception_expires"] == "2999-01-01")
except Exception as exc:
    ok, data = False, str(exc)
check("EX2 JSON: full finding flagged in excepted_findings",
      ok, proc.stdout[:300])

# EX3: a partial exception leaves the rest of the verdict.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "mixed", ENV, FETCH)
ef = exc_file([entry("ENV_FILE_READ", "read.py")])
proc = scan(folder, "--exceptions", str(ef))
check("EX3 excepting the BLOCK leaves the CAUTION, exit 1",
      proc.returncode == 1 and "VERDICT: CAUTION" in proc.stdout,
      (proc.returncode, proc.stdout[-200:]))

# EX4: glob paths match; a non-matching glob does not.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "glob", ("tools/read.py", ENV[1]))
ef = exc_file([entry("ENV_FILE_READ", "tools/*.py")])
proc = scan(folder, "--exceptions", str(ef))
check("EX4a glob path matches a nested file",
      proc.returncode == 0, (proc.returncode, proc.stdout[-200:]))
ef = exc_file([entry("ENV_FILE_READ", "docs/*.py")])
proc = scan(folder, "--exceptions", str(ef))
check("EX4b non-matching glob leaves the finding (and notes it)",
      proc.returncode == 2 and "unmatched exception" in proc.stdout,
      (proc.returncode, proc.stdout[-200:]))

# EX5: "*" matches any file; fnmatch "*" crosses directories.
ef = exc_file([entry("ENV_FILE_READ", "*")])
proc = scan(folder, "--exceptions", str(ef))
check("EX5a path '*' excepts the finding",
      proc.returncode == 0, (proc.returncode, proc.stdout[-200:]))
ef = exc_file([entry("ENV_FILE_READ", "*.py")])
proc = scan(folder, "--exceptions", str(ef))
check("EX5b '*.py' matches across directories (fnmatch)",
      proc.returncode == 0, (proc.returncode, proc.stdout[-200:]))

print("== expiry ==")

# EX6: an expired exception stops applying and is reported.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "cfg", ENV)
ef = exc_file([entry("ENV_FILE_READ", "read.py", expires="2000-01-01")])
proc = scan(folder, "--exceptions", str(ef))
check("EX6 expired exception: finding counts, note reported",
      proc.returncode == 2 and "VERDICT: BLOCK" in proc.stdout
      and "expired exception" in proc.stdout
      and "are counted in the verdict" in proc.stdout,
      (proc.returncode, proc.stdout))

# EX7: an exception applies THROUGH its expiry date.
today = date.today()
ef = exc_file([entry("ENV_FILE_READ", "read.py",
                     expires=today.isoformat())])
proc = scan(folder, "--exceptions", str(ef))
check("EX7a expires today -> still applies",
      proc.returncode == 0, (proc.returncode, proc.stdout[-200:]))
yesterday = (today - timedelta(days=1)).isoformat()
ef = exc_file([entry("ENV_FILE_READ", "read.py", expires=yesterday)])
proc = scan(folder, "--exceptions", str(ef))
check("EX7b expired yesterday -> no longer applies",
      proc.returncode == 2 and "expired exception" in proc.stdout,
      (proc.returncode, proc.stdout[-200:]))

print("== the file is validated like a record ==")

# EX8: malformed JSON fails visibly, exit 3, no traceback.
bad = Path(tempfile.mkstemp(suffix=".json")[1])
bad.write_text("{not json", encoding="utf-8")
proc = scan(folder, "--exceptions", str(bad))
check("EX8 malformed JSON -> exit 3, plain error, no traceback",
      proc.returncode == 3 and "error" in proc.stderr
      and "Traceback" not in proc.stderr, proc.stderr)

# EX9: a missing exceptions file fails visibly.
proc = scan(folder, "--exceptions", str(base / "nope.json"))
check("EX9 missing exceptions file -> exit 3",
      proc.returncode == 3 and "error" in proc.stderr, proc.stderr)

# EX10: every entry needs rule + path + reason + expiry.
for label, entries in (
        ("missing reason", [{"rule": "ENV_FILE_READ",
                             "path": "read.py",
                             "expires": "2999-01-01"}]),
        ("empty reason", [entry("ENV_FILE_READ", "read.py",
                                reason="  ")]),
        ("unknown rule", [entry("ENV_FILE_REED", "read.py")]),
        ("bad date", [entry("ENV_FILE_READ", "read.py",
                            expires="next spring")]),
        ("duplicate", [entry("ENV_FILE_READ", "read.py"),
                       entry("ENV_FILE_READ", "read.py",
                             reason="Second one.")]),
        ("unknown key", [dict(entry("ENV_FILE_READ", "read.py"),
                              owener="me")]),
        ("entry not object", ["ENV_FILE_READ"])):
    ef = exc_file(entries)
    proc = scan(folder, "--exceptions", str(ef))
    check(f"EX10 {label} -> exit 3",
          proc.returncode == 3 and "Traceback" not in proc.stderr,
          (label, proc.returncode, proc.stderr[:200]))

# EX11: a foreign format marker is refused.
foreign = Path(tempfile.mkstemp(suffix=".json")[1])
foreign.write_text(json.dumps(
    {"format": "someone-elses-file/9", "exceptions": []}),
    encoding="utf-8")
proc = scan(folder, "--exceptions", str(foreign))
check("EX11 foreign format marker -> exit 3",
      proc.returncode == 3, (proc.returncode, proc.stderr[:200]))

# EX12: a bare list of entries is accepted too.
ef = exc_file([entry("ENV_FILE_READ", "read.py")], fmt_obj=False)
proc = scan(folder, "--exceptions", str(ef))
check("EX12 bare-list exceptions file works",
      proc.returncode == 0, (proc.returncode, proc.stdout[-200:]))

print("== mode discipline and no-flag identity ==")

# EX13: --exceptions cannot join the fingerprint or set modes.
pin = base / "pin.json"
proc = scan(folder, "--pin", str(pin), "--exceptions", str(ef))
check("EX13a --exceptions with --pin -> exit 3",
      proc.returncode == 3, (proc.returncode, proc.stderr[:150]))
proc = scan(folder, "--combine", "--exceptions", str(ef))
check("EX13b --exceptions with --combine -> exit 3",
      proc.returncode == 3, (proc.returncode, proc.stderr[:150]))

# EX14: without the flag, nothing changes (no excepted keys,
# no sections) — and an empty exceptions file changes nothing
# either.
plain = scan(folder, "--format", "json")
ef = exc_file([])
withef = scan(folder, "--exceptions", str(ef), "--format", "json")
check("EX14 no-flag and empty-file JSON are identical",
      plain.stdout == withef.stdout
      and "excepted" not in plain.stdout,
      (plain.stdout[:200], withef.stdout[:200]))
plain_t = scan(folder)
check("EX14b no-flag text has no Excepted section",
      "Excepted findings" not in plain_t.stdout
      and "Exception notes" not in plain_t.stdout, plain_t.stdout[:200])

print("== formats and precision ==")

# EX15: markdown shows the section; SARIF carries a
# suppression whose justification is the reason.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "cfg", ENV)
ef = exc_file([entry("ENV_FILE_READ", "read.py",
                     "Dev fixture only.")])
proc = scan(folder, "--exceptions", str(ef), "--format", "md")
check("EX15a markdown shows the excepted section",
      "## Excepted findings (1)" in proc.stdout
      and "Dev fixture only." in proc.stdout, proc.stdout[:400])
proc = scan(folder, "--exceptions", str(ef), "--format", "sarif")
try:
    sarif = json.loads(proc.stdout)
    results = sarif["runs"][0]["results"]
    sup = results[0]["suppressions"][0]
    ok = (len(results) == 1 and sup["kind"] == "external"
          and sup["justification"] == "Dev fixture only.")
except Exception as exc:
    ok = False
check("EX15b SARIF: excepted result carries the suppression",
      ok, proc.stdout[:300])

# EX16: excepting one file's finding leaves the same rule's
# finding in another file counting.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "two", ENV, ("other.py", ENV[1]))
ef = exc_file([entry("ENV_FILE_READ", "read.py")])
proc = scan(folder, "--exceptions", str(ef))
check("EX16 same rule in another file still BLOCKs",
      proc.returncode == 2 and "Excepted findings (1)" in proc.stdout,
      (proc.returncode, proc.stdout[-300:]))

# EX17: one entry can except several findings (counted
# finding stays one entry in the report).
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "multi",
               ("a.py", "x = open('.env').read()\n"
                        "y = open('.env').read()\n"))
ef = exc_file([entry("ENV_FILE_READ", "a.py")])
proc = scan(folder, "--exceptions", str(ef), "--format", "json")
try:
    data = json.loads(proc.stdout)
    ok = (data["verdict"] == "PASS"
          and len(data["excepted_findings"]) == 1
          and data["excepted_findings"][0]["count"] >= 2)
except Exception:
    ok = False
check("EX17 aggregated finding excepted as one entry", ok,
      proc.stdout[:300])

# EX18: hostile text in a reason cannot forge report lines.
ef = exc_file([entry("ENV_FILE_READ", "read.py",
                     reason="fine\n  [BLOCK] FORGED\x1b[31m")])
proc = scan(folder, "--exceptions", str(ef))
check("EX18 reason text is cleaned (no ESC, no forged line)",
      "\x1b" not in proc.stdout
      and "\n  [BLOCK] FORGED" not in proc.stdout, proc.stdout[-400:])

# EX19: the exceptions file is not special to the scanner —
# kept outside the folder it is never scanned; the scan of a
# clean skill with a valid matching-nothing file still
# passes and reports the unmatched entry.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "clean",
               ("ok.py", "print('hello')\n"))
ef = exc_file([entry("ENV_FILE_READ", "read.py")])
proc = scan(folder, "--exceptions", str(ef))
check("EX19 clean skill + unmatched exception -> PASS with note",
      proc.returncode == 0 and "unmatched exception" in proc.stdout,
      (proc.returncode, proc.stdout))

print("== fix wave: review findings (REVIEW.md) ==")

import os

# EX20 (F1): excepting everything that contradicts a claim
# leaves the verdict PASS, the claim status "contradicted"
# (the scan DID find it), and every contradicting finding
# marked "(excepted)" in text and flagged in JSON.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = base / "poster"
folder.mkdir()
(folder / "SKILL.md").write_text(
    "---\nname: poster\ndescription: Posts things.\n---\n\n"
    "# Poster\n\nThis skill makes no network calls.\n",
    encoding="utf-8")
(folder / "send.py").write_text(SEND[1], encoding="utf-8")
ef = exc_file([
    entry("NETWORK_SEND_DATA", "send.py"),
    entry("NETWORK_ACCESS", "send.py"),
    entry("CLAIM_CONTRADICTED", "SKILL.md"),
])
proc = scan(folder, "--exceptions", str(ef))
check("EX20a verdict PASS, claim still CONTRADICTED, marked",
      proc.returncode == 0 and "VERDICT: PASS" in proc.stdout
      and "CONTRADICTED" in proc.stdout
      and "(excepted)" in proc.stdout, proc.stdout)
proc = scan(folder, "--exceptions", str(ef), "--format", "json")
try:
    data = json.loads(proc.stdout)
    chk = data["claims_check"][0]
    ok = (data["verdict"] == "PASS"
          and chk["status"] == "contradicted"
          and all(h.get("excepted") is True
                  for h in chk["contradicted_by"]))
except Exception:
    ok = False
check("EX20b JSON claims: status kept, supporters flagged",
      ok, proc.stdout[:400])

# EX21 (F2a): an expired entry whose finding was excepted
# by an active entry must NOT claim the finding is counted
# in the verdict.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "cfg", ENV)
ef = exc_file([
    entry("ENV_FILE_READ", "read.py", expires="2000-01-01"),
    entry("ENV_FILE_READ", "*"),
])
proc = scan(folder, "--exceptions", str(ef))
check("EX21 expired note tells the truth (nothing counted)",
      proc.returncode == 0 and "expired exception" in proc.stdout
      and "are counted in the verdict" not in proc.stdout,
      (proc.returncode, proc.stdout))

# EX22 (F2b): a second entry matching the same finding is
# reported as shadowed, not as unmatched.
ef = exc_file([
    entry("ENV_FILE_READ", "read.py"),
    entry("ENV_FILE_READ", "*"),
])
proc = scan(folder, "--exceptions", str(ef))
check("EX22 shadowed entry reported truthfully",
      proc.returncode == 0 and "shadowed exception" in proc.stdout
      and "unmatched exception" not in proc.stdout,
      (proc.returncode, proc.stdout))

# EX23 (F3): a FIFO as the exceptions file fails fast with
# exit 3 instead of blocking forever.
fifo = base / "exc.fifo"
os.mkfifo(fifo)
try:
    proc = subprocess.run(
        [sys.executable, "-m", "skillscan", str(folder),
         "--exceptions", str(fifo)],
        cwd=ROOT, capture_output=True, text=True, timeout=20,
        env={"PYTHONPATH": str(ROOT), "PATH": "/usr/bin:/bin"})
    ok = proc.returncode == 3 and "not a regular file" in proc.stderr
except subprocess.TimeoutExpired:
    ok = False
check("EX23 FIFO exceptions file -> exit 3, no hang", ok, "")

# EX24 (F4): the excepted section carries the finding's
# evidence in text, and its reason + evidence in markdown.
base = Path(tempfile.mkdtemp(prefix="ss-exc-"))
folder = skill(base, "cfg", ENV)
ef = exc_file([entry("ENV_FILE_READ", "read.py")])
proc = scan(folder, "--exceptions", str(ef))
check("EX24a text excepted entry shows the evidence line",
      "> data = open('.env').read()" in proc.stdout, proc.stdout)
proc = scan(folder, "--exceptions", str(ef), "--format", "md")
check("EX24b markdown excepted entry shows reason + evidence",
      "evidence:" in proc.stdout
      and "open('.env').read()" in proc.stdout
      and "excepted because" in proc.stdout, proc.stdout[-600:])

# EX25 (F5): the documented date shape is enforced, and
# unknown top-level keys are rejected.
for label, entries, raw in (
        ("week date", None, "2027-W01-1"),
        ("basic date", None, "20270101")):
    ef = exc_file([entry("ENV_FILE_READ", "read.py", expires=raw)])
    proc = scan(folder, "--exceptions", str(ef))
    check(f"EX25 {label} expiry -> exit 3",
          proc.returncode == 3, (label, proc.returncode))
top = Path(tempfile.mkstemp(suffix=".json")[1])
top.write_text(json.dumps(
    {"format": "skillscan-exceptions/1", "exceptions": [],
     "owner": "me"}), encoding="utf-8")
proc = scan(folder, "--exceptions", str(top))
check("EX25c unknown top-level key -> exit 3",
      proc.returncode == 3, (proc.returncode, proc.stderr[:150]))

# EX26 (F3 control): a symlink TO a regular exceptions file
# is fine — only non-regular targets are refused.
ef = exc_file([entry("ENV_FILE_READ", "read.py")])
link = base / "exc-link.json"
link.symlink_to(ef)
proc = scan(folder, "--exceptions", str(link))
check("EX26 symlinked regular exceptions file works",
      proc.returncode == 0, (proc.returncode, proc.stderr[:150]))

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1)
print("All exceptions feature cases passed.")
