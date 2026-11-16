# Benchmarks — methodology and full results

SkillScan's measured detection and false-positive rates on a public
labelled corpus. These are SkillScan's own numbers, published as
measured — including the families where the rates are poor. Last run:
**2026-11-15**, scanner: the current tree (64 deterministic
rules — v0.8.0's 63 plus the `INJECTION_EXECUTION` promotion).
First run 2026-11-11 on v0.6.0; the v0.8.0 re-run gave every
skill the same verdict as the v0.6 run (see "What changed from
v0.6" below); the 2026-11-15 re-run moved 297 malicious skills
from CAUTION to BLOCK and changed nothing else, and a
same-day fix wave then tightened three over-broad rules,
setting the final figures below (see "What changed from
v0.8.0" below).

## Corpus

**MaliciousSkillBench** — an academic benchmark consolidating 13
public sources into 9,740 labelled skills: **7,505 malicious /
2,235 benign**, with harmonised attack-category labels assigned to a
subset of the malicious side.

- GitHub: https://github.com/protectskills/MaliciousSkillBench
  pinned at commit `893afd609be22a2dfac5a2b94bbebb4eeb99515e`
  (2026-08-22).
- Hugging Face: https://huggingface.co/datasets/ProtectSkills/MaliciousSkillBench
  pinned at revision `d4b42ce5766a6e0359c987cf59c1007cb3795a90`
  (`primary.parquet`, used for benign texts and label metadata).
- Licence/terms as stated in the corpus repository: code Apache-2.0;
  benchmark-authored metadata/annotations CC BY 4.0; third-party skill
  artifacts retain their upstream terms, and a responsible-use
  document governs the malicious artifacts. The corpus is used for
  measurement only.

## How the run was done

- *Malicious side:* the corpus's per-source package archives were
  extracted (path-safe extraction, no execution) into real folder
  trees, and each skill folder was scanned individually. 7,421 of
  7,505 malicious skills have an extracted package tree and were run;
  the remaining 84 are text-only/sanitised records with no package
  tree and were not run.
- *Benign side:* the benchmark does not ship benign package trees; it
  ships frozen skill text. Each benign identity's frozen text was
  materialised as a single `SKILL.md` in its own folder, and all
  2,235 were scanned that way.
- SkillScan interacted with every sample by reading it as text only.
  Nothing was executed, installed, imported, or uploaded. The scanner
  produced zero errors across all 9,656 scans.
- Median scan time in the 2026-11-15 run was ~106 ms per
  malicious skill (p95 ~600 ms) and ~44 ms per benign skill
  (the v0.8.0 run measured ~110 ms / ~43 ms on the same
  harness — timings are machine-dependent; the verdicts are
  the result).

## Counting rules

- Corpus label *malicious*: a **BLOCK** verdict counts as strict
  detection; **BLOCK or CAUTION** counts as loose detection.
- Corpus label *benign*: a **BLOCK** verdict counts as a false
  positive; a **CAUTION** verdict counts as a soft flag and is
  reported separately, not as a false positive.
- Attack-family breakdowns use the corpus's harmonised category
  field. Families are multi-label: a skill counts in every family it
  carries ("membership basis"). Where a family's membership number
  flatters the result, the pure single-category figure is stated
  alongside.

## Results

### Headline

| Set | n | BLOCK | CAUTION | PASS | Detection (BLOCK) | Detection (BLOCK+CAUTION) |
|---|---|---|---|---|---|---|
| Malicious | 7,421 | 3,689 | 2,427 | 1,305 | **49.7%** | **82.4%** |
| Benign | 2,235 | 0 | 557 | 1,678 | false BLOCK **0%** | flagged 24.9% |

What changed from v0.6, stated exactly: **nothing — at the
verdict level.** All 9,656 skills received the identical verdict
in the v0.8.0 run (malicious BLOCK 3,399, CAUTION 2,718, PASS
1,304; benign BLOCK 0, CAUTION 557, PASS 1,678), and the family
table below is likewise unchanged. v0.7 added no deterministic
rules (the count stayed 59). The post-v0.6 deterministic changes
did fire — on 163 malicious and 16 benign folders the rule sets
differ — but every new fire landed on a folder already at that
verdict or higher:

- `ERROR_INFO_LEAK`'s JavaScript/TypeScript form (v0.7.1) fired
  on 38 more malicious folders (473 → 511 fires, all at CAUTION
  severity): 30 were already BLOCK and 8 already CAUTION.
- The claims check (v0.7.1) reported contradictions on 129
  malicious folders — 126 at CAUTION tier, 3 at its BLOCK tier
  for exfiltration contradictions — and on 16 benign folders.
  Every one was already at the same or a higher verdict; no
  benign verdict changed. On this corpus the check corroborates
  verdicts the behaviour rules had already reached, which is
  what it is for: it reports where a skill's own claims disagree
  with the scan.
- The two MCP tool-description rules (v0.8.0) fired 0 times:
  only 12 of 7,421 malicious folders carry a `"tools"` manifest
  at all (see Limitations). The corpus predates that attack
  shape; the rules are covered by their fixture suites instead.
- `--combine`, `--pin` / `--check-pin` and `--exceptions` are
  separate modes a plain folder scan never exercises, so this
  run says nothing about them either way.

(For the record, v0.6's own change from v0.5 was four
previously-CAUTION malicious skills moving to BLOCK, all caught
by the then-new AGENT_CONFIG_WRITE rule in code; that rule still
fires on 38 malicious folders, 9 at BLOCK severity, and
AGENT_CREDENTIAL_READ still on none, because the corpus's
credential theft aims at SSH/cloud/browser stores, not agent
credential stores.)

What changed from v0.8.0, stated exactly (2026-11-15 run):
**297 malicious skills moved from CAUTION to BLOCK, and
nothing else.** Every transition is attributed to the one new
rule, the `INJECTION_EXECUTION` promotion (temp-path kind);
PASS counts are identical on both sides; the benign side is
identical (0 false BLOCKs, 557 CAUTION, and the promotion
fires nowhere on it). The same run on a second, internal
benign corpus — 344 hand-written benign skills with real
code, frozen before this measurement — also showed zero
promotions; that set's baseline (52 of 344 BLOCKed by
pre-existing rules, three defect groups among them) is
recorded in the README's "What remains open" block, and its
fixes are the next work item. Seven other measured promotion
candidates were not shipped: each has a legitimate twin the
scanner cannot tell apart at line level, and they stay at
CAUTION deliberately.

A same-day fix wave then tightened three rules to require
the evidence their names claim (`SSH_CREDENTIAL_READ` must
see an actual read of key material; `NETWORK_SEND_DATA`
judges the tokenised statement, so `-D` no longer matches
`-d` and another command's `-d` is not curl's; `RM_RF`
demotes only provably own-created targets). Final effect on
this corpus: 34 explained BLOCK losses against 27 gains
(genuine multi-line curl sends the per-line pattern had
missed) — BLOCK 3,696 → 3,689 — one mention-only skill
dropping CAUTION → PASS, and benign CAUTIONs 557 → 551 with
false BLOCKs still 0. On the internal code-bearing benign
set the same wave moved BLOCK 52 → 38, the remainder being
stated stances.

### Detection by attack family (membership basis)

The BLOCK column is the 2026-11-15 run; BLOCK+CAUTION is
unchanged from v0.8.0 except for one mention-only skill the
fix wave dropped from CAUTION to PASS (no-category row),
because the promotion only moved skills that were already
flagged.

| Family | n | BLOCK | BLOCK+CAUTION |
|---|---|---|---|
| privilege_tool_authority_abuse | 1,004 | 78.2% | 99.4% |
| execution_code_delivery | 3,205 | 79.2% | 97.9% |
| credential_access | 197 | 54.3% | 95.9% |
| persistence_control | 249 | 55.4% | 90.0% |
| instruction_goal_memory_manipulation | 1,560 | 70.4% | 86.2% |
| data_exfiltration_disclosure | 266 | 35.0% | 83.8% |
| resource_availability_abuse | 330 | 41.5% | 90.3% |
| dependency_supply_chain | 167 | 14.4% | 87.4% |
| defense_evasion_obfuscation | 20 | 10.0% | 100% |
| integrity_output_manipulation | 97 | 2.1% | 28.9% |
| discovery_reconnaissance | 5 | 0.0% | 20.0% |
| (no category assigned) | 2,591 | 26.8% | 67.5% |

Two membership figures need their honest footnotes:

- *Instruction/goal manipulation* looks respectable on a membership
  basis because most of those skills also carry code-shaped labels.
  Among **pure** instruction-manipulation skills (single category,
  prose payloads, n=365), BLOCK is **8.8%** and BLOCK+CAUTION 45.2%.
- *Output manipulation* is near-blind in both views: pure
  single-category BLOCK 2.4% (2026-11-15 run; 1.2% before the
  promotion), BLOCK+CAUTION 28.6%.

### Benign side in detail

- False BLOCKs: **0 of 2,235 (0%)**, as in v0.4. v0.3 measured 15
  false BLOCKs (0.67%) — a regression caused by `SUBSTITUTION_EXEC`
  firing at block severity on command-substitution examples inside
  benign prose documentation. v0.4 capped inert text (comments,
  string literals, documentation examples) below block severity,
  the regression was fully reversed on the same benign set, and
  v0.5 holds at zero.
- CAUTIONs: 551 (24.7%). The count was 557 (24.9%) from v0.6
  through the promotion run (up only 2 from 555, 24.8%, in
  v0.5 — the v0.6 addition was `AGENT_CONFIG_WRITE` on 5
  skills, 0.22%, all in prose at caution severity); the fix
  wave's SSH prose gate then removed 6 mention-only
  cautions. The only post-v0.6 rule to fire on the
  benign side is the claims check: `CLAIM_CONTRADICTED` on 16
  skills, every one already at CAUTION — no benign verdict
  changed in the v0.8.0 run, and none in the 2026-11-15 run
  either (the promotion fires nowhere on the benign side). The top driver overall remains
  `PROSE_DOWNLOAD_RUN` (290 skills, 13.0% of all benign): prose
  that joins an external download with a run step.

## Limitations

- **Most misses are prose-only skills.** Of the 1,304 malicious
  skills that PASSed, 886 are a single `SKILL.md` with no code:
  install lures pointing at external archives, pure instruction/goal
  manipulation, and output manipulation. A deterministic folder
  scanner sees behaviour shapes in code and text mechanics; it does
  not understand what prose *means*, and these numbers show exactly
  where that boundary sits.
- **Code-bearing misses exist too.** 239 missed folders contain
  code. The dominant shape is a small reader-helper script that
  reads local files and returns their contents, with the onward
  send performed by the agent following the prose — the exfiltration
  channel is outside the folder's code. Part of the class is pure
  transformation code structurally indistinguishable from benign
  utilities.
- **Asymmetry caveat.** Malicious skills were scanned as full
  packages (code included); benign skills as prose-only folders.
  That mirrors how SkillScan is used (scan the folder you were
  given), but it means the benign false-positive figure measures
  prose-triggered false BLOCKs, not code-triggered ones.
- **Manifest shapes are rare in this corpus.** Only 693 of the
  7,421 malicious folders carry any `.json` file at all, only 12
  carry a `"tools"` key — the MCP tool-manifest shape — and no
  URL/VCS dependency specs appear in it. So the v0.8.0 MCP
  tool-description rules fired 0 times here and these results say
  nothing about them either way (their evidence is their fixture
  suites), and the dependency/supply-chain family's low BLOCK
  rate is mostly a severity-policy question about install
  instructions; these results say little about manifest-heavy
  real-world folders.
- **Corpus dependence.** These rates are properties of this corpus
  at this pinned revision and this scanner version. A different
  corpus will give different numbers; the pinned commits above are
  what make this run reproducible and falsifiable.
