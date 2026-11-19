"""Deterministic rule definitions for SkillScan.

Every rule is plain data: an id, a severity, a plain-English reason and a
compiled regex applied line-by-line to text files. Python files additionally
go through `ast` checks in scanner.py, which map syntax nodes onto the same
rule ids. No rule uses an LLM; a verdict is fully reproducible from the
folder contents.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str  # "block" or "caution"
    reason: str
    pattern: re.Pattern
    # OWASP mapping: categories from the OWASP LLM Top 10 (2025) and the
    # OWASP MCP Top 10 this rule's technique belongs to, e.g. "LLM02,
    # MCP01". Empty string where no category sensibly applies. Metadata
    # only — it never affects the verdict; it exists so findings can be
    # triaged in the taxonomies security teams already use.
    owasp: str = ""


# The OWASP mapping for every rule, kept in one table so it can be
# reviewed at a glance. LLM codes are the OWASP LLM Top 10 (2025);
# MCP codes are the OWASP MCP Top 10.
_OWASP_MAP: dict[str, str] = {
    "SSH_CREDENTIAL_READ": "LLM02, MCP01",
    "AGENT_CREDENTIAL_READ": "LLM02, MCP01",
    "AGENT_CONFIG_WRITE": "LLM06, MCP02, MCP05",
    "CLOUD_CREDENTIAL_READ": "LLM02, MCP01",
    "ENV_FILE_READ": "LLM02, MCP01",
    "ENVIRON_SECRET_ACCESS": "LLM02, MCP01",
    "NETWORK_ACCESS": "",
    "NETWORK_SEND_DATA": "LLM02",
    "SHELL_SUBPROCESS": "LLM06, MCP05",
    "SHELL_OS_SYSTEM": "LLM06, MCP05",
    "EVAL_EXEC": "LLM06, MCP05",
    "BASE64_OBFUSCATION": "MCP03",
    "DECODE_AND_RUN": "MCP03, MCP05",
    "CURL_PIPE_BASH": "LLM03, MCP04, MCP05",
    "FILE_DELETE": "LLM06",
    "RM_RF": "LLM06",
    "PERSISTENCE": "LLM06",
    "HOME_OR_SYSTEM_WRITE": "",
    "CHMOD_CHOWN": "",
    "RUNTIME_PACKAGE_INSTALL": "LLM03, MCP04",
    "DYNAMIC_IMPORT": "LLM03, MCP04",
    "CREDENTIAL_ENUMERATION": "LLM02, MCP01",
    "EXFIL_COMBINATION": "LLM02",
    "MCP_UNRESTRICTED_EXEC": "LLM06, MCP02, MCP05",
    "MCP_UNRESTRICTED_READ": "LLM02, MCP10",
    "MCP_SERVER_COMMAND": "MCP05, MCP09",
    "HARDCODED_SECRET_LIVE": "LLM02, MCP01",
    "HARDCODED_SECRET_GENERIC": "LLM02, MCP01",
    "CLOUD_METADATA_ACCESS": "LLM02, MCP01",
    "CLOUD_METADATA_EXFIL": "LLM02, MCP01",
    "BROWSER_CREDENTIAL_STORE": "LLM02, MCP01",
    "REVERSE_SHELL": "MCP05",
    "ERROR_INFO_LEAK": "LLM02, MCP10",
    "PACKAGE_INSTALL_SCRIPT": "LLM03, MCP04",
    "PACKAGE_INSTALL_SCRIPT_EXEC": "LLM03, MCP04, MCP05",
    "DEPENDENCY_SOURCE": "LLM03, MCP04",
    "DEPENDENCY_EXECUTION": "LLM03, MCP04, MCP05",
    "INSTALL_FROM_URL": "LLM03, MCP04",
    "DOWNLOAD_AND_RUN": "LLM03, MCP05",
    "PROSE_DOWNLOAD_RUN": "LLM03, MCP04",
    "READ_AND_DISCLOSE": "LLM02, MCP03",
    "OUTPUT_MANIPULATION": "LLM01, LLM08",
    "PROSE_INSTRUCTION_EN": "LLM01, MCP06",
    "PROSE_FETCH_EXECUTE": "LLM03, MCP04",
    "PROSE_PIPE_INSTRUCTION": "LLM03, MCP04, MCP05",
    "PROSE_READ_SEND": "LLM02, MCP03",
    "PROSE_SAFETY_BYPASS": "LLM06, MCP05",
    "LURE_WITH_BYPASS": "LLM03, MCP04, MCP05",
    "TAINTED_SEND": "LLM02",
    "SECRET_FLOW": "LLM02",
    "TYPOSQUAT_SUSPECT": "LLM03, MCP04",
    "SCAN_INCOMPLETE": "",
    "HIDDEN_TEXT": "LLM01, MCP03, MCP06",
    "NON_ENGLISH_INSTRUCTION": "LLM01, MCP06",
    "ANY_LANGUAGE_STRUCTURE": "LLM01, MCP06",
    "MARKDOWN_CONCEALMENT": "LLM01, MCP03, MCP06",
    "SUBSTITUTION_EXEC": "LLM03, MCP05",
    "ENV_INJECTION": "LLM06, MCP05",
    "ENV_INJECTION_INSTALL": "LLM03, MCP04, MCP05",
    "CLAIM_CONTRADICTED": "LLM01",
    "CLAIM_EXFIL_CONTRADICTION": "LLM01, LLM02",
    "MCP_DESCRIPTION_INSTRUCTION": "LLM01, MCP04",
    "MCP_DESCRIPTION_POISONING": "LLM01, MCP04",
    "INJECTION_EXECUTION": "LLM06, MCP05",
    "INSTALL_FROM_BARE_IP": "LLM03, MCP04",
    "SETUID_CHMOD": "LLM06, MCP05",
    "SUDOERS_GRANT": "LLM06, MCP05",
    "SUDO_GROUP_GRANT": "LLM06, MCP05",
    "SITECUSTOMIZE_WRITE": "LLM06, MCP05",
    "SCHTASKS_CREATE": "LLM06, MCP05",
    "CRON_PATH_WRITE": "LLM06, MCP05",
    "STARTUP_FOLDER_WRITE": "LLM06, MCP05",
    "REGISTRY_RUN_WRITE": "LLM06, MCP05",
    "MINER_BINARY_CONTEXT": "LLM06",
    "STRATUM_ENDPOINT": "LLM06",
    "POWERSHELL_REMOTE_EXEC": "LLM03, MCP05",
}


def _rule(rule_id: str, severity: str, reason: str, pattern: str) -> Rule:
    return Rule(rule_id, severity, reason,
                re.compile(pattern, re.IGNORECASE),
                owasp=_OWASP_MAP.get(rule_id, ""))


def _metadata_pattern() -> str:
    """Cloud metadata endpoints in every cheap textual form: dotted IP,
    decimal-integer IP (2852039166), hex IP (0xa9fea9fe), the AWS IPv6
    endpoint, the Google hostname, and the well-known paths (including
    the IMDSv2 token path /latest/api/token). The integer/hex forms are
    computed from the dotted constants so they cannot drift apart."""
    parts = [
        r"169\.254\.169\.254", r"169\.254\.170\.2",
        r"metadata\.google\.internal", r"metadata\.goog\b",
        r"/latest/meta-data/", r"/latest/api/token",
        r"/computeMetadata/v1/", r"fd00:ec2::254",
    ]
    for dotted in ("169.254.169.254", "169.254.170.2"):
        value = 0
        for octet in dotted.split("."):
            value = (value << 8) + int(octet)
        parts.append(rf"\b{value}\b")          # decimal form
        parts.append(rf"0x0*{value:x}\b")      # hex form
    return "(" + "|".join(parts) + ")"


METADATA_PATTERN = _metadata_pattern()


RULES: list[Rule] = [
    _rule(
        "SSH_CREDENTIAL_READ", "block",
        "Reads SSH credential material (~/.ssh / private key files). A skill "
        "has no legitimate reason to read your SSH keys.",
        # Dedicated matchers in scanner.py (fix wave): the rule fires
        # only when a key-material path is consumed by a read
        # operation — a bare path mention, an assignment, a chmod or
        # a permission repair is not a read.
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "AGENT_CREDENTIAL_READ", "block",
        "Reads an AI agent's own stored sign-in credentials (for "
        "example ~/.claude/.credentials.json, ~/.codex/auth.json, or a "
        "Gemini/OpenCode auth store). Those files hand over the user's "
        "agent-account session, and a skill has no ordinary reason to "
        "read them. It counts as credential material for "
        "EXFIL_COMBINATION, like an SSH key read.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "AGENT_CONFIG_WRITE", "block",
        "Writes, appends, copies or registers configuration into a "
        "GLOBAL AI-agent configuration location outside the skill's "
        "own folder (for example ~/.claude/CLAUDE.md, ~/.claude "
        "settings or SessionStart hooks, ~/.codex configuration, a "
        "desktop app's MCP config, or global editor/agent rules). "
        "That silently changes what the user's agent does in every "
        "future session, not just while this skill runs. A skill's own "
        "project-local .claude/.codex/.mcp files are not this rule. "
        "Documentation that tells the user to make the same change "
        "themselves, visibly, is the same location at CAUTION — "
        "user-mediated, not silent.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "CLOUD_CREDENTIAL_READ", "block",
        "Reads cloud credential files (~/.aws, ~/.azure, ~/.gcloud), which "
        "can hand over full cloud-account access.",
        r"(\.aws\b|\.azure\b|\.gcloud\b|aws_access_key|aws_secret)",
    ),
    _rule(
        "ENV_FILE_READ", "block",
        "Reads a .env file, where API keys and passwords are commonly stored. "
        "(JS process.env is environment access, not this rule. Placeholder "
        "templates such as .env.example / .env.sample / .env.template are "
        "not flagged — they hold no real values.)",
        r"((?<![\w])\.env\b(?!\.(example|sample|template|dist|defaults)\b)|dotenv|load_dotenv)",
    ),
    _rule(
        "ENVIRON_SECRET_ACCESS", "caution",
        "Accesses environment variables from the host environment, where API "
        "keys and tokens commonly live.",
        r"(os\.environ\b|getenv\s*\(|process\.env\b)",
    ),
    _rule(
        "NETWORK_ACCESS", "caution",
        "Makes network requests. Network access is common in honest skills, "
        "but it is also the channel used to send your data away — check where it talks to.",
        r"((?<![\w.])(requests|httpx)\s*\.|(?<![\w.])urllib\s*\.\s*(?:request|urlopen)\b|(?<![\w.])http\.client\b|"
        r"(?<![\w.])socket\s*\.\s*(socket|create_connection)\b|"
        r"(?<![\w.])(fetch|axios|XMLHttpRequest)\s*\(|(?<![\w.])curl\s|(?<![\w.])wget\s|"
        r"(?<![\w.])(?:node:)?https?\s*\.\s*(get|request)\s*\()",
    ),
    _rule(
        "NETWORK_SEND_DATA", "block",
        "Sends data out over the network (HTTP POST/PUT, curl -d, a Request "
        "with a body). Combined with any local file access this is the "
        "classic exfiltration shape.",
        # The curl/wget surface is NOT here: it is split by
        # surface in scanner.py (fix waves 1-2, shell surface
        # restored in wave 4). AST subprocess strings and shell
        # files are judged by the statement tokeniser (full
        # spec'd flag family, _nsd_shell_hit); shell files are
        # judged on the joined logical (continuation-joined,
        # variable-expanded) statement. Both require curl/wget
        # in command position and a case-sensitive data flag
        # among the command's own top-level option tokens.
        # Code files (.py/.js/...) get
        # the baseline line regex with only two repairs — the data
        # flags match case-sensitively (the old IGNORECASE match
        # read curl's receive-side `-D` as `-d`) and a flag inside
        # a `$(...)` span does not count (mktemp's `-d`) — see
        # _nsd_code_line_hit. Documentation files keep the old
        # per-physical-line regex exactly (_NSD_DOC_LINE_RE): the
        # tokeniser's joined-statement judging changed doc and
        # code behaviour beyond the fixes' scope.
        r"((?<![\w.])(requests|httpx)\s*\.\s*(post|put|patch)\s*\(|"
        r"\.post\s*\(\s*['\"]https?://|urlopen\s*\([^)]*data\s*=)",
    ),
    _rule(
        "SHELL_SUBPROCESS", "caution",
        "Runs external programs via subprocess / child_process. Sometimes "
        "legitimate (backups, media tools); always worth reading before you install.",
        r"((?<![\w.])subprocess\s*\.\s*(?-i:run|Popen|call|check_output|check_call)\s*\(|"
        r"child_process\s*\.|(?<![\w.])execSync\s*\(|(?<![\w.])spawnSync\s*\()",
    ),
    _rule(
        "SHELL_OS_SYSTEM", "block",
        "Runs shell commands through os.system / os.popen, with full shell "
        "interpretation and no argument safety.",
        r"(os\.system\s*\(|os\.popen\s*\(|commands\.getoutput)",
    ),
    _rule(
        "EVAL_EXEC", "block",
        "Evaluates or executes dynamic code strings (eval/exec). Whatever the "
        "string contains runs with the agent's full permissions.",
        r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|__import__\s*\(",
    ),
    _rule(
        "BASE64_OBFUSCATION", "caution",
        "Decodes base64 / encoded blobs. Encoding is sometimes innocent, but "
        "in an installable skill it often hides the real payload from reviewers.",
        r"((?<![\w.])(base64\s*\.\s*\w+|b64decode\s*\(|b64encode\s*\(|atob\s*\(|fromhex\s*\())",
    ),
    _rule(
        "DECODE_AND_RUN", "block",
        "Decodes an encoded payload AND executes dynamic code in the same file "
        "— the standard obfuscated-dropper pattern.",
        r"(b64decode|base64)",  # file-level co-occurrence handled in scanner.py
    ),
    _rule(
        "CURL_PIPE_BASH", "block",
        "Downloads a script and pipes it straight into a shell (curl|bash / "
        "wget|sh). The downloaded code is never reviewed before it runs.",
        r"(curl[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh)|wget[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh))",
    ),
    _rule(
        "FILE_DELETE", "caution",
        "Deletes files (os.remove / os.unlink / shutil.rmtree). Legitimate in "
        "cleanup tools, dangerous everywhere else — check exactly what it deletes.",
        r"(shutil\.rmtree\s*\(|os\.remove\s*\(|os\.unlink\s*\(|pathlib[^\n]*\.unlink\s*\()",
    ),
    _rule(
        "RM_RF", "block",
        "Uses `rm -rf`, recursive forced deletion that can wipe directories "
        "outside the skill's own folder.",
        r"rm\s+-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r",
    ),
    _rule(
        "PERSISTENCE", "block",
        "Installs persistence outside the skill folder (crontab, shell "
        "startup files, LaunchAgents, systemd units, autostart entries) so "
        "code keeps running after the skill is removed.",
        r"(crontab|\.bashrc|\.zshrc|\.profile\b|LaunchAgents|LaunchDaemons|systemd|\.config/autostart|rc\.local)",
    ),
    _rule(
        "HOME_OR_SYSTEM_WRITE", "caution",
        "Resolves or touches paths in the home directory or system locations "
        "(Path.home, expanduser, $HOME, /etc, /usr/local) instead of staying "
        "inside its own skill folder.",
        r"(Path\.home\s*\(|expanduser\s*\(|getpwuid|homedir\s*\(|\$HOME\b|/etc/|/usr/local/)",
    ),
    _rule(
        "CHMOD_CHOWN", "caution",
        "Changes file permissions or ownership (chmod/chown), which can make "
        "files world-writable or lock the owner out.",
        r"(os\.chmod\s*\(|os\.chown\s*\(|(?<![\w.])chmod\s|(?<![\w.])chown\s)",
    ),
    _rule(
        "RUNTIME_PACKAGE_INSTALL", "caution",
        "Installs packages at run time (pip install / npm install / apt-get "
        "install) instead of declaring dependencies up front — the installed "
        "code is unreviewed and unpinned. (Documentation that merely tells "
        "the user to install a NAMED package from the official registry, or "
        "to install the declared requirements file, is ordinary setup prose "
        "and is not flagged; an install from a URL / archive / custom index "
        "is flagged separately as INSTALL_FROM_URL.)",
        r"(pip3?\s+install|npm\s+install|yarn\s+add|apt(-get)?\s+install|brew\s+install|gem\s+install)",
    ),
    _rule(
        "DYNAMIC_IMPORT", "caution",
        "Loads modules or functions dynamically (importlib / getattr, or a "
        "JS require() of a computed, non-literal path) in a way static "
        "review cannot fully resolve. Indirection like this is how "
        "payloads hide from reviewers — read it by hand.",
        r"(importlib\.import_module\s*\(|"
        r"(?<![\w.])require\s*\(\s*(?![\"'][^\"']*[\"']\s*[,)]))",
    ),
    _rule(
        "CREDENTIAL_ENUMERATION", "caution",
        "Enumerates files with glob/walk patterns that look like credential "
        "discovery (id_*, .ssh*, *key*) instead of naming one file it needs.",
        r"(glob\s*\([^)]*(id_|\.ssh|\*key)|rglob\s*\([^)]*(id_|\.ssh))",
    ),
    _rule(
        "EXFIL_COMBINATION", "block",
        "This skill both reads credential / private material AND has a "
        "way to send data out over the network. That combination is the "
        "exfiltration shape, whatever either half claims to be for.",
        r"(?!)never-matches-line-level",  # scan-level combination, scanner.py
    ),
    _rule(
        "MCP_UNRESTRICTED_EXEC", "block",
        "This MCP manifest declares a tool that runs arbitrary caller-supplied "
        "commands / code with the user's permissions and no constraint.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "MCP_UNRESTRICTED_READ", "caution",
        "This MCP manifest declares a tool that reads arbitrary files by "
        "unconstrained path, so anything on the machine can be pulled in.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "MCP_SERVER_COMMAND", "caution",
        "This MCP manifest starts a server through a shell / interpreter / "
        "package runner command — that command runs on your machine at agent start.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "HARDCODED_SECRET_LIVE", "block",
        "Contains a credential in an unambiguous live format (an AWS "
        "access-key id, a GitHub or GitLab token, an sk- API key, a "
        "Stripe live key, an npm token, a Slack token, or a private-key "
        "block) written directly into the skill. Real keys "
        "do not belong inside installable code — treat this one as "
        "compromised. Placeholder values and clearly-marked documentation "
        "examples are deliberately not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "HARDCODED_SECRET_GENERIC", "caution",
        "Assigns a long, high-entropy literal to a password / secret / "
        "token / api-key variable. It may be an innocent test value, but "
        "hardcoded credentials in shipped code have a way of being real — "
        "check it, and prefer environment variables. Obvious placeholders "
        "and environment-variable references are not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "CLOUD_METADATA_ACCESS", "caution",
        "References a cloud metadata endpoint (169.254.169.254, "
        "169.254.170.2, metadata.google.internal, /latest/meta-data/) "
        "in dotted, decimal-integer, hex, or IPv6 form, or the IMDSv2 "
        "token path. That service hands out temporary cloud credentials "
        "to anything that can reach it, so a skill has almost no "
        "legitimate reason to talk to it — on its own this is a caution; "
        "combined with an outbound send it becomes a block "
        "(CLOUD_METADATA_EXFIL). Sending TO the metadata endpoint itself "
        "(the IMDSv2 token PUT) is this rule, not exfiltration.",
        METADATA_PATTERN,
    ),
    _rule(
        "CLOUD_METADATA_EXFIL", "block",
        "This skill reaches a cloud metadata endpoint (a source of live "
        "cloud credentials) AND reads credential material or has a way "
        "to send data out over the network. That is the cloud "
        "credential-theft shape.",
        r"(?!)never-matches-line-level",  # scan-level combination, scanner.py
    ),
    _rule(
        "BROWSER_CREDENTIAL_STORE", "caution",
        "Touches browser or wallet credential storage (browser profile "
        "password/cookie stores such as Login Data, logins.json, key4.db, "
        "Local State, browser profile directories, or wallet extension "
        "storage). Reading these is what stealer malware does; a skill "
        "that also sends data out is blocked as EXFIL_COMBINATION.",
        r"(Login Data\b|logins\.json|key4\.db|cookies\.sqlite|Local State\b|"
        r"Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|"
        r"wallet\.dat|\.electrum\b|google-chrome\b|BraveSoftware|"
        r"Chrome[/\\]User Data|Edge[/\\]User Data|mozilla[/\\]firefox|"
        r"User Data[/\\](Default|Profile))",
    ),
    _rule(
        "REVERSE_SHELL", "block",
        "Builds a raw-socket reverse shell: it opens a socket connection "
        "and wires it to a shell (socket fd duplication with dup2, "
        "pty.spawn, /dev/tcp, or spawning /bin/sh alongside a socket). "
        "That hands an interactive shell on this machine to whoever is "
        "listening at the other end.",
        r"(?!)never-matches-line-level",  # file-level check in scanner.py
    ),
    _rule(
        "ERROR_INFO_LEAK", "caution",
        "Returns raw exception text, a formatted stack trace, or an "
        "environment dump as a tool result, or sends it on to a "
        "remote endpoint. Whatever receives it (including the model) "
        "then sees internal paths, messages and possibly secrets "
        "that were in the environment. The Python form (returning "
        "str(e) or traceback text from an except block) and the "
        "JavaScript/TypeScript form (returning or sending "
        "err.stack / err.message from a catch block, or the whole "
        "process.env) are both detected. Logging the error and "
        "returning a plain message is the safe shape and is not "
        "flagged.",
        r"(return[^\n]*(traceback\.format_exc|format_exc\s*\())",
    ),
    _rule(
        "PACKAGE_INSTALL_SCRIPT", "caution",
        "This package runs code automatically at install time: an npm "
        "lifecycle script (preinstall / install / postinstall / prepare) "
        "or a setup.py that does more than declare metadata (subprocess, "
        "network, sockets). Install-time code runs before you ever call "
        "the tool — read it before installing.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "PACKAGE_INSTALL_SCRIPT_EXEC", "block",
        "An install-time script downloads or executes outside code "
        "(curl/wget download, pipe to a shell, encoded payload, network "
        "fetch from a script). Code fetched at install time is never "
        "reviewed before it runs — this is the classic malicious-package "
        "shape.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "DEPENDENCY_SOURCE", "caution",
        "A dependency manifest (package.json, requirements file, "
        "pyproject.toml, setup.py, Pipfile) sources a dependency from "
        "OUTSIDE the official package registry: a git URL, a direct "
        "http(s) archive link, a local file path, or a non-official "
        "package index. Registry artefacts are at least versioned and "
        "independently scanned; off-registry code can change silently, "
        "disappear, or never have been reviewed by anyone. On its own "
        "this is a caution; combined with install-time code execution "
        "it becomes DEPENDENCY_EXECUTION.",
        r"(?!)never-matches-line-level",  # manifest-level, scanner.py
    ),
    _rule(
        "DEPENDENCY_EXECUTION", "block",
        "This skill both pulls a dependency from outside the official "
        "registry (git URL / direct archive link / local path / custom "
        "index) AND runs code at install time (an npm lifecycle script, "
        "a setup.py with behaviour, a loader-injection install) or "
        "declares an unrestricted-exec MCP tool. Unreviewed off-registry "
        "code plus an automatic execution path is the malicious-package "
        "shape: nothing a registry would have scanned ever gets a say.",
        r"(?!)never-matches-line-level",  # scan-level combination, scanner.py
    ),
    _rule(
        "INSTALL_FROM_URL", "caution",
        "An install command (pip / npm / yarn / apt / brew / gem) takes "
        "its package from a URL, a git source, an archive file, a local "
        "path, or a non-official package index instead of the official "
        "registry — the S3 install-lure shape. Whatever arrives from "
        "there is unversioned and unreviewed. (Installing a NAMED "
        "package from the official registry is ordinary and is not "
        "flagged in documentation.)",
        r"(?!)never-matches-line-level",  # classified per line, scanner.py
    ),
    _rule(
        "DOWNLOAD_AND_RUN", "block",
        "A JavaScript/TypeScript file both fetches remote content "
        "(http/https module call, fetch, axios) AND dynamically loads "
        "code (require() of a computed, non-literal path, or eval). "
        "Fetching data is ordinary; fetching and then loading what "
        "arrives — or a file it was written to — as code is the JS "
        "download-and-run dropper shape: the executed code is whatever "
        "the server sends at run time, never what was reviewed.",
        r"(?!)never-matches-line-level",  # file-level check in scanner.py
    ),
    _rule(
        "PROSE_DOWNLOAD_RUN", "caution",
        "The instructions walk through a download-and-run chain by "
        "hand: fetch an archive or binary from an external source, "
        "then run, launch or install what arrived. Split across "
        "steps, no single line is a command — but the chain is the "
        "S3 dropper pattern performed by the user or agent instead "
        "of by a script. Only follow it when the source is one you "
        "independently trust.",
        r"(?!)never-matches-line-level",  # document-level, scanner.py
    ),
    _rule(
        "READ_AND_DISCLOSE", "caution",
        "The folder's code reads local files while its instructions "
        "direct sending or uploading content to an external "
        "destination (a URL, an email address, a server or webhook). "
        "Nothing in the code connects the two — the agent itself is "
        "the channel, carrying whatever the code read out of the "
        "machine. Check exactly what is read and where it is sent "
        "before using this skill.",
        r"(?!)never-matches-line-level",  # scan-level combination, scanner.py
    ),
    _rule(
        "OUTPUT_MANIPULATION", "caution",
        "The instructions steer what the agent's output should show or "
        "hide: keeping information from the user, pretending, or always "
        "pushing one option over alternatives. Output manipulation is "
        "the agent lying or nudging on the skill's behalf — different "
        "from a task description, and invisible unless you read the "
        "instructions.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "PROSE_INSTRUCTION_EN", "caution",
        "The instructions contain English system-prompt manipulation: "
        "overriding or discarding earlier instructions, demanding the "
        "system prompt, developer-mode phrasing, or an instruction to "
        "send the user's data to an outside destination. Ordinary "
        "skills describe a task; they do not reprogram the agent.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "PROSE_FETCH_EXECUTE", "caution",
        "The instructions fetch a script or tool straight from a URL "
        "and tell the agent to run it (sometimes only as 'run it'). "
        "The executed code is whatever the server sends at run time — "
        "the prose form of the download-and-run dropper pattern.",
        r"(?!)never-matches-line-level",  # document-level, scanner.py
    ),
    _rule(
        "PROSE_PIPE_INSTRUCTION", "caution",
        "The instructions tell the agent (or you) to pipe a network "
        "download straight into a shell — unverified remote code "
        "executed sight-unseen, written as documentation instead of "
        "as a command line.",
        r"(?!)never-matches-line-level",  # document-level, scanner.py
    ),
    _rule(
        "PROSE_READ_SEND", "caution",
        "The instructions read local files or folders and direct "
        "sending their contents to an outside destination (a URL, an "
        "email address, a server or webhook) — data leaving the "
        "machine by prose instruction, with the agent as the channel. "
        "Check exactly what is read and where it goes.",
        r"(?!)never-matches-line-level",  # document-level, scanner.py
    ),
    _rule(
        "PROSE_SAFETY_BYPASS", "caution",
        "The instructions ask for a safety control — antivirus, "
        "SmartScreen, Gatekeeper, a certificate check — to be "
        "disabled, turned off or ignored so something can run. "
        "Legitimate tools do not need your protections switched off.",
        r"(?!)never-matches-line-level",  # document-level, scanner.py
    ),
    _rule(
        "LURE_WITH_BYPASS", "block",
        "The skill both walks through fetching code to run AND asks "
        "for a safety control to be disabled first — the classic "
        "malware-install lure shape, split across the document so no "
        "single line carries it.",
        r"(?!)never-matches-line-level",  # scan-level combination, scanner.py
    ),
    _rule(
        "TAINTED_SEND", "block",
        "Values read from credential material — SSH keys, token or "
        "credential files, cloud configuration, browser password "
        "stores — flow into a network send in this code. The code may "
        "never name a credential rule; the data flow itself is "
        "credential exfiltration by construction.",
        r"(?!)never-matches-line-level",  # AST taint check in scanner.py
    ),
    _rule(
        "SECRET_FLOW", "caution",
        "A secret-named environment variable's value flows into the "
        "body of an outgoing request. Secrets belong in auth headers; "
        "a secret in a payload body is logged, cached and forwarded "
        "in places headers are not. (A service's own token in its own "
        "Authorization header is ordinary and is not flagged.)",
        r"(?!)never-matches-line-level",  # AST taint check in scanner.py
    ),
    _rule(
        "TYPOSQUAT_SUSPECT", "caution",
        "A declared dependency name is one small edit away from a "
        "very popular package name — a transposed letter, a swapped "
        "separator, a look-alike character. Typosquatting is how "
        "malicious packages ride on a popular package's reputation; "
        "verify the exact spelling against the project's official "
        "documentation before installing.",
        r"(?!)never-matches-line-level",  # manifest check in scanner.py
    ),
    _rule(
        "HIDDEN_TEXT", "block",
        "Text is concealed with invisible or deceptive characters: "
        "zero-width characters, Unicode Tags-block characters (which can "
        "encode a whole hidden instruction), bidirectional control "
        "characters that make text display differently from how it "
        "reads, or an HTML comment carrying instruction-like content. "
        "Hidden text in a skill's instructions or a tool description is "
        "read by the agent but not by you. (Severity is CAUTION for the "
        "character-level indicators; it is BLOCK only when a decoded "
        "Tags-block payload contains instruction keywords. A single "
        "zero-width joiner in ordinary multilingual text does not fire.)",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "NON_ENGLISH_INSTRUCTION", "caution",
        "Instruction-attack phrasing in a language other than English: "
        "an override of earlier instructions, a request to send or steal "
        "credential material, or an instruction to keep something from "
        "the user, in one of the covered languages (Spanish, French, "
        "German, Polish, Turkish, Chinese, Japanese, Russian, Hindi, "
        "Portuguese, Arabic, Korean, Indonesian, Ukrainian). The phrase "
        "lists are data files (skillscan/phrases/<code>.json) — adding "
        "a language means adding one file. This is a phrase list, not "
        "an understanding of the language — it catches the known shapes "
        "and is stated as a heuristic.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "ANY_LANGUAGE_STRUCTURE", "caution",
        "An instruction surface (documentation or a tool description) "
        "in ANY language pairs a private credential-store location "
        "(~/.ssh, ~/.aws, a .env file, an SSH key file, a browser "
        "credential store) with an outbound destination or fetch "
        "command (a URL, an IP address, an email address, curl/wget, "
        "a webhook). That pairing is the exfiltration shape whatever "
        "language the prose is in, so this rule needs no phrase list. "
        "It deliberately requires the private-store anchor: a guide "
        "that tells users to send their own API token to the service's "
        "own API URL is normal documentation and does not fire, and "
        "safety prose warning against the shape does not fire either.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "MARKDOWN_CONCEALMENT", "caution",
        "Content is hidden from a human reader with presentation "
        "tricks — a display:none or visibility:hidden element, "
        "invisible (zero-size / fully transparent / white-on-white / "
        "off-screen-positioned) text, or a hidden attribute — and "
        "the hidden content contains instruction-like wording. The "
        "agent reading the raw file sees what the rendered page hides. "
        "(A plain <details> element is a disclosure widget, not "
        "concealment, and does not fire on its own.)",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "SUBSTITUTION_EXEC", "block",
        "Executes a download through shell substitution — $(curl …), "
        "$(wget …), backtick curl/wget, or process substitution "
        "<(curl …) — so the downloaded content runs as part of another "
        "command instead of travelling down a visible pipe. It is the "
        "quieter sibling of curl | bash: the fetched code is never "
        "reviewed before it runs. (A substitution that only CAPTURES "
        "the download into a variable that is never executed — a "
        "version check fetching a release number — is the same shape "
        "at CAUTION severity, not BLOCK.)",
        r"(\$\(\s*(sudo\s+)?(curl|wget)\b|`\s*(curl|wget)\b|<\s*\(\s*(curl|wget)\b)",
    ),
    _rule(
        "ENV_INJECTION", "caution",
        "Touches loader / interpreter injection points: LD_PRELOAD, "
        "DYLD_INSERT_LIBRARIES or PYTHONSTARTUP (which make other "
        "programs load this code), or writes a file to a predictable "
        "path under /tmp and then makes it executable or runs it — the "
        "fixed-name temp file another process can be tricked into "
        "loading or racing. Setting these at install time is blocked "
        "separately (ENV_INJECTION_INSTALL).",
        r"\b(LD_PRELOAD|DYLD_INSERT_LIBRARIES|PYTHONSTARTUP)\b",
    ),
    _rule(
        "ENV_INJECTION_INSTALL", "block",
        "An install-time or server-start context sets LD_PRELOAD, "
        "DYLD_INSERT_LIBRARIES or PYTHONSTARTUP: an npm lifecycle "
        "script, a setup.py, or an MCP manifest environment entry. "
        "That makes every later program on the machine load the "
        "skill's code — persistence and code injection in one line.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "SCAN_INCOMPLETE", "caution",
        "Some content in this folder could not be scanned (unreadable, "
        "oversized, special file, symlink, or nothing was scanned at all). "
        "A verdict based on partial coverage must not be read as clean.",
        r"(?!)never-matches-line-level",  # scanner bookkeeping, scanner.py
    ),
    _rule(
        "CLAIM_CONTRADICTED", "caution",
        "The skill's own description claims it does not do something "
        "the scan found it doing (its SKILL.md says one thing, its "
        "behaviour says another). If the claim was scoped or "
        "qualified in a way this checker could not see, the "
        "behaviour is still real — read the code before installing.",
        r"(?!)never-matches-line-level",  # claims check, claims.py
    ),
    _rule(
        "MCP_DESCRIPTION_INSTRUCTION", "caution",
        "An MCP tool description steers the agent's behaviour "
        "beyond the tool's own function: cross-tool preference, "
        "instruction overrides, or a credential store named inside "
        "an instruction. Descriptions should say what the tool "
        "does, not direct the agent.",
        r"(?!)never-matches-line-level",  # manifest pass, manifests.py
    ),
    _rule(
        "MCP_DESCRIPTION_POISONING", "block",
        "An MCP tool description carries the tool-poisoning shape: "
        "it tells the agent to keep actions hidden from the user, "
        "or to read a credential store and pass its contents "
        "along. The description is metadata the agent obeys — "
        "treat the server as malicious.",
        r"(?!)never-matches-line-level",  # manifest pass, manifests.py
    ),
    _rule(
        "CLAIM_EXFIL_CONTRADICTION", "block",
        "The skill's own description claims it makes no network use "
        "or never touches credentials, while the scan found the "
        "exfiltration shape: credential material plus a way to send "
        "data out. The description denies the exact behaviour the "
        "scan proved.",
        r"(?!)never-matches-line-level",  # claims check, claims.py
    ),
    # --- CAUTION -> BLOCK promotion combinations (scan-level, -------
    # scanner.py): completed attack chains whose halves are each
    # only a caution. Each fires only on a folder with no
    # block-severity finding yet, so the finding is exactly the
    # promotion.
    _rule(
        "INJECTION_EXECUTION", "block",
        "The skill stages a file at a fixed temp path (a "
        "fixed-name file under /tmp that is made executable or "
        "run) AND has a way to run or download code in the same "
        "file. Either half alone is a caution; together the "
        "staged code actually gets executed — a completed "
        "write-to-a-world-writable-staging-path-and-run-it "
        "chain. (Loader-variable assignments on their own do "
        "not count: they stay ENV_INJECTION, caution — see "
        "compute_promotions for why the set form is parked.)",
        r"(?!)never-matches-line-level",  # promotion pass, scanner.py
    ),
    # --- Gap wave (2026-11-18): priced deterministic shapes, each ----
    # BLOCK because the shape itself is the harm. All are dedicated
    # matchers in scanner.py (_gapwave_findings); the priced forms and
    # their legitimate twins are recorded in the wave's pricing notes.
    _rule(
        "INSTALL_FROM_BARE_IP", "block",
        "An install command (pip / npm / yarn / apt / brew / gem) takes "
        "its package from a bare public IP address instead of a named "
        "registry or mirror — a direct archive URL, or an index / "
        "registry option pointed at the IP. A bare IP has no registry, "
        "no name that can be checked, no TLS identity and no versioning "
        "authority: the installed code is whatever that anonymous host "
        "serves at install time. Real mirrors and registries have "
        "hostnames; private, loopback, link-local and shared/CGNAT "
        "addresses (your own LAN or tailnet infrastructure — only "
        "globally routable addresses are judged) are not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "SETUID_CHMOD", "block",
        "Sets the setuid or setgid bit on a file (chmod with a "
        "4xxx/2xxx/6xxx/7xxx mode, chmod +s, os.chmod with such a mode, "
        "or install -m with one). A setuid file runs with its owner's "
        "privileges whoever launches it — putting that bit on a file a "
        "skill ships is privilege escalation itself. Ordinary "
        "executable permissions (chmod +x, 755) are not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "SUDOERS_GRANT", "block",
        "Contains a passwordless-sudo grant line in full sudoers "
        "grammar (a user, a host spec, and NOPASSWD: followed by a "
        "command spec such as ALL or a path), or writes into "
        "/etc/sudoers or a file under /etc/sudoers.d in a file that "
        "carries grant content (a grant line, or a Defaults that "
        "weakens authentication). Either shape hands out root "
        "access without a password. A bare NOPASSWD fragment (a "
        "detector's search string), merely mentioning or reading "
        "the sudoers path, validating it with visudo -c, copying "
        "it out for backup, or writing a Defaults-only drop-in "
        "that grants nobody anything is not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "SUDO_GROUP_GRANT", "block",
        "Adds a user to the sudo or wheel group (usermod -aG sudo "
        "or --append --groups sudo, gpasswd -a … sudo, adduser "
        "<user> sudo, useradd -G … sudo). Group membership is "
        "standing root access on the machine, granted silently "
        "by a skill.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "SITECUSTOMIZE_WRITE", "block",
        "Writes a sitecustomize.py or usercustomize.py into a "
        "site-packages / dist-packages directory — the write must "
        "target that file (an open-for-write, a copy/move into "
        "place, a variable built from the path and written). "
        "Python imports that module automatically at every "
        "interpreter startup, so the file is code that runs "
        "inside every Python process on the machine — "
        "interpreter-level persistence. Reading the hook, or "
        "copying/moving it OUT (backup, quarantine), is not "
        "flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "SCHTASKS_CREATE", "block",
        "Creates a Windows scheduled task (schtasks /create). A "
        "scheduled task is persistence owned by the operating system: "
        "the payload keeps running on its schedule after the skill "
        "itself is removed.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "CRON_PATH_WRITE", "block",
        "Writes into a cron location (/etc/crontab, /etc/cron.d and "
        "the other /etc/cron.* directories, /var/spool/cron) or "
        "installs a crontab from a file. Cron entries run unattended "
        "on a schedule with the owner's privileges — persistence "
        "outside the skill folder. Merely mentioning or reading a "
        "cron path is not flagged; the write must be anchored to the "
        "path itself.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "STARTUP_FOLDER_WRITE", "block",
        "Writes a file into the Windows Startup folder (Start Menu\\"
        "Programs\\Startup, or shell:startup) — the folder must be "
        "the write's own target or destination. Anything placed "
        "there runs automatically at every sign-in — persistence "
        "outside the skill folder. Listing the folder, writing a "
        "report about it, or moving an item OUT of it is not "
        "flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "REGISTRY_RUN_WRITE", "block",
        "Writes a value under a Windows Registry Run or RunOnce key "
        "(HKCU/HKLM …\\CurrentVersion\\Run) — reg add, "
        "Set-ItemProperty, a registry-API value write linked to "
        "the key, or a .reg file carrying values for the key. "
        "Run-key values launch at every sign-in. Reading or "
        "exporting the key, deleting its values (a .reg line "
        "\"name\"=-, DeleteValue, a delete-only manager), and "
        "indicator lists that merely quote the shapes are not "
        "flagged; a value write is required.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "MINER_BINARY_CONTEXT", "block",
        "Runs, delivers or configures a known cryptominer binary "
        "(xmrig, minerd, cpuminer, ethminer, nbminer, cgminer): "
        "the binary is invoked with arguments, downloaded or "
        "extracted, fetched from a release URL naming it, or named "
        "beside a pool endpoint (a stratum URL, or a host:port in "
        "a -o / pool / url position) in the same statement. The "
        "machine's CPU is the product being taken. A bare name in "
        "a detector's signature list, an explainer's prose, or a "
        "removal tool's target is not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "STRATUM_ENDPOINT", "block",
        "References a stratum mining-pool endpoint "
        "(stratum+tcp://, stratum+ssl:// or stratum+tls://, "
        "including the stratum2+ spellings). A stratum endpoint "
        "is a cryptomining pool connection string; it has no "
        "other use, and its presence means the skill connects "
        "this machine to a mining pool.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    _rule(
        "POWERSHELL_REMOTE_EXEC", "block",
        "PowerShell code fetches remote content and executes it: "
        "Invoke-Expression (iex) applied to a web request (iwr / "
        "irm / Invoke-WebRequest / Invoke-RestMethod / curl / "
        "wget, parenthesised or piped), a DownloadString inside "
        "an iex expression or whose result reaches iex, or "
        "DownloadData whose bytes reach an assembly load. The "
        "executed code is whatever the server sends at run time — "
        "the PowerShell form of the download-and-run dropper. "
        "Like its shell analogues, the shape BLOCKs in script "
        "files and is CAUTION in documentation (vendor install "
        "one-liners in docs are the analogue of curl | sh in "
        "docs). A download with no execution linkage — reading a "
        "version file, a feed, API data — is not flagged.",
        r"(?!)never-matches-line-level",  # dedicated matcher in scanner.py
    ),
    # DD_DISK_FILL was removed in fix wave 3 (dual-use primitive:
    # blank disk images, swap files, LUKS keyfiles and own-drive
    # wipes are syntactically identical to the priced form; see
    # the CHANGELOG and FIX3_NOTE).
]

RULES_BY_ID = {rule.id: rule for rule in RULES}

# Rules that must NOT be applied as plain line regexes (handled specially).
FILE_LEVEL_RULE_IDS = {
    "DECODE_AND_RUN", "EXFIL_COMBINATION", "MCP_UNRESTRICTED_EXEC",
    "MCP_UNRESTRICTED_READ", "MCP_SERVER_COMMAND", "SCAN_INCOMPLETE",
    "HARDCODED_SECRET_LIVE", "HARDCODED_SECRET_GENERIC",
    "CLOUD_METADATA_EXFIL", "REVERSE_SHELL",
    "PACKAGE_INSTALL_SCRIPT", "PACKAGE_INSTALL_SCRIPT_EXEC",
    "HIDDEN_TEXT", "NON_ENGLISH_INSTRUCTION", "MARKDOWN_CONCEALMENT",
    "ENV_INJECTION_INSTALL", "SUBSTITUTION_EXEC",
    "ANY_LANGUAGE_STRUCTURE",
    "DEPENDENCY_SOURCE", "DEPENDENCY_EXECUTION", "INSTALL_FROM_URL",
    "DOWNLOAD_AND_RUN", "PROSE_DOWNLOAD_RUN", "READ_AND_DISCLOSE",
    "OUTPUT_MANIPULATION", "PROSE_INSTRUCTION_EN", "PROSE_FETCH_EXECUTE",
    "PROSE_PIPE_INSTRUCTION", "PROSE_READ_SEND", "PROSE_SAFETY_BYPASS",
    "LURE_WITH_BYPASS", "TAINTED_SEND", "SECRET_FLOW", "TYPOSQUAT_SUSPECT",
    "AGENT_CONFIG_WRITE", "AGENT_CREDENTIAL_READ",
    "CLAIM_CONTRADICTED", "CLAIM_EXFIL_CONTRADICTION",
    "INJECTION_EXECUTION", "SSH_CREDENTIAL_READ",
    "INSTALL_FROM_BARE_IP", "SETUID_CHMOD", "SUDOERS_GRANT",
    "SUDO_GROUP_GRANT", "SITECUSTOMIZE_WRITE", "SCHTASKS_CREATE",
    "CRON_PATH_WRITE", "STARTUP_FOLDER_WRITE", "REGISTRY_RUN_WRITE",
    "MINER_BINARY_CONTEXT", "STRATUM_ENDPOINT",
    "POWERSHELL_REMOTE_EXEC",
}
LINE_RULES = [r for r in RULES if r.id not in FILE_LEVEL_RULE_IDS]
