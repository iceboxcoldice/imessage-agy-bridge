#!/usr/bin/env python3
"""
Deterministic, fail-closed PreToolUse security gate for the iMessage <-> AGY bridge.

Supports two session roles (set via AGY_SESSION_ROLE by imessage-agy-daemon):
  - "restricted" (default, used for all group chats & secondary users):
      Strictly read-only, zero secrets, hard-denies any write/mutation/shell-escape/secret access.
  - "admin" (used ONLY in 1:1 private chat with ADMIN_HANDLES):
      Auto-allows safe read-only non-secret operations; for state-changing/destructive commands,
      file writes, or secret access, pauses and requests explicit YES/NO confirmation over iMessage
      via atomic token-bound IPC with imessage-agy-daemon (configurable via .env).
"""

import json
import os
import re
import shlex
import sys
import time
import uuid
from typing import List, Set, Tuple

HOME_LOWER = os.path.expanduser("~").lower()

# Paths that can NEVER be modified over iMessage (even in 1:1 admin mode) to protect the bridge & TCC binary
SELF_PROTECT_WRITE_PREFIXES = (
    f"{HOME_LOWER}/code/imessage-agy-bridge",
    f"{HOME_LOWER}/.config/imessage-agy-bridge",
    f"{HOME_LOWER}/.local/bin/imessage-agy-daemon",
    f"{HOME_LOWER}/.local/share/imessage-agy-jail",
    f"{HOME_LOWER}/.local/share/imessage-agy-admin",
    f"{HOME_LOWER}/library/launchagents",
    f"{HOME_LOWER}/library/messages",
)

# Paths that can NEVER be read by AGY subprocesses directly (chat.db is managed solely by daemon.m)
NEVER_ALLOW_READ_SUBSTRINGS = (
    "library/messages/chat.db",
)

BASE_BLOCKED_DIR_PREFIXES = (
    f"{HOME_LOWER}/.ssh",
    f"{HOME_LOWER}/.gnupg",
    f"{HOME_LOWER}/.aws",
    f"{HOME_LOWER}/.kube",
    f"{HOME_LOWER}/library/keychains",
    f"{HOME_LOWER}/library/messages",
    "/private/var/db",
    "/var/db",
    "/etc/sudoers",
    "/private/etc/sudoers",
)

RESTRICTED_ONLY_BLOCKED_DIR_PREFIXES = (
    f"{HOME_LOWER}/.gemini",
    f"{HOME_LOWER}/.docker",
    f"{HOME_LOWER}/.config",
    f"{HOME_LOWER}/library",
    f"{HOME_LOWER}/code/imessage-agy-bridge",
)

BASE_BLOCKED_BASENAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "authorized_keys",
    "known_hosts",
    "chat.db",
    "chat.db-wal",
    "chat.db-shm",
    "credentials.json",
    "client_secret.json",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    "master.passwd",
    "sudoers",
}

RESTRICTED_ONLY_BLOCKED_BASENAMES = {
    ".zsh_history",
    ".bash_history",
    ".sh_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".sqlite_history",
}

BLOCKED_EXTENSIONS = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
    ".keychain",
    ".keychain-db",
    ".jks",
    ".keystore",
    ".ovpn",
)

BASE_BLOCKED_COMPONENTS = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    "keychains",
}

RESTRICTED_ONLY_BLOCKED_COMPONENTS = {
    ".gemini",
}

BLOCKED_SUBSTRINGS = (
    "jetski-standalone-oauth-token",
    "chat.db",
    "/.ssh",
    "/.env",
    "id_ed25519",
    "id_rsa",
)

RESTRICTED_ALLOWED_READ_ROOTS = (
    f"{HOME_LOWER}/.config/imessage-agy-bridge/workspaces/jail",
    f"{HOME_LOWER}/.local/share/imessage-agy-jail",
    "/volumes",
    "/tmp",
    "/private/tmp",
    "/var/log",
    "/private/var/log",
    "/opt/homebrew",
    "/usr/local",
    "/applications",
    "/etc/hosts",
    "/private/etc/hosts",
)

ADMIN_ALLOWED_READ_ROOTS = (
    HOME_LOWER,
    "/volumes",
    "/tmp",
    "/private/tmp",
    "/var/log",
    "/private/var/log",
    "/opt/homebrew",
    "/usr/local",
    "/applications",
    "/etc",
    "/private/etc",
    "/library",
    "/system/library",
)

BROAD_RECURSIVE_ROOTS = {
    "/",
    "/users",
}

ALLOWED_BIN_DIRS = (
    "/bin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/opt/homebrew/bin/",
    "/usr/local/bin/",
)

BASE_ALLOWED_COMMANDS = {
    "uptime",
    "df",
    "du",
    "vm_stat",
    "top",
    "ps",
    "sysctl",
    "uname",
    "sw_vers",
    "arch",
    "hostname",
    "date",
    "whoami",
    "id",
    "diskutil",
    "pmset",
    "ioreg",
    "system_profiler",
    "lsof",
    "netstat",
    "ifconfig",
    "scutil",
    "ping",
    "docker",
    "colima",
    "brew",
    "git",
    "ls",
    "stat",
    "file",
    "wc",
    "sort",
    "uniq",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "cut",
    "tr",
    "which",
}

CATASTROPHIC_CMD_PATTERNS = (
    re.compile(r"(?:^|[;&|\s])(?:sudo\s+)?rm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+(?:/|/\*|~|\$HOME|/Users|" + re.escape(HOME_LOWER) + r"|/Volumes)\s*(?:$|[;&|])", re.IGNORECASE),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdiskutil\s+(?:eraseDisk|eraseVolume|apfs\s+deleteContainer)\b", re.IGNORECASE),
    re.compile(r"\bdd\s+.*\bof=/dev/r?disk", re.IGNORECASE),
)


def parse_csv_env(var_name: str, expand_path: bool = False) -> List[str]:
    raw = (os.environ.get(var_name) or "").strip()
    if not raw:
        return []
    items = []
    for part in raw.split(","):
        clean = part.strip()
        if not clean:
            continue
        if expand_path:
            clean = os.path.abspath(os.path.expanduser(clean)).lower()
        items.append(clean)
    return items


def get_blocked_dir_prefixes(is_admin: bool = False) -> Tuple[str, ...]:
    extra = parse_csv_env("AGY_EXTRA_BLOCKED_PATHS", expand_path=True)
    base = BASE_BLOCKED_DIR_PREFIXES if is_admin else (BASE_BLOCKED_DIR_PREFIXES + RESTRICTED_ONLY_BLOCKED_DIR_PREFIXES)
    return base + tuple(extra)


def get_allowed_read_roots(is_admin: bool) -> Tuple[str, ...]:
    base = ADMIN_ALLOWED_READ_ROOTS if is_admin else RESTRICTED_ALLOWED_READ_ROOTS
    extra = parse_csv_env("AGY_ALLOWED_READ_ROOTS", expand_path=True)
    return base + tuple(extra)


def get_allowed_commands(is_admin: bool) -> Set[str]:
    cmds = set(BASE_ALLOWED_COMMANDS)
    for c in parse_csv_env("AGY_EXTRA_ALLOWED_COMMANDS", expand_path=False):
        cmds.add(c)
    if is_admin:
        cmds.update({
            "cat", "find", "mdfind", "fd", "rg", "jq", "yq", "awk",
            "tree", "realpath", "dirname", "basename", "readlink",
            "md5", "shasum", "diff", "comm", "paste", "column",
            "env", "printenv", "tailscale", "launchctl", "plutil",
            "defaults", "log", "sw_vers", "xcode-select",
        })
    return cmds


def emit(decision: str, reason: str = "") -> None:
    out = {"decision": decision}
    if reason:
        out["reason"] = reason
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()


def is_under_any(path_lower: str, roots: Tuple[str, ...]) -> bool:
    for r in roots:
        if path_lower == r or path_lower.startswith(r.rstrip("/") + "/"):
            return True
    return False


def check_catastrophic_or_self_harm(name: str, args: dict) -> Tuple[bool, str]:
    """Hard guardrails that NEVER allow tampering with chat.db or the bridge daemon itself."""
    raw_dump = json.dumps(args).lower()
    for sub in NEVER_ALLOW_READ_SUBSTRINGS:
        if sub in raw_dump or "chat.db" in raw_dump:
            return False, "Direct access to Messages chat.db is strictly reserved for the bridge daemon."

    if name in {"write_file", "write_to_file", "edit_file", "replace_file_content", "multi_replace_file_content", "delete_file"}:
        path = str(args.get("Path") or args.get("TargetFile") or args.get("AbsolutePath") or "")
        if path:
            for cand in (os.path.abspath(os.path.expanduser(path)).lower(), os.path.realpath(os.path.expanduser(path)).lower()):
                if is_under_any(cand, SELF_PROTECT_WRITE_PREFIXES):
                    return False, f"Modifying bridge infrastructure ('{path}') over iMessage is prohibited; use direct SSH."

    if name == "run_command":
        cmd = str(args.get("CommandLine") or "")
        for pat in CATASTROPHIC_CMD_PATTERNS:
            if pat.search(cmd):
                return False, "Catastrophic disk/root wipe command is permanently blocked over iMessage."
        low_cmd = cmd.lower()
        if "imessage-agy-daemon" in low_cmd or "imessage-agy-jail" in low_cmd or "imessage-agy-admin" in low_cmd:
            if any(w in low_cmd for w in ("rm ", "mv ", "cp ", ">", "chmod ", "chown ", "sed ", "tee ", "truncate ")):
                return False, "Modifying bridge binaries or security hooks over iMessage is prohibited."

    return True, ""


def check_path_safe(raw_path: str, require_allowed_root: bool = True, is_admin: bool = False) -> Tuple[bool, str]:
    """Returns (is_safe, reason). If False due to secret/protected location, reason prefixes '[SECRET]'."""
    p = (raw_path or "").strip()
    if not p:
        if require_allowed_root:
            return False, "Empty file path is not allowed."
        return True, ""

    low_raw = p.lower()
    for sub in BLOCKED_SUBSTRINGS:
        if sub in low_raw:
            return False, f"[SECRET] Access to sensitive path matching '{sub}' is restricted."

    blocked_dirs = get_blocked_dir_prefixes(is_admin=is_admin)
    allowed_roots = get_allowed_read_roots(is_admin=is_admin)
    blocked_components = BASE_BLOCKED_COMPONENTS if is_admin else (BASE_BLOCKED_COMPONENTS | RESTRICTED_ONLY_BLOCKED_COMPONENTS)
    blocked_basenames = BASE_BLOCKED_BASENAMES if is_admin else (BASE_BLOCKED_BASENAMES | RESTRICTED_ONLY_BLOCKED_BASENAMES)

    expanded = os.path.expanduser(p)
    abspath = os.path.abspath(expanded)
    realpath = os.path.realpath(expanded)

    for candidate in (abspath, realpath):
        c_low = candidate.lower()
        if c_low in ("/dev/null", "/dev/stdout", "/dev/stderr"):
            return True, ""

        base = os.path.basename(c_low)
        if base in blocked_basenames or base.startswith(".env"):
            return False, f"[SECRET] Access to sensitive file '{base}' is restricted."

        for ext in BLOCKED_EXTENSIONS:
            if base.endswith(ext):
                return False, f"[SECRET] Access to credential/key file (*{ext}) is restricted."

        if not is_admin and is_under_any(c_low, (f"{HOME_LOWER}/.config/imessage-agy-bridge/workspaces/jail", f"{HOME_LOWER}/.local/share/imessage-agy-jail")):
            return True, ""

        if is_under_any(c_low, blocked_dirs):
            return False, f"[SECRET] Access to protected directory '{candidate}' is restricted."

        parts = [seg for seg in c_low.split("/") if seg]
        for seg in parts:
            if seg in blocked_components:
                return False, f"[SECRET] Access to protected component '{seg}' is restricted."

        if require_allowed_root and not is_under_any(c_low, allowed_roots):
            return False, f"Path '{candidate}' is outside default read-only inspection roots."

    return True, ""


def split_unquoted_pipes(cmd: str) -> Tuple[bool, List[str], str]:
    cleaned = cmd.replace("2>/dev/null", " ").replace("2>&1", " ")

    if "\n" in cleaned or "\r" in cleaned or "\x00" in cleaned:
        return False, [], "Multiline or null-byte commands require explicit approval."

    in_single = False
    in_double = False
    escaped = False
    stages: List[str] = []
    buf: List[str] = []
    i = 0
    n = len(cleaned)

    while i < n:
        ch = cleaned[i]
        nxt = cleaned[i + 1] if i + 1 < n else ""

        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue

        if ch == "\\" and not in_single:
            escaped = True
            buf.append(ch)
            i += 1
            continue

        if ch == "'" and not in_double:
            in_single = not in_single
            buf.append(ch)
            i += 1
            continue

        if ch == '"' and not in_single:
            in_double = not in_double
            buf.append(ch)
            i += 1
            continue

        if not in_single:
            if ch == "`":
                return False, [], "Backtick command substitution is restricted."
            if ch == "$" and nxt in ("(", "{"):
                return False, [], "Shell substitution $(...) or ${...} is restricted."

        if not in_single and not in_double:
            if ch in (";", ">", "<"):
                return False, [], f"Shell operator '{ch}' (chaining/redirection) is restricted."
            if ch == "&":
                return False, [], "Shell backgrounding or '&&' chaining is restricted."
            if ch == "|" and nxt == "|":
                return False, [], "Shell '||' chaining is restricted."
            if ch == "|":
                stage = "".join(buf).strip()
                if not stage:
                    return False, [], "Empty pipeline stage is invalid."
                stages.append(stage)
                buf = []
                i += 1
                continue

        buf.append(ch)
        i += 1

    if in_single or in_double or escaped:
        return False, [], "Unbalanced quotes or trailing escape in command."

    last = "".join(buf).strip()
    if not last:
        return False, [], "Empty command or trailing pipe."
    stages.append(last)
    return True, stages, ""


def non_flag_args(tokens: List[str], flags_with_value: set) -> List[str]:
    res: List[str] = []
    skip_next = False
    for t in tokens[1:]:
        if skip_next:
            skip_next = False
            continue
        if t in flags_with_value:
            skip_next = True
            continue
        if t.startswith("-"):
            continue
        res.append(t)
    return res


def command_touches_secret(cmd: str, is_admin: bool = False) -> bool:
    low = cmd.lower()
    for sub in BLOCKED_SUBSTRINGS:
        if sub in low:
            return True
    for ext in BLOCKED_EXTENSIONS:
        if ext in low:
            return True
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        tokens = cmd.split()
    for tok in tokens:
        if tok in ("|", ";", "&&", "||", ">", ">>", "<"):
            continue
        cand = tok.split("=", 1)[1] if ("=" in tok and tok.startswith("-")) else tok
        if cand.startswith("/") or cand.startswith("~") or "/" in cand or cand.startswith("."):
            ok, reason = check_path_safe(cand, require_allowed_root=False, is_admin=is_admin)
            if not ok and reason.startswith("[SECRET]"):
                return True
    return False


def validate_stage(stage: str, is_admin: bool) -> Tuple[bool, str]:
    try:
        tokens = shlex.split(stage, posix=True)
    except ValueError as e:
        return False, f"Malformed shell quoting: {e}"

    if not tokens:
        return False, "Empty command stage."

    first = tokens[0]
    if "=" in first:
        return False, "Inline environment variable assignments are restricted."

    if "/" in first:
        if not any(first.startswith(d) for d in ALLOWED_BIN_DIRS):
            return False, f"Executable path '{first}' is not in an approved system binary directory."

    prog = os.path.basename(first)
    allowed_cmds = get_allowed_commands(is_admin=is_admin)

    if prog == "cat" and not is_admin:
        return False, "Direct 'cat' is disabled in shared chats; use read_file for non-sensitive files."

    if prog not in allowed_cmds:
        return False, f"Command '{prog}' is not in the auto-approved read-only allowlist."

    args = tokens[1:]

    if prog == "docker":
        pos = non_flag_args(tokens, {"--context", "-c", "-H", "--host", "--config", "--log-level", "-l"})
        if not pos:
            return False, "Docker requires an explicit subcommand."
        sub = pos[0]
        if sub == "inspect":
            if not is_admin:
                return False, "[SECRET] 'docker inspect' exposes container environment variables and is restricted in shared chats."
        elif sub in {"ps", "logs", "stats", "info", "version", "images"}:
            pass
        elif sub in {"volume", "network"}:
            allowed_vn = {"ls", "list", "inspect"} if is_admin else {"ls", "list"}
            if len(pos) < 2 or pos[1] not in allowed_vn:
                return False, f"'docker {sub}' only auto-allows {sorted(allowed_vn)}."
        elif sub == "compose":
            if "--env-file" in args or any(a.startswith("--env-file=") for a in args):
                return False, "[SECRET] 'docker compose --env-file' accesses env secrets."
            compose_idx = tokens.index("compose")
            c_pos = non_flag_args(
                tokens[compose_idx:],
                {"-f", "--file", "-p", "--project-name", "--project-directory", "--profile"},
            )
            if not c_pos or c_pos[0] not in {"ps", "logs", "ls", "top", "images", "version"}:
                return False, "'docker compose' state-changing subcommands require approval."
        else:
            return False, f"Docker subcommand '{sub}' modifies or enters containers."

    elif prog == "colima":
        pos = non_flag_args(tokens, {"-p", "--profile"})
        if not pos or pos[0] not in {"status", "list", "ls", "version"}:
            return False, "'colima' state-changing subcommands require approval."

    elif prog == "git":
        for a in args:
            if (
                a == "-c"
                or a.startswith("-c")
                or a.startswith("--config")
                or a.startswith("--exec")
                or a.startswith("--upload-pack")
                or a == "--output"
                or a.startswith("--output=")
            ):
                return False, f"Git flag '{a}' is restricted."
        pos = non_flag_args(tokens, {"-C", "--git-dir", "--work-tree"})
        if not pos or pos[0] not in {"status", "log", "diff", "branch", "show", "remote", "rev-parse", "describe", "tag"}:
            return False, "Mutating git subcommands require approval."
        if pos[0] in {"branch", "tag"}:
            sub_idx = tokens.index(pos[0])
            sub_args = tokens[sub_idx + 1 :]
            allowed_list_flags = {"-a", "--all", "-r", "--remotes", "-l", "--list", "-v", "-vv", "--verbose", "--show-current", "--Sort"}
            for sa in sub_args:
                if sa in allowed_list_flags or sa.startswith("--sort="):
                    continue
                return False, f"Creating or modifying git {pos[0]}s ('{sa}') requires approval."
        elif pos[0] == "remote":
            sub_idx = tokens.index("remote")
            for sa in tokens[sub_idx + 1 :]:
                if sa not in {"-v", "--verbose", "show"}:
                    return False, f"Mutating 'git remote' argument '{sa}' requires approval."

    elif prog == "sort":
        for a in args:
            if a in {"-o", "--output"} or a.startswith("-o") or a.startswith("--output="):
                return False, "'sort -o/--output' writes to disk and is restricted."

    elif prog == "uniq":
        pos = non_flag_args(tokens, {"-f", "-s", "-w"})
        if len(pos) > 1:
            return False, "'uniq' output file parameter writes to disk and is restricted."

    elif prog == "file":
        for a in args:
            if a in {"-C", "--compile", "-m", "--magic-file"} or a.startswith("-m") or a.startswith("--magic-file="):
                return False, f"'file {a}' is restricted."

    elif prog == "tail":
        for a in args:
            if a in {"-f", "-F", "--follow"} or (a.startswith("-") and not a.startswith("--") and ("f" in a[1:] or "F" in a[1:])):
                return False, "'tail -f/-F' blocks indefinitely in headless mode; use 'tail -n <lines>'."

    elif prog == "ps":
        skip_val = False
        for a in args:
            if skip_val:
                skip_val = False
                continue
            if a in {"-o", "-O", "-p", "-u", "-U", "-g", "-G", "-t"}:
                skip_val = True
                continue
            if a == "-E" or (a.startswith("-") and not a.startswith("--") and "E" in a[1:]):
                return False, "[SECRET] 'ps -E' exposes process environment variables."
            # BSD style flags without leading '-' (e.g., 'ps aux', 'ps eww')
            if not a.startswith("-") and "e" in a:
                return False, "[SECRET] 'ps e' exposes process environment variables."
            if a.startswith("-") and not a.startswith("--") and "e" in a[1:] and a not in {"-ef", "-e", "-eo", "-el"}:
                return False, "[SECRET] 'ps' environment flag is restricted."

    elif prog == "brew":
        pos = non_flag_args(tokens, set())
        if not pos or pos[0] not in {"list", "ls", "info", "services", "doctor", "config", "outdated"}:
            if "--version" not in args:
                return False, "Mutating 'brew' subcommands require approval."
        if pos and pos[0] == "services":
            if len(pos) < 2 or pos[1] not in {"list", "info"}:
                return False, "Mutating 'brew services' subcommands require approval."

    elif prog == "diskutil":
        pos = non_flag_args(tokens, set())
        if not pos or pos[0] not in {"list", "info", "apfs"}:
            return False, "Mutating 'diskutil' subcommands require approval."
        if pos[0] == "apfs" and (len(pos) < 2 or pos[1] != "list"):
            return False, "Mutating 'diskutil apfs' subcommands require approval."

    elif prog == "pmset":
        if not args or args[0] != "-g":
            return False, "Modifying power settings via 'pmset' requires approval."

    elif prog == "sysctl":
        if any(a == "-w" or a.startswith("-w") for a in args):
            return False, "'sysctl -w' modifies kernel state."

    elif prog == "top":
        if "-l" not in args:
            return False, "On macOS, 'top' must include '-l 1' so it exits non-interactively."

    elif prog == "ping":
        if "-c" not in args:
            return False, "'ping' must include '-c <count>' (e.g. 'ping -c 3')."
        idx = args.index("-c")
        if idx + 1 >= len(args) or not args[idx + 1].isdigit() or int(args[idx + 1]) > 5:
            return False, "'ping -c' count must be an integer <= 5."

    is_recursive = False
    if prog in {"grep", "egrep", "fgrep"} and any(
        a in {"-r", "-R", "--recursive", "-rn", "-ri", "-rni", "-rin"}
        or (a.startswith("-") and not a.startswith("--") and ("r" in a[1:] or "R" in a[1:]))
        for a in args
    ):
        is_recursive = True
    if prog == "ls" and any(
        a == "-R" or (a.startswith("-") and not a.startswith("--") and "R" in a[1:])
        for a in args
    ):
        is_recursive = True

    for tok in args:
        low_tok = tok.lower()
        for sub in BLOCKED_SUBSTRINGS:
            if sub in low_tok:
                return False, f"[SECRET] Argument references restricted resource '{sub}'."

        candidates = [tok]
        if "=" in tok and tok.startswith("-"):
            candidates.append(tok.split("=", 1)[1])

        for cand in candidates:
            if not cand or cand.startswith("-"):
                continue

            if any(g in cand for g in ("*", "?", "[")) and ("/" in cand or cand.startswith("~") or cand.startswith(".")):
                return False, f"[SECRET] Wildcard globbing in path argument '{cand}' is restricted."

            looks_like_path = (
                cand.startswith("/")
                or cand.startswith("~")
                or cand.startswith(".")
                or "/" in cand
                or cand.lower() in (BASE_BLOCKED_BASENAMES if is_admin else (BASE_BLOCKED_BASENAMES | RESTRICTED_ONLY_BLOCKED_BASENAMES))
                or any(cand.lower().endswith(ext) for ext in BLOCKED_EXTENSIONS)
            )
            if looks_like_path:
                require_root = cand.startswith("/") or cand.startswith("~")
                ok, reason = check_path_safe(cand, require_allowed_root=require_root, is_admin=is_admin)
                if not ok:
                    return False, reason

                if is_recursive and not is_admin:
                    resolved = os.path.realpath(os.path.expanduser(cand)).lower()
                    if resolved in BROAD_RECURSIVE_ROOTS:
                        return False, f"Recursive scan on broad root '{cand}' is restricted; specify a project subdirectory."

    if is_recursive and not is_admin and not any(not a.startswith("-") for a in args[1:] if prog in {"grep", "egrep", "fgrep"} or args):
        cwd_low = os.path.realpath(os.getcwd()).lower()
        if cwd_low in BROAD_RECURSIVE_ROOTS:
            return False, "Recursive scan from broad working directory is restricted."

    return True, ""


def evaluate_readonly_policy(payload: dict, is_admin: bool) -> Tuple[bool, str]:
    tc = payload.get("toolCall") or {}
    name = (tc.get("name") or "").strip().lower()
    args = tc.get("args") or {}

    if not name:
        return False, "Missing tool name in PreToolUse payload."

    if name in {"read_file", "view_file", "view_file_outline", "view_code_item"}:
        path = args.get("Path") or args.get("AbsolutePath") or args.get("File") or ""
        return check_path_safe(str(path), require_allowed_root=True, is_admin=is_admin)

    if name in {"list_dir", "list_directory"}:
        path = args.get("DirectoryPath") or args.get("Path") or ""
        return check_path_safe(str(path), require_allowed_root=True, is_admin=is_admin)

    if name in {"find_by_name", "grep_search", "code_search"}:
        path = (
            args.get("SearchDirectory")
            or args.get("SearchPath")
            or args.get("DirectoryPath")
            or args.get("Path")
            or ""
        )
        ok, reason = check_path_safe(str(path), require_allowed_root=True, is_admin=is_admin)
        if not ok:
            return False, reason
        resolved = os.path.realpath(os.path.expanduser(str(path))).lower()
        if resolved in BROAD_RECURSIVE_ROOTS:
            return False, f"Recursive search on broad directory '{path}' is restricted; target a specific subfolder."
        query_str = " ".join(
            str(args.get(k) or "") for k in ("Pattern", "Query", "Includes", "Extensions")
        ).lower()
        for sub in BLOCKED_SUBSTRINGS:
            if sub in query_str:
                return False, f"[SECRET] Searching for restricted pattern '{sub}' is restricted."
        return True, ""

    if name in {"search_web", "web_search", "read_url_content"}:
        if name == "read_url_content" and not is_admin:
            return False, "Tool 'read_url_content' is restricted in shared chats."
        return True, ""

    if name == "run_command":
        cmd = str(args.get("CommandLine") or "").strip()
        if not cmd:
            return False, "Empty command is prohibited."
        # Interactive TTY hang guards apply in both modes so daemon never hangs on top/ping without flags
        ok, stages, err = split_unquoted_pipes(cmd)
        if not ok:
            if command_touches_secret(cmd, is_admin=is_admin):
                return False, f"[SECRET] {err}"
            return False, err
        for st in stages:
            st_ok, st_err = validate_stage(st, is_admin=is_admin)
            if not st_ok:
                if not st_err.startswith("[SECRET]") and command_touches_secret(st, is_admin=is_admin):
                    return False, f"[SECRET] {st_err}"
                return False, st_err
        return True, ""

    return False, f"Tool '{name}' modifies state or accesses external resources."


def summarize_tool_call(name: str, args: dict, max_len: int = 1200) -> str:
    if name == "run_command":
        s = str(args.get("CommandLine") or "").strip()
    elif name in {"read_file", "view_file", "view_file_outline", "view_code_item", "write_file", "write_to_file", "edit_file", "replace_file_content", "multi_replace_file_content", "delete_file"}:
        p = args.get("Path") or args.get("TargetFile") or args.get("AbsolutePath") or args.get("File") or ""
        s = f"{name}: {p}"
    elif name in {"list_dir", "list_directory", "find_by_name", "grep_search", "code_search"}:
        p = args.get("DirectoryPath") or args.get("SearchDirectory") or args.get("SearchPath") or args.get("Path") or ""
        q = args.get("Query") or args.get("Pattern") or ""
        s = f"{name}: {p}" + (f" ({q})" if q else "")
    elif name == "read_url_content":
        s = f"read_url: {args.get('Url') or args.get('url') or ''}"
    else:
        s = f"{name}: {json.dumps(args)[:max_len]}"
    return s[:max_len] + ("..." if len(s) > max_len else "")


def request_admin_imessage_approval(category: str, name: str, args: dict, reason: str) -> Tuple[bool, str]:
    approval_dir = (os.environ.get("AGY_APPROVAL_DIR") or "").strip()
    token = (os.environ.get("AGY_APPROVAL_TOKEN") or "").strip()
    try:
        timeout_sec = max(15, min(300, int(float(os.environ.get("AGY_APPROVAL_TIMEOUT") or "90"))))
    except ValueError:
        timeout_sec = 90

    if not approval_dir or not token or not os.path.isdir(approval_dir):
        return False, "Interactive approval channel unavailable."

    req_id = uuid.uuid4().hex[:12]
    code = f"{(uuid.uuid4().int % 9000) + 1000}"
    req_tmp = os.path.join(approval_dir, f".req_{req_id}.tmp")
    req_path = os.path.join(approval_dir, f"req_{req_id}.json")
    resp_path = os.path.join(approval_dir, f"resp_{req_id}.json")

    clean_reason = reason.replace("[SECRET] ", "")
    req_obj = {
        "id": req_id,
        "code": code,
        "token": token,
        "category": category,
        "tool": name,
        "summary": summarize_tool_call(name, args, max_len=1200),
        "reason": clean_reason,
        "created_at": time.time(),
    }

    with open(req_tmp, "w", encoding="utf-8") as f:
        json.dump(req_obj, f)
    os.chmod(req_tmp, 0o600)
    os.replace(req_tmp, req_path)

    deadline = time.time() + timeout_sec
    try:
        while time.time() < deadline:
            if os.path.exists(resp_path):
                try:
                    with open(resp_path, "r", encoding="utf-8") as rf:
                        resp = json.load(rf)
                    os.remove(resp_path)
                except Exception:
                    time.sleep(0.1)
                    continue

                if resp.get("token") != token:
                    return False, "Approval token mismatch (rejected)."
                if resp.get("approved") is True:
                    return True, ""
                return False, str(resp.get("reason") or "Administrator denied permission via iMessage.")
            time.sleep(0.25)
    finally:
        for p in (req_tmp, req_path):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    return False, f"Timed out after {timeout_sec}s waiting for YES/NO approval on iMessage."


def main() -> None:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            emit("deny", "Empty PreToolUse stdin payload.")
            return

        payload = json.loads(raw)
        tc = payload.get("toolCall") or {}
        name = (tc.get("name") or "").strip().lower()
        args = tc.get("args") or {}

        # 0. Universal hard guardrails (chat.db, self-modification, catastrophic disk wipe)
        safe_core, core_reason = check_catastrophic_or_self_harm(name, args)
        if not safe_core:
            emit("deny", f"Blocked by bridge core safety guardrail: {core_reason}")
            return

        role = (os.environ.get("AGY_SESSION_ROLE") or "restricted").strip().lower()
        is_admin = (role == "admin")

        # Non-interactive macOS hang guard even for admin (bare 'top' without -l or bare 'ping' without -c hangs forever)
        if name == "run_command":
            cmd_str = str(args.get("CommandLine") or "").strip()
            try:
                toks = shlex.split(cmd_str, posix=True)
            except ValueError:
                toks = []
            if toks:
                bname = os.path.basename(toks[0])
                if bname == "top" and "-l" not in toks[1:]:
                    emit("deny", "On macOS headless mode, pass 'top -l 1 -n 10' so top exits cleanly.")
                    return
                if bname == "ping" and "-c" not in toks[1:]:
                    emit("deny", "Pass 'ping -c 3 <host>' so ping terminates cleanly.")
                    return

        allowed, reason = evaluate_readonly_policy(payload, is_admin=is_admin)
        if allowed:
            emit("allow")
            return

        # Restricted role (group chats & secondary users): strictly fail-closed!
        if not is_admin:
            clean_reason = reason.replace("[SECRET] ", "")
            emit("deny", f"Blocked by iMessage bridge security policy: {clean_reason}")
            return

        # 1:1 Primary Admin role: check .env policy for interactive YES/NO approval
        is_secret = reason.startswith("[SECRET]") or (name == "run_command" and command_touches_secret(str(args.get("CommandLine") or ""), is_admin=True))
        category = "secret_access" if is_secret else "privileged_action"

        policy_var = "AGY_ADMIN_ASK_SECRETS" if is_secret else "AGY_ADMIN_ASK_DESTRUCTIVE"
        policy_mode = (os.environ.get(policy_var) or "true").strip().lower()

        if policy_mode in {"false", "0", "no", "deny"}:
            clean_reason = reason.replace("[SECRET] ", "")
            emit("deny", f"Disabled in .env ({policy_var}=false): {clean_reason}")
            return

        if policy_mode == "auto":
            emit("allow")
            return

        # Interactive YES/NO prompt via iMessage!
        approved, app_reason = request_admin_imessage_approval(category, name, args, reason)
        if approved:
            emit("allow")
        else:
            emit("deny", app_reason)

    except Exception as exc:
        emit("deny", f"Fail-closed security hook error: {type(exc).__name__}")


if __name__ == "__main__":
    main()
