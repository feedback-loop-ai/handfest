#!/usr/bin/env bash
# Declarative installer for Handfest skills, hooks, and localized MCP/hook templates.
# Zero external dependencies beyond POSIX shell + coreutils (cp/install/sed/mkdir/chmod).

set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: plugins/install.sh [--handfest-home <dir>] [--help]

Installs:
  - /handfest SKILL.md into:
      ~/.gemini/config/skills/handfest/SKILL.md  (Antigravity / agy)
      ~/.claude/skills/handfest/SKILL.md         (Claude Code)
      ~/.codex/skills/handfest/SKILL.md          (Codex)
  - pre-tool-use.sh (0755) into ${HANDFEST_HOME}/hooks/pre-tool-use.sh
  - policy-map.json into ${HANDFEST_HOME}/policy-map.json (only if absent)
  - localized MCP & hook templates into ${HANDFEST_HOME}/templates/

Environment:
  HANDFEST_HOME   Target config directory (default: ${HOME}/.handfest)
USAGE
}

HANDFEST_HOME="${HANDFEST_HOME:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --handfest-home)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "error: --handfest-home requires a non-empty directory path" >&2
        exit 2
      fi
      HANDFEST_HOME="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${HOME:-}" ]]; then
  echo "error: HOME must be set" >&2
  exit 1
fi

if [[ -z "$HANDFEST_HOME" ]]; then
  HANDFEST_HOME="${HOME}/.handfest"
fi

case "$HANDFEST_HOME" in
  *$'\n'*|*$'\r'*|*$'\t'*)
    echo "error: HANDFEST_HOME must not contain control characters" >&2
    exit 1
    ;;
esac

if [[ "$HANDFEST_HOME" != /* ]]; then
  HANDFEST_HOME="$(pwd)/${HANDFEST_HOME}"
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Escape a string for JSON/TOML double-quoted string literals (\ -> \\, " -> \").
escape_json_toml_string() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '%s' "$s"
}

# Shell single-quote a command path (' -> '\'' ), then JSON-escape for claude-settings.json.
escape_shell_single_quoted() {
  local s="$1"
  local sq="'\\''"
  printf "'%s'" "${s//\'/$sq}"
}

# Escape &, \, and | for sed replacement strings.
escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

# Escape a string for systemd ExecStart double-quoted arguments (\ -> \\, " -> \", % -> %%, $ -> $$).
escape_systemd_string() {
  local s="$1"
  local dollar='$'
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//%/%%}"
  s="${s//"$dollar"/"$dollar$dollar"}"
  printf '%s' "$s"
}

HANDFEST_HOME_JSON_ESC="$(escape_sed_replacement "$(escape_json_toml_string "$HANDFEST_HOME")")"
HANDFEST_HOME_SYSTEMD_ESC="$(escape_sed_replacement "$(escape_systemd_string "$HANDFEST_HOME")")"
HOOK_CMD_RAW="$(escape_shell_single_quoted "${HANDFEST_HOME}/hooks/pre-tool-use.sh")"
HOOK_CMD_JSON_ESC="$(escape_sed_replacement "$(escape_json_toml_string "$HOOK_CMD_RAW")")"

install_localized_template() {
  local src="$1"
  local dst="$2"
  sed "s|/path/to/handfest-config|${HANDFEST_HOME_JSON_ESC}|g" "$src" >"${dst}.tmp"
  chmod 0644 "${dst}.tmp"
  mv -f "${dst}.tmp" "$dst"
}

install_systemd_template() {
  local src="$1"
  local dst="$2"
  sed "s|/path/to/handfest-config|${HANDFEST_HOME_SYSTEMD_ESC}|g" "$src" >"${dst}.tmp"
  chmod 0644 "${dst}.tmp"
  mv -f "${dst}.tmp" "$dst"
}

install_claude_settings_template() {
  local src="$1"
  local dst="$2"
  sed "s|/path/to/handfest-config/hooks/pre-tool-use.sh|${HOOK_CMD_JSON_ESC}|g" "$src" >"${dst}.tmp"
  chmod 0644 "${dst}.tmp"
  mv -f "${dst}.tmp" "$dst"
}

mkdir -p "$HANDFEST_HOME"
chmod 0700 "$HANDFEST_HOME"
mkdir -p \
  "${HANDFEST_HOME}/mandates" \
  "${HANDFEST_HOME}/state" \
  "${HANDFEST_HOME}/hooks" \
  "${HANDFEST_HOME}/templates"
chmod 0700 "${HANDFEST_HOME}/state"

# 1. Install /handfest SKILL.md for Antigravity (agy), Claude Code, and Codex.
mkdir -p \
  "${HOME}/.gemini/config/skills/handfest" \
  "${HOME}/.claude/skills/handfest" \
  "${HOME}/.codex/skills/handfest"

install -m 0644 "${SCRIPT_DIR}/agy/SKILL.md" "${HOME}/.gemini/config/skills/handfest/SKILL.md"
install -m 0644 "${SCRIPT_DIR}/claude-code/SKILL.md" "${HOME}/.claude/skills/handfest/SKILL.md"
install -m 0644 "${SCRIPT_DIR}/agy/SKILL.md" "${HOME}/.codex/skills/handfest/SKILL.md"

# 2. Install PreToolUse hook (0755) and preserve any existing policy-map.json.
install -m 0755 "${SCRIPT_DIR}/claude-code/hooks/pre-tool-use.sh" "${HANDFEST_HOME}/hooks/pre-tool-use.sh"

if [[ ! -e "${HANDFEST_HOME}/policy-map.json" ]]; then
  install -m 0644 "${SCRIPT_DIR}/policy-map.example.json" "${HANDFEST_HOME}/policy-map.json"
fi
install -m 0644 "${SCRIPT_DIR}/policy-map.example.json" "${HANDFEST_HOME}/templates/policy-map.example.json"

# 3. Install localized MCP and hook configuration templates.
install_localized_template "${SCRIPT_DIR}/agy/mcp.example.json" "${HANDFEST_HOME}/templates/agy-mcp.json"
install_localized_template "${SCRIPT_DIR}/claude-code/mcp.example.json" "${HANDFEST_HOME}/templates/claude-mcp.json"
install_claude_settings_template "${SCRIPT_DIR}/claude-code/settings.example.json" "${HANDFEST_HOME}/templates/claude-settings.json"
install_localized_template "${SCRIPT_DIR}/codex/config.example.toml" "${HANDFEST_HOME}/templates/codex-config.toml"
install_localized_template "${SCRIPT_DIR}/dsh/mcp.example.json" "${HANDFEST_HOME}/templates/dsh-mcp.json"
install_systemd_template "${SCRIPT_DIR}/systemd/handfest-approver.service.example" "${HANDFEST_HOME}/templates/handfest-approver.service"

cat <<SUMMARY
Installed Handfest skills, hook, and localized templates:
  HANDFEST_HOME: ${HANDFEST_HOME}
  Skills:
    - ${HOME}/.gemini/config/skills/handfest/SKILL.md
    - ${HOME}/.claude/skills/handfest/SKILL.md
    - ${HOME}/.codex/skills/handfest/SKILL.md
  Hook:
    - ${HANDFEST_HOME}/hooks/pre-tool-use.sh
  Templates:
    - ${HANDFEST_HOME}/templates/agy-mcp.json
    - ${HANDFEST_HOME}/templates/claude-mcp.json
    - ${HANDFEST_HOME}/templates/claude-settings.json
    - ${HANDFEST_HOME}/templates/codex-config.toml
    - ${HANDFEST_HOME}/templates/dsh-mcp.json
    - ${HANDFEST_HOME}/templates/policy-map.example.json
    - ${HANDFEST_HOME}/templates/handfest-approver.service

Next step (out-of-band in your human terminal):
  handfest init --dir "${HANDFEST_HOME}" --principal-name "<your-name>" --ssh-key ~/.ssh/id_ed25519_sk.pub

Optional (background approver daemon via systemd --user):
  # Match --key / --ssh-key / --gpg-key / --fido2-cred / --piv-pubkey in handfest-approver.service
  # to the signer backend chosen in 'handfest init' above.
  mkdir -p ~/.config/systemd/user && cp "${HANDFEST_HOME}/templates/handfest-approver.service" ~/.config/systemd/user/
  systemctl --user daemon-reload && systemctl --user enable --now handfest-approver.service
SUMMARY
