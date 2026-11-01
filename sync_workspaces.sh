#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_DIR="${HOME}/.config/imessage-agy-bridge"
JAIL_DST="${RUNTIME_DIR}/workspaces/jail"
ADMIN_DST="${RUNTIME_DIR}/workspaces/admin"
LEGACY_JAIL_DST="${HOME}/.local/share/imessage-agy-jail"
LEGACY_ADMIN_DST="${HOME}/.local/share/imessage-agy-admin"

mkdir -p "${RUNTIME_DIR}/approvals" "${RUNTIME_DIR}/workspaces"
chmod 700 "${RUNTIME_DIR}" "${RUNTIME_DIR}/approvals"

# Migrate or sync .env and bridge_state.json into ~/.config/imessage-agy-bridge
if [[ -f "${SCRIPT_DIR}/.env" ]]; then
    cp -f "${SCRIPT_DIR}/.env" "${RUNTIME_DIR}/.env"
    chmod 600 "${RUNTIME_DIR}/.env"
elif [[ ! -f "${RUNTIME_DIR}/.env" && -f "${SCRIPT_DIR}/.env.example" ]]; then
    cp "${SCRIPT_DIR}/.env.example" "${RUNTIME_DIR}/.env"
    chmod 600 "${RUNTIME_DIR}/.env"
fi

if [[ ! -f "${RUNTIME_DIR}/bridge_state.json" && -f "${SCRIPT_DIR}/bridge_state.json" ]]; then
    cp -p "${SCRIPT_DIR}/bridge_state.json" "${RUNTIME_DIR}/bridge_state.json"
    chmod 600 "${RUNTIME_DIR}/bridge_state.json"
fi

deploy_workspace() {
    local src_dir="$1"
    local dst_dir="$2"
    local settings_src="$3"
    local settings_dst="$4"

    if [[ -d "${dst_dir}" ]]; then
        chmod -R u+w "${dst_dir}" 2>/dev/null || true
        rm -rf "${dst_dir}"
    fi

    mkdir -p "${dst_dir}/.agents/scripts" "${dst_dir}/.agents/skills/imessage-formatter"
    cp "${src_dir}/GEMINI.md" "${dst_dir}/GEMINI.md"
    cp "${src_dir}/AGENTS.md" "${dst_dir}/AGENTS.md"
    cp "${src_dir}/.agents/hooks.json" "${dst_dir}/.agents/hooks.json"
    cp "${SCRIPT_DIR}/jail/.agents/scripts/pre_tool_guard.py" "${dst_dir}/.agents/scripts/pre_tool_guard.py"
    cp "${SCRIPT_DIR}/jail/.agents/skills/imessage-formatter/SKILL.md" "${dst_dir}/.agents/skills/imessage-formatter/SKILL.md"
    sed "s|__HOME__|${HOME}|g" "${settings_src}" > "${dst_dir}/${settings_dst}"

    # Lock files read-only so agent turns cannot tamper with their own rules or hooks
    chmod 444 "${dst_dir}/GEMINI.md" "${dst_dir}/AGENTS.md" "${dst_dir}/.agents/hooks.json" "${dst_dir}/.agents/skills/imessage-formatter/SKILL.md" "${dst_dir}/${settings_dst}"
    chmod 555 "${dst_dir}/.agents/scripts/pre_tool_guard.py"
    chmod 555 "${dst_dir}/.agents/scripts" "${dst_dir}/.agents/skills/imessage-formatter" "${dst_dir}/.agents/skills" "${dst_dir}/.agents" "${dst_dir}"
}

echo "Syncing isolated AGY workspaces into ${RUNTIME_DIR} (no binary rebuild)..."
deploy_workspace "${SCRIPT_DIR}/jail" "${JAIL_DST}" "${SCRIPT_DIR}/bridge-settings.json" "bridge-settings.json"
deploy_workspace "${SCRIPT_DIR}/admin_workspace" "${ADMIN_DST}" "${SCRIPT_DIR}/bridge-settings-admin.json" "bridge-settings-admin.json"

# Clean up legacy ~/.local/share/imessage-agy-* directories if present
for legacy_dir in "${LEGACY_JAIL_DST}" "${LEGACY_ADMIN_DST}"; do
    if [[ -d "${legacy_dir}" ]]; then
        chmod -R u+w "${legacy_dir}" 2>/dev/null || true
        rm -rf "${legacy_dir}"
    fi
done

# Render launchd plist into ~/Library/LaunchAgents pointing WorkingDirectory to ~/.config/imessage-agy-bridge
PLIST_TEMPLATE="${SCRIPT_DIR}/launchd.plist.template"
if [[ -d "${HOME}/Library/LaunchAgents" && -f "${PLIST_TEMPLATE}" ]]; then
    SERVICE_LABEL="${SERVICE_LABEL:-com.${USER}.imessage-agy-bridge}"
    sed -e "s|__SERVICE_LABEL__|${SERVICE_LABEL}|g" \
        -e "s|__HOME__|${HOME}|g" \
        -e "s|__PROJECT_DIR__|${RUNTIME_DIR}|g" \
        "${PLIST_TEMPLATE}" \
        > "${HOME}/Library/LaunchAgents/${SERVICE_LABEL}.plist"
fi

# Enforce 0600 permissions on local secrets/logs/state
for dir in "${RUNTIME_DIR}" "${SCRIPT_DIR}"; do
    for secret_file in ".env" "bridge_state.json" "bridge.err.log" "bridge.log"; do
        if [[ -f "${dir}/${secret_file}" ]]; then
            chmod 600 "${dir}/${secret_file}"
        fi
    done
done
rm -f "${SCRIPT_DIR}/config.json"

echo "✅ Runtime directory and workspaces synced:"
echo "  Config & State:  ${RUNTIME_DIR}"
echo "  Restricted Jail: ${JAIL_DST}"
echo "  Admin 1:1 Dir:   ${ADMIN_DST}"
