# iMessage <-> Antigravity CLI (agy) Bridge

A lightweight native macOS Objective-C daemon that watches `~/Library/Messages/chat.db-wal` and `chat.db` via kernel `kqueue` (`EVFILT_VNODE`) events for incoming iMessages from whitelisted senders (or Note-to-Self threads), dispatches queries to Google Antigravity CLI (`agy`) with tiered sandboxing and interactive `YES / NO` iMessage approvals, and replies directly in the iMessage thread.

## Configuration (`.env`)

Runtime configuration and isolated workspaces live in `~/.config/imessage-agy-bridge/`. Configuration is kept in `.env` (excluded from version control via `.gitignore` and hot-reloaded automatically).

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your Apple ID / phone number:
   ```env
   ADMIN_HANDLES="admin@example.com,+15550001111"
   ALLOWED_SENDERS="admin@example.com,+15550001111,secondary@example.com,+15550002222"
   TRIGGER_PREFIXES="@agy,!agy"
   REQUIRE_PREFIX=true
   DB_PATH="~/Library/Messages/chat.db"
   AGY_BINARY="~/.local/bin/agy"
   CONVERSATION_ID="imessage-agy-main"
   POLL_INTERVAL_SECONDS=0
   MAX_REPLY_LENGTH=1800
   SEND_ACK=true
   ```

## Requirements & Permissions

1. **Messages.app**: Signed into your Apple ID.
2. **Antigravity CLI**: Installed and signed in at `~/.local/bin/agy`.
3. **Full Disk Access (FDA)**:
   - System Settings $\rightarrow$ Privacy & Security $\rightarrow$ Full Disk Access
   - Add `~/.local/bin/imessage-agy-daemon`.
4. **Automation**:
   - System Settings $\rightarrow$ Privacy & Security $\rightarrow$ Automation
   - Allow `imessage-agy-daemon` to control `Messages.app`.

## Building & Deploying

```bash
./build.sh
```

## Syncing Config / Hooks (No Binary Rebuild or FDA Toggle)

```bash
./sync_workspaces.sh
```

To view logs:
```bash
tail -f ~/.config/imessage-agy-bridge/bridge.err.log
```
