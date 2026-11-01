# iMessage <-> Antigravity CLI (agy) Bridge

A lightweight daemon running on macOS that polls `~/Library/Messages/chat.db` for incoming iMessages from whitelisted senders (or Note-to-Self threads), dispatches queries to Google Antigravity CLI (`agy`), and replies with the generated response directly in the iMessage thread.

## Configuration (`.env`)

Configuration is kept in a local `.env` file that is excluded from version control (`.gitignore`).

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your Apple ID / phone number:
   ```env
   ALLOWED_SENDERS="your_apple_id@example.com,+15125550100"
   TRIGGER_PREFIXES="!agy ,!agy,!"
   REQUIRE_PREFIX=true
   DB_PATH="~/Library/Messages/chat.db"
   AGY_BINARY="~/.local/bin/agy"
   CONVERSATION_ID="imessage-agy-main"
   POLL_INTERVAL_SECONDS=2.0
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

## Building & Running Manually

```bash
./build.sh
~/.local/bin/imessage-agy-daemon
```

## Syncing Config / Hooks (No Binary Rebuild or FDA Toggle)

```bash
./sync_workspaces.sh
```

To view logs:
```bash
tail -f ~/Code/imessage-agy-bridge/bridge.err.log
```
