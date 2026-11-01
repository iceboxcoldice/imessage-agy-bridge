---
name: imessage-formatter
description: Formats responses specifically for Apple iMessage bubbles on iPhone screens. Enforces short lines, zero markdown tables, clean unicode bullet points, status emojis, and compact mobile layout.
---

# iMessage Response Formatter Skill

Use this skill whenever generating responses destined for iMessage, SMS, or mobile push notifications.

## 1. iPhone Bubble Display Constraints
- **Line Length**: Keep lines between 30 and 50 characters. Insert manual line breaks frequently.
- **Bubble Budget**: Aim for responses under 800 characters so the response fits into a single comfortable chat bubble.
- **Lock Screen Friendly**: Always place the direct answer or status in line 1 so the iOS lock screen push notification shows the key information immediately.

## 2. Formatting & Syntax Rules for Messages.app
- **Strictly NO Markdown Tables**: Never output markdown tables. Tables wrap horizontally and render illegibly in mobile chat bubbles.
- **Clean Unicode Over Heavy Markdown**:
  Because standard iMessage displays literal text:
  * Use `•` (bullet) instead of complex markdown lists.
  * Use simple status emojis for instant glanceability:
    🟢 `Up / Healthy`
    🔴 `Down / Error`
    🟡 `Degraded / Warning`
    📦 `Container / Service`
    💾 `Disk / Storage`
    ⚡ `CPU / Performance`
- **Lists & Key-Value Pairs**:
  Format items compactly:
  ```text
  🟢 immich-server: Up (3h)
  🟢 postgres: Up (3h)
  🟢 redis: Up (3h)
  ```

## 3. Communication Style
- **No Chatbot Filler**: Eliminate conversational preambles ("Sure, I can help with that", "Here is what I found", "Let me know if you need anything else").
- **Zero Sign-offs**: Do not append "Best regards" or signature text.
- **Action-Oriented**: Be direct, accurate, and concise.
