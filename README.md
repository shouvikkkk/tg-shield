# tg-shield 🛡️

Mass-report-attack defense for Telegram groups: media probation, behavior-based trust scoring, one-tap lockdown.

## The problem

In March 2026, a group admin shared a first-hand account of his 150-member Telegram community being **banned overnight**: attackers joined the public group and flooded it with illegal material, and Telegram's automated moderation killed the entire group before any human could react. The only defense he found was hand-rolling a custom bot that deleted media from inactive users — in his words, *"a tedious task that is not within the reach of every group administrator."*

**tg-shield packages exactly that defense** so any group admin can deploy it in minutes: new and untrusted members simply cannot post media until they've earned trust, and one command freezes all media group-wide the moment an attack starts.

## What tg-shield does

- **Built for the mass-report scenario** — not generic spam filtering: the whole design assumes the attacker is already inside the group and the clock is ticking.
- **Behavior-based trust, no CAPTCHAs** — every member earns a score from account age × activity; media rights unlock automatically. Attackers burning fresh accounts never qualify.
- **Delete-only probation** — media from untrusted members is deleted instantly, with a short self-deleting note. Text chat is never touched, so real newcomers aren't punished.
- **One-tap lockdown** — `/lockdown` blocks all media group-wide while text keeps working; `/unlock` restores everything. No digging through Telegram's permission maze mid-attack.
- **Free and open source** — single Python file, SQLite, no servers, no paid APIs, MIT licensed.

## Requirements

- Python 3.10+
- A bot token from [@BotFather](https://t.me/BotFather)
- The bot must be a **group admin** with:
  - ✅ **Delete messages** (for media probation)
  - ✅ **Restrict members** (for `/lockdown` / `/unlock`)

If a right is missing, tg-shield fails **loud** — it tells the group exactly which right it needs instead of silently doing nothing.

## Setup

```bash
git clone https://github.com/shouvikkkk/tg-shield.git
cd tg-shield
pip install -r requirements.txt

export TG_SHIELD_TOKEN="your-bot-token-from-BotFather"
# optional:
export TG_SHIELD_THRESHOLD=50      # trust score needed to post media (0-100)
export TG_SHIELD_DB="tg_shield.db" # SQLite path

python bot.py
```

Then add the bot to your group and promote it to admin with the two rights above. Probation starts automatically — no further configuration needed.

## Commands

| Command | Who | What it does |
|---|---|---|
| `/start` | anyone (private chat) | Setup checklist for adding the bot to your group |
| `/help` | anyone | Command list |
| `/trust` | admins | Allowlist a user — reply to their message, or `/trust @username` |
| `/untrust` | admins | Remove a user from the allowlist |
| `/lockdown` | admins | Block **all** media group-wide; text keeps working |
| `/unlock` | admins | Restore normal media permissions |
| `/status` | admins | Lockdown state, users tracked, media deleted in 24h, threshold |
| `/setthreshold N` | admins | Trust score (0–100) required to post media |

Non-admins trying admin commands get a polite "admins only" reply.

## The trust formula

```
score = min(100, 2 × days_since_first_seen + message_count)
trusted = manually allowlisted  OR  score ≥ threshold (default 50)
```

Group admins and the owner are always exempt. Deleted media never counts toward trust, so flooding the group can't farm it. Examples:

| Member | Score | Can post media? |
|---|---|---|
| Joined today, 0 messages | 0 | ❌ |
| 14 days, 20 messages | 48 | ❌ (default threshold 50) |
| 25 days, 40 messages | 90 | ✅ |
| Manually allowlisted | — | ✅ always |

## How it differs

- **Shieldy** — verifies newcomers with CAPTCHAs at join time; tg-shield instead continuously scores behavior and restricts *media specifically*, the actual attack vector.
- **Rose** — a general-purpose group-management suite (warns, bans, filters, federations); tg-shield is a single-purpose tool built for one scenario: surviving a mass-report attack.
- **GroupHelp** — group management with antispam and welcome features; tg-shield's trust scoring, delete-only media probation, and one-tap media lockdown are purpose-built defenses the generalists don't offer.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Shouvik Maji.
