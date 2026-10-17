#!/usr/bin/env python3
"""tg-shield — mass-report-attack defense for Telegram groups.

Public Telegram groups get destroyed when attackers join and post illegal
material, triggering Telegram's automated bans. tg-shield defends with:

  * behavior-based trust scoring (SQLite, no external services),
  * automatic media probation for new/untrusted members,
  * one-tap lockdown (/lockdown) that kills all media but keeps text chat alive.

Configuration (environment variables):
  TG_SHIELD_TOKEN      Bot token from @BotFather (required).
  TG_SHIELD_THRESHOLD  Trust score (0-100) needed to post media (default 50).
  TG_SHIELD_DB         SQLite database path (default tg_shield.db).
"""

import asyncio
import logging
import os
import sqlite3
import threading
import time

from telegram import Update
from telegram.constants import ChatMemberStatus
from telegram.error import BadRequest, Forbidden
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

log = logging.getLogger("tg-shield")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_THRESHOLD = int(os.environ.get("TG_SHIELD_THRESHOLD", "50"))
DB_PATH = os.environ.get("TG_SHIELD_DB", "tg_shield.db")
ADMIN_CACHE_TTL = 300  # seconds to cache getChatMember results

# ChatPermissions fields that count as "media" for lockdown purposes.
MEDIA_FIELDS = [
    "can_send_photos",
    "can_send_videos",
    "can_send_documents",
    "can_send_audios",
    "can_send_voice_notes",
    "can_send_video_notes",
    "can_send_other_messages",
]

MEDIA_FILTER = (
    filters.PHOTO
    | filters.VIDEO
    | filters.Document.ALL
    | filters.AUDIO
    | filters.VOICE
    | filters.VIDEO_NOTE
    | filters.ANIMATION
    | filters.Sticker.ALL
)

PROBATION_NOTE = (
    "Media from new members is held until you've been active a while \u2014 "
    "text chat is unaffected."
)

# ---------------------------------------------------------------------------
# Pure logic (no Telegram API calls — easy to unit test)
# ---------------------------------------------------------------------------


def trust_score(days_since_first_seen: int, message_count: int) -> int:
    """Behavior-based trust score, 0-100.

    score = min(100, 2 * days_since_first_seen + message_count)
    """
    return min(100, 2 * max(0, days_since_first_seen) + max(0, message_count))


def is_trusted_user(trusted_flag: int, score: int, threshold: int) -> bool:
    """True if the user is manually allowlisted or their score clears the bar."""
    return bool(trusted_flag) or score >= threshold


def lockdown_call():
    """Full set_chat_permissions call spec for /lockdown.

    Returns (permissions_kwargs, use_independent_chat_permissions):
    text stays on, every media field explicitly off.
    """
    perms = {"can_send_messages": True}
    for field in MEDIA_FIELDS:
        perms[field] = False
    return perms, True


def unlock_permissions_kwargs() -> dict:
    """ChatPermissions kwargs for /unlock: restore normal member messaging."""
    perms = {"can_send_messages": True}
    for field in MEDIA_FIELDS:
        perms[field] = True
    # Restore the message-adjacent toggles too; leave invite/pin/info rights
    # untouched so /unlock never overrides a group's deliberate restrictions.
    perms["can_add_web_page_previews"] = True
    perms["can_send_polls"] = True
    return perms


# ---------------------------------------------------------------------------
# Storage (SQLite)
# ---------------------------------------------------------------------------

_db_lock = threading.Lock()


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id     INTEGER NOT NULL,
            chat_id     INTEGER NOT NULL,
            username    TEXT,
            first_seen  REAL NOT NULL,
            msg_count   INTEGER NOT NULL DEFAULT 0,
            trusted     INTEGER NOT NULL DEFAULT 0,
            violations  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (user_id, chat_id)
        );
        CREATE TABLE IF NOT EXISTS settings (
            chat_id    INTEGER PRIMARY KEY,
            threshold  INTEGER NOT NULL,
            lockdown   INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS deletions (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id  INTEGER NOT NULL,
            user_id  INTEGER NOT NULL,
            ts       REAL NOT NULL
        );
        """
    )
    conn.commit()


def record_message(
    conn: sqlite3.Connection,
    chat_id: int,
    user_id: int,
    username: str | None,
    counted: bool = True,
) -> None:
    """Register activity. counted=False for messages we deleted (no trust gain)."""
    now = time.time()
    with _db_lock:
        row = conn.execute(
            "SELECT first_seen FROM users WHERE user_id=? AND chat_id=?",
            (user_id, chat_id),
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO users (user_id, chat_id, username, first_seen,"
                " msg_count) VALUES (?, ?, ?, ?, ?)",
                (user_id, chat_id, username, now, 1 if counted else 0),
            )
        else:
            conn.execute(
                "UPDATE users SET username=?, msg_count=msg_count+? WHERE"
                " user_id=? AND chat_id=?",
                (username, 1 if counted else 0, user_id, chat_id),
            )
        conn.commit()


def get_user(conn: sqlite3.Connection, chat_id: int, user_id: int):
    with _db_lock:
        return conn.execute(
            "SELECT user_id, chat_id, username, first_seen, msg_count, trusted,"
            " violations FROM users WHERE user_id=? AND chat_id=?",
            (user_id, chat_id),
        ).fetchone()


def find_user_by_username(conn: sqlite3.Connection, chat_id: int, username: str):
    username = username.lstrip("@").lower()
    with _db_lock:
        return conn.execute(
            "SELECT user_id, chat_id, username, first_seen, msg_count, trusted,"
            " violations FROM users WHERE chat_id=? AND lower(username)=?",
            (chat_id, username),
        ).fetchone()


def set_trusted(conn: sqlite3.Connection, chat_id: int, user_id: int, trusted: bool) -> None:
    now = time.time()
    with _db_lock:
        conn.execute(
            "INSERT INTO users (user_id, chat_id, first_seen, trusted)"
            " VALUES (?, ?, ?, ?) ON CONFLICT(user_id, chat_id)"
            " DO UPDATE SET trusted=excluded.trusted",
            (user_id, chat_id, now, 1 if trusted else 0),
        )
        conn.commit()


def add_violation(conn: sqlite3.Connection, chat_id: int, user_id: int) -> None:
    with _db_lock:
        conn.execute(
            "UPDATE users SET violations=violations+1 WHERE user_id=? AND chat_id=?",
            (user_id, chat_id),
        )
        conn.execute(
            "INSERT INTO deletions (chat_id, user_id, ts) VALUES (?, ?, ?)",
            (chat_id, user_id, time.time()),
        )
        conn.commit()


def get_settings(conn: sqlite3.Connection, chat_id: int, default_threshold: int):
    with _db_lock:
        row = conn.execute(
            "SELECT threshold, lockdown FROM settings WHERE chat_id=?", (chat_id,)
        ).fetchone()
    if row is None:
        return default_threshold, False
    return row[0], bool(row[1])


def set_settings(
    conn: sqlite3.Connection,
    chat_id: int,
    threshold: int | None = None,
    lockdown: bool | None = None,
) -> None:
    with _db_lock:
        row = conn.execute(
            "SELECT threshold, lockdown FROM settings WHERE chat_id=?", (chat_id,)
        ).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO settings (chat_id, threshold, lockdown) VALUES (?, ?, ?)",
                (
                    chat_id,
                    threshold if threshold is not None else DEFAULT_THRESHOLD,
                    1 if lockdown else 0,
                ),
            )
        else:
            new_threshold = threshold if threshold is not None else row[0]
            new_lockdown = (1 if lockdown else 0) if lockdown is not None else row[1]
            conn.execute(
                "UPDATE settings SET threshold=?, lockdown=? WHERE chat_id=?",
                (new_threshold, new_lockdown, chat_id),
            )
        conn.commit()


def count_users(conn: sqlite3.Connection, chat_id: int) -> int:
    with _db_lock:
        return conn.execute(
            "SELECT COUNT(*) FROM users WHERE chat_id=?", (chat_id,)
        ).fetchone()[0]


def count_recent_deletions(conn: sqlite3.Connection, chat_id: int, hours: int = 24) -> int:
    with _db_lock:
        return conn.execute(
            "SELECT COUNT(*) FROM deletions WHERE chat_id=? AND ts>?",
            (chat_id, time.time() - hours * 3600),
        ).fetchone()[0]


# ---------------------------------------------------------------------------
# Telegram helpers
# ---------------------------------------------------------------------------

_admin_cache: dict = {}  # (chat_id, user_id) -> (is_admin, timestamp)


async def is_admin(context: ContextTypes.DEFAULT_TYPE, chat_id: int, user_id: int) -> bool:
    """Admins/owner are always exempt. Results cached for 5 minutes."""
    key = (chat_id, user_id)
    now = time.time()
    cached = _admin_cache.get(key)
    if cached and now - cached[1] < ADMIN_CACHE_TTL:
        return cached[0]
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        result = member.status in (
            ChatMemberStatus.ADMINISTRATOR,
            ChatMemberStatus.OWNER,
        )
    except (BadRequest, Forbidden):
        result = False
    _admin_cache[key] = (result, now)
    return result


async def delete_later(message, delay: int = 60) -> None:
    await asyncio.sleep(delay)
    try:
        await message.delete()
    except Exception:
        pass  # note already gone or rights changed; nothing to do


def _is_group(chat) -> bool:
    return chat is not None and chat.type in ("group", "supergroup")


async def _require_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Reply politely if the caller may not use admin commands. Returns True if OK."""
    chat = update.effective_chat
    user = update.effective_user
    message = update.effective_message
    if not _is_group(chat):
        await message.reply_text(
            "Add me to your group first \u2014 these commands only work there."
        )
        return False
    if not await is_admin(context, chat.id, user.id):
        await message.reply_text("Sorry \u2014 that command is for group admins only.")
        return False
    return True


async def _resolve_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Resolve the /trust|/untrust target: reply first, then @username via DB.

    Returns (user_id, display_name) or (None, error_message).
    """
    message = update.effective_message
    chat = update.effective_chat
    conn = context.bot_data["db"]

    # 1. Reply to the user's message — the reliable path.
    if message.reply_to_message and message.reply_to_message.from_user:
        target = message.reply_to_message.from_user
        if target.is_bot:
            return None, "That's a bot \u2014 nothing to allowlist."
        return target.id, target.full_name

    # 2. @username — resolve through users we've actually seen chat.
    if context.args:
        row = find_user_by_username(conn, chat.id, context.args[0])
        if row:
            return row[0], "@" + (row[2] or context.args[0].lstrip("@"))
        return (
            None,
            f"I haven't seen {context.args[0]} chat here yet \u2014 reply to one of"
            " their messages instead.",
        )

    return None, "Reply to the user's message, or use /trust @username."


# ---------------------------------------------------------------------------
# Message handlers
# ---------------------------------------------------------------------------


async def on_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Count ordinary text messages toward trust. Text is never deleted."""
    chat = update.effective_chat
    user = update.effective_user
    message = update.effective_message
    if not _is_group(chat) or user is None or user.is_bot or message is None:
        return
    record_message(context.bot_data["db"], chat.id, user.id, user.username, counted=True)


async def on_media(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Media probation: delete media from non-exempt, untrusted users."""
    chat = update.effective_chat
    user = update.effective_user
    message = update.effective_message
    if not _is_group(chat) or user is None or user.is_bot or message is None:
        return
    # Anonymous admin channel posts ride on sender_chat — never touch those.
    if message.sender_chat is not None:
        return

    conn = context.bot_data["db"]
    threshold = context.bot_data["threshold"]

    if await is_admin(context, chat.id, user.id):
        record_message(conn, chat.id, user.id, user.username, counted=True)
        return

    row = get_user(conn, chat.id, user.id)
    if row is None:
        days, msg_count, trusted_flag = 0, 0, 0
    else:
        days = int((time.time() - row[3]) // 86400)
        msg_count, trusted_flag = row[4], row[5]
    score = trust_score(days, msg_count)

    if is_trusted_user(trusted_flag, score, threshold):
        record_message(conn, chat.id, user.id, user.username, counted=True)
        return

    # Not trusted: delete first, ask questions never. Fail LOUD if we can't.
    try:
        await message.delete()
    except (BadRequest, Forbidden):
        await chat.send_message(
            "\u26a0\ufe0f tg-shield needs the 'Delete messages' admin right to protect"
            " this group. Please promote me to admin and I'll start working."
        )
        log.warning("deleteMessage failed in chat %s — missing admin rights", chat.id)
        return

    # Deleted media earns no trust.
    record_message(conn, chat.id, user.id, user.username, counted=False)
    add_violation(conn, chat.id, user.id)
    log.info("deleted media from user %s in chat %s (score %d)", user.id, chat.id, score)

    note = await chat.send_message(PROBATION_NOTE)
    asyncio.create_task(delete_later(note, 60))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat = update.effective_chat
    if _is_group(chat):
        await update.effective_message.reply_text(
            "\U0001f6e1\ufe0f tg-shield is watching this group. Media from new members"
            " is held until they've been active a while."
        )
        return
    await update.effective_message.reply_text(
        "\U0001f6e1\ufe0f I'm tg-shield \u2014 mass-report-attack defense for Telegram"
        " groups.\n\nSetup checklist:\n"
        "1. Add me to your group.\n"
        "2. Promote me to admin with these rights:\n"
        "   \u2705 Delete messages\n"
        "   \u2705 Restrict members (needed for /lockdown)\n"
        "3. Done \u2014 media probation starts automatically.\n\n"
        "Run /help inside your group for the command list."
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.effective_message.reply_text(
        "\U0001f6e1\ufe0f tg-shield commands (admins only, except /start):\n\n"
        "/trust \u2014 allowlist a user (reply to their message, or /trust @username)\n"
        "/untrust \u2014 remove a user from the allowlist\n"
        "/lockdown \u2014 block ALL media group-wide, text keeps working\n"
        "/unlock \u2014 restore normal media permissions\n"
        "/status \u2014 shield state, tracked users, deletions in 24h, threshold\n"
        "/setthreshold N \u2014 trust score (0\u2013100) needed to post media"
    )


async def cmd_trust(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    target_id, result = await _resolve_target(update, context)
    if target_id is None:
        await update.effective_message.reply_text(result)
        return
    set_trusted(context.bot_data["db"], update.effective_chat.id, target_id, True)
    await update.effective_message.reply_text(f"\u2705 {result} is now trusted.")


async def cmd_untrust(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    target_id, result = await _resolve_target(update, context)
    if target_id is None:
        await update.effective_message.reply_text(result)
        return
    set_trusted(context.bot_data["db"], update.effective_chat.id, target_id, False)
    await update.effective_message.reply_text(
        f"{result} removed from the allowlist \u2014 back to trust scoring."
    )


async def cmd_lockdown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    perms, independent = lockdown_call()
    try:
        await context.bot.set_chat_permissions(
            chat.id,
            ChatPermissions(**perms),
            use_independent_chat_permissions=independent,
        )
    except (BadRequest, Forbidden):
        await update.effective_message.reply_text(
            "\u26a0\ufe0f tg-shield needs the 'Restrict members' admin right for"
            " /lockdown. Please grant it and try again."
        )
        log.warning("setChatPermissions failed in chat %s — missing rights", chat.id)
        return
    set_settings(context.bot_data["db"], chat.id, lockdown=True)
    notice = await chat.send_message(
        "\U0001f512 Lockdown enabled: text chat works, all media is blocked for now."
        " Admins can /unlock when the threat passes."
    )
    try:
        await notice.pin(disable_notification=True)
    except (BadRequest, Forbidden):
        pass  # pin rights optional — skip silently
    log.info("lockdown enabled in chat %s", chat.id)


async def cmd_unlock(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    try:
        await context.bot.set_chat_permissions(
            chat.id,
            **unlock_permissions_kwargs(),
            use_independent_chat_permissions=True,
        )
    except (BadRequest, Forbidden):
        await update.effective_message.reply_text(
            "\u26a0\ufe0f tg-shield needs the 'Restrict members' admin right for"
            " /unlock. Please grant it and try again."
        )
        return
    set_settings(context.bot_data["db"], chat.id, lockdown=False)
    await update.effective_message.reply_text(
        "\U0001f513 Lockdown lifted \u2014 normal media permissions restored."
    )
    log.info("lockdown lifted in chat %s", chat.id)


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    chat = update.effective_chat
    conn = context.bot_data["db"]
    threshold, lockdown = get_settings(conn, chat.id, context.bot_data["threshold"])
    users = count_users(conn, chat.id)
    deletions = count_recent_deletions(conn, chat.id, 24)
    await update.effective_message.reply_text(
        "\U0001f6e1\ufe0f tg-shield status\n\n"
        f"Lockdown: {'\U0001f512 ON' if lockdown else '\u2705 off'}\n"
        f"Trust threshold: {threshold}\n"
        f"Users tracked: {users}\n"
        f"Media deleted (24h): {deletions}"
    )


async def cmd_setthreshold(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _require_admin(update, context):
        return
    if not context.args:
        await update.effective_message.reply_text(
            f"Usage: /setthreshold N (0\u2013100). Current:"
            f" {context.bot_data['threshold']}"
        )
        return
    try:
        value = int(context.args[0])
    except ValueError:
        value = -1
    if not 0 <= value <= 100:
        await update.effective_message.reply_text(
            "Threshold must be a number between 0 and 100."
        )
        return
    context.bot_data["threshold"] = value
    set_settings(context.bot_data["db"], update.effective_chat.id, threshold=value)
    await update.effective_message.reply_text(
        f"Trust threshold set to {value}. Users below it can't post media."
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def build_application(token: str, db_path: str, default_threshold: int):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    init_db(conn)
    app = ApplicationBuilder().token(token).build()
    app.bot_data["db"] = conn
    app.bot_data["threshold"] = default_threshold

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("trust", cmd_trust))
    app.add_handler(CommandHandler("untrust", cmd_untrust))
    app.add_handler(CommandHandler("lockdown", cmd_lockdown))
    app.add_handler(CommandHandler("unlock", cmd_unlock))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("setthreshold", cmd_setthreshold))
    # Media probation must run before the generic text counter sees the message.
    app.add_handler(MessageHandler(MEDIA_FILTER, on_media), group=0)
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND, on_text), group=1
    )
    return app


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
    )
    token = os.environ.get("TG_SHIELD_TOKEN")
    if not token:
        raise SystemExit(
            "TG_SHIELD_TOKEN is not set. Create a bot with @BotFather,"
            " then run: TG_SHIELD_TOKEN=<token> python bot.py"
        )
    app = build_application(token, DB_PATH, DEFAULT_THRESHOLD)
    log.info(
        "tg-shield starting (db=%s, threshold=%d)", DB_PATH, DEFAULT_THRESHOLD
    )
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
