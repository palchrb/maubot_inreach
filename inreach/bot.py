import json
import re
import time
import hashlib
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote

from aiohttp import hdrs, ClientResponse
from aiohttp.web import Request, Response

from maubot import Plugin, PluginWebApp
from maubot.handlers import command, web, event
from mautrix.types import (
    RoomID,
    UserID,
    EventType,
    MessageEvent,
    MessageEventContent,
    PowerLevelStateEventContent,
)
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

from .migrations import upgrade_table


# ============ utils ============
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def now_ms() -> int:
    return int(time.time() * 1000)


def escape_md(s: str) -> str:
    return re.sub(r"([\\*_{}\\[\\]()#+\\-!`])", r"\\\1", str(s or ""))


def first_nonempty_line(s: str) -> Optional[str]:
    for ln in (s or "").splitlines():
        t = ln.strip()
        if t:
            return t
    return None


def parse_auth_token(req: Request, allow_query: bool) -> Optional[str]:
    h = req.headers.get(hdrs.AUTHORIZATION)
    if h and " " in h:
        typ, val = h.split(" ", 1)
        if typ.lower() == "bearer":
            return val
    if allow_query:
        tok = req.rel_url.query.get("token")
        if tok:
            return tok
    return None


# ============ config ============
class PluginConfig(BaseProxyConfig):
    def do_update(self, h: ConfigUpdateHelper) -> None:
        # Gmail Admin API (Apps Script backend)
        h.copy("admin_base_url")        # e.g. https://script.google.com/macros/s/<DEPLOYMENT_ID>/exec
        h.copy("admin_token")           # shared secret for ?admin_token=...

        # Gmail base address (we'll produce local+alias@domain)
        h.copy("gmail_base_address")    # e.g. bridge@gmail.com

        # Alias policy
        h.copy("alias_append_random")   # bool
        h.copy("alias_random_len")      # int

        # Command access / permissions
        h.copy("restrict_commands_to_local")
        h.copy("local_homeserver_domain")
        h.copy("pl_required")
        h.copy("adminlist")

        # Sending policy (defaults for fresh subs)
        h.copy("active_mode_default")   # True => 'active', False => 'manual'
        h.copy("max_reply_chars")       # e.g. 160
        h.copy("allow_non_admin_send")  # if false, only admins may send replies when relay_mode is off

        # Web handler
        h.copy("allow_query_token")     # accept ?token=... (normally False)


# ============ plugin ============
class InReachPlugin(Plugin):
    """Main plugin class."""
    config: PluginConfig
    webapp: PluginWebApp

    # -------- boilerplate --------
    @classmethod
    def get_config_class(cls):
        return PluginConfig

    @classmethod
    def get_db_upgrade_table(cls):
        return upgrade_table

    async def start(self) -> None:
        self.config.load_and_update()
        # sensible defaults
        if self.config.get("alias_append_random", None) is None:
            self.config["alias_append_random"] = True
        if not self.config.get("alias_random_len", None):
            self.config["alias_random_len"] = 8
        if not self.config.get("gmail_base_address", None):
            self.config["gmail_base_address"] = "email@example.com"
        if self.config.get("active_mode_default", None) is None:
            self.config["active_mode_default"] = False
        if not self.config.get("max_reply_chars", None):
            self.config["max_reply_chars"] = 160
        if self.config.get("allow_non_admin_send", None) is None:
            self.config["allow_non_admin_send"] = True
        if self.config.get("allow_query_token", None) is None:
            self.config["allow_query_token"] = False

        self._alias_re = re.compile(r"^[a-z0-9._-]{1,64}$")
        self.log.info("InReach plugin ready. Web base: %s", self.webapp_url)

    # -------- helpers: permissions --------
    def _user_domain(self, user: UserID) -> str:
        try:
            server = str(user).split(":", 1)[1]
        except Exception:
            return ""
        return server.split(":", 1)[0].lower()

    async def _owner_pl_if_v12(self, room_id: RoomID, user: UserID) -> Optional[int]:
        """Emulate 'owner' logic for room v12+: creator or additional_creators."""
        ev = None
        try:
            ev = await self.client.get_state_event(room_id, EventType.ROOM_CREATE)
        except Exception:
            pass

        content: Dict[str, Any] = {}
        sender = ""

        if isinstance(ev, dict):
            sender = str(ev.get("sender", "") or "")
            c = ev.get("content")
            if isinstance(c, dict):
                content = c
        elif ev is not None:
            try:
                if hasattr(ev, "serialize"):
                    content = ev.serialize()  # type: ignore[attr-defined]
                else:
                    content = getattr(ev, "__dict__", {}) or {}
            except Exception:
                content = getattr(ev, "__dict__", {}) or {}

        rv = (content or {}).get("room_version")
        try:
            rv_int = int(str(rv))
        except Exception:
            rv_int = None

        if rv_int is not None and rv_int >= 12 and not sender:
            # fetch raw /state to discover sender
            try:
                path = f"/_matrix/client/v3/rooms/{quote(str(room_id))}/state"
                raw_state = await self.client.api.request("GET", path)
                if isinstance(raw_state, list):
                    for e in raw_state:
                        if isinstance(e, dict) and e.get("type") == "m.room.create" and (e.get("state_key", "") == ""):
                            sender = str(e.get("sender", "") or "")
                            c = e.get("content")
                            if not content and isinstance(c, dict):
                                content = c
                            break
            except Exception:
                pass

        if rv_int is not None and rv_int >= 12:
            addl = (content or {}).get("additional_creators") or []
            if sender and (sender == str(user) or (isinstance(addl, list) and str(user) in addl)):
                return 1_000_000

        creator = (content or {}).get("creator")
        if creator and creator == str(user):
            return 100
        return None

    async def _get_user_pl(self, room_id: RoomID, user: UserID) -> int:
        owner_pl = await self._owner_pl_if_v12(room_id, user)
        if owner_pl is not None:
            return owner_pl
        try:
            ev = await self.client.get_state_event(room_id, EventType.ROOM_POWER_LEVELS)
        except Exception:
            return 0
        try:
            if isinstance(ev, PowerLevelStateEventContent):
                pls = ev
            elif isinstance(ev, dict):
                pls = PowerLevelStateEventContent.deserialize(ev)
            elif hasattr(ev, "content"):
                c = ev.content
                if isinstance(c, PowerLevelStateEventContent):
                    pls = c
                elif isinstance(c, dict):
                    pls = PowerLevelStateEventContent.deserialize(c)
                else:
                    pls = PowerLevelStateEventContent.deserialize(getattr(c, "__dict__", {}))
            else:
                pls = PowerLevelStateEventContent.deserialize(getattr(ev, "__dict__", {}))
        except Exception:
            return 0
        level = pls.users.get(user)
        if level is None:
            level = pls.users.get(str(user))
        if level is None:
            level = pls.users_default or 0
        try:
            return int(level or 0)
        except Exception:
            return 0

    async def _is_admin(self, room_id: RoomID, user: UserID) -> bool:
        if str(user) in set(self.config.get("adminlist", []) or []):
            return True
        if self.config.get("restrict_commands_to_local", False):
            want = (self.config.get("local_homeserver_domain", "") or "").lower()
            if want and self._user_domain(user) != want:
                return False
        required = int(self.config.get("pl_required", 0) or 0)
        if required <= 0:
            return True
        level = await self._get_user_pl(room_id, user)
        return level >= required

    # -------- per-room policy helpers --------
    async def _load_room_policy(self, room_id: RoomID) -> Tuple[int, bool, bool]:
        """Return (max_chars, relay_mode, active_mode) for room."""
        row = await self.database.fetchrow(
            "SELECT COALESCE(max_chars, 0) AS max_chars, COALESCE(relay_mode, FALSE) AS relay_mode, "
            "       (mode='active' AND active) AS is_active "
            "FROM inreach_room WHERE room_id=$1",
            str(room_id),
        )
        if not row:
            return int(self.config.get("max_reply_chars", 160) or 160), False, False
        max_chars = int(row["max_chars"] or 0) or int(self.config.get("max_reply_chars", 160) or 160)
        relay_mode = bool(row["relay_mode"])
        is_active = bool(row["is_active"])
        return max_chars, relay_mode, is_active

    async def _can_user_send(self, room_id: RoomID, user: UserID, relay_mode: bool) -> bool:
        """When relay_mode is off, enforce admin PL if allow_non_admin_send is False.
        When relay_mode is on, allow everyone."""
        if relay_mode:
            return True
        if not bool(self.config.get("allow_non_admin_send", True)):
            return await self._is_admin(room_id, user)
        return True

    # -------- helpers: alias, gmail --------
    def _norm_alias(self, alias: str) -> Optional[str]:
        a = (alias or "").strip().lower()
        return a if self._alias_re.match(a) else None

    def _gmail_plus(self, alias: str) -> str:
        base = str(self.config.get("gmail_base_address", "email@example.com") or "email@example.com").strip()
        if "@" not in base:
            return base
        local, domain = base.split("@", 1)
        return f"{local}+{alias}@{domain}"

    # Garmin helpers
    def _extract_reply_url(self, text: str) -> Optional[str]:
        """Find Garmin reply URL (handles region subdomains)."""
        if not text:
            return None
        m = re.search(
            r"https?://[a-z]+\.?explore\.garmin\.com/textmessage/txtmsg\?[^ \n\r\t>]+",
            text,
            re.IGNORECASE,
        )
        return m.group(0) if m else None

    def _parse_adr_from_reply_url(self, url: str) -> Optional[str]:
        """IMPORTANT: use unquote (not unquote_plus) to preserve '+' in emails."""
        try:
            q = parse_qs(urlparse(url).query)
            adr = q.get("adr", [None])[0]
            return unquote(adr) if adr else None
        except Exception:
            return None

    # -------- backend admin API --------
    async def _admin_call(self, action: str, body: Optional[Dict[str, Any]] = None) -> Tuple[bool, Dict[str, Any]]:
        base = self.config.get("admin_base_url", None)
        token = self.config.get("admin_token", None)
        if not base or not token:
            return False, {"error": "missing_admin_config"}
        params = {"admin_token": token, "action": action}
        try:
            resp: ClientResponse
            if body is None:
                resp = await self.http.get(base, params=params, allow_redirects=True)
            else:
                resp = await self.http.post(base, params=params, json=body, allow_redirects=True)
            txt = await resp.text()
            try:
                data = json.loads(txt)
            except Exception:
                data = {"raw": txt}
            ok = (200 <= resp.status < 300) and data is not None and not data.get("error")
            return ok, data
        except Exception as e:
            self.log.exception("admin_call %s failed", action)
            return False, {"error": str(e)}

    # -------- web endpoint (data-plane from Gmail bridge) --------
    @web.post("/inreach/send")
    async def webhook_inreach(self, req: Request) -> Response:
        """Bearer-protected endpoint that the Apps Script posts emails to."""
        token = parse_auth_token(req, bool(self.config.get("allow_query_token", False)))
        if not token:
            return Response(status=401, text="missing_token")
        tok_h = sha256_hex(token)

        # Find the room with this token
        room_row = await self.database.fetchrow(
            "SELECT room_id, friendly FROM inreach_room WHERE token_hash=$1 LIMIT 1",
            tok_h,
        )
        if not room_row:
            return Response(status=401, text="bad_token")

        room_id = RoomID(room_row["room_id"])
        friendly = room_row["friendly"]

        try:
            data = await req.json()
        except Exception:
            return Response(status=400, text="invalid_json")

        # Derive short display label from incoming alias if present.
        alias_in = (data or {}).get("alias") or ""
        label_row = None
        if alias_in:
            label_row = await self.database.fetchrow(
                "SELECT label FROM inreach_alias WHERE room_id=$1 AND alias=$2",
                str(room_id), alias_in
            )
        short_label = (label_row["label"] if label_row and label_row.get("label") else None) \
                      or (alias_in.split("-", 1)[0] if alias_in else (friendly or "inreach"))

        body_plain = (((data or {}).get("body") or {}).get("plain")) or ""
        body_html = (((data or {}).get("body") or {}).get("html")) or ""
        snippet = data.get("snippet") or ""
        subject = data.get("subject") or ""
        preview = first_nonempty_line(body_plain) or snippet or subject or "(no text)"

        # store latest reply URL when present
        reply_url = self._extract_reply_url(body_plain) or self._extract_reply_url(body_html)
        if reply_url:
            await self.database.execute(
                """
                INSERT INTO inreach_reply (room_id, last_reply_url, updated_ts)
                VALUES ($1, $2, $3)
                ON CONFLICT (room_id)
                DO UPDATE SET last_reply_url=excluded.last_reply_url,
                              updated_ts=excluded.updated_ts
                """,
                str(room_id), reply_url, now_ms()
            )

        pos_link = f"[Position]({reply_url})" if reply_url else ""
        msg = f"**{escape_md(short_label)}**: {preview}"
        if pos_link:
            msg += f" — {pos_link}"

        try:
            # Force posting as a normal text message
            await self.client.send_markdown(room_id, msg, msgtype="m.text")
        except Exception:
            self.log.exception("Send to room failed")
            return Response(status=500, text="room_send_failed")

        return Response(status=204)

    # -------- commands --------
    @command.new(name="inreach", require_subcommand=True, help="Manage the InReach email bridge")
    async def inreach(self, evt: MessageEvent) -> None:
        await self._help(evt)

    @inreach.subcommand(name="help", help="Show help")
    async def _help(self, evt: MessageEvent) -> None:
        base = self.config.get("gmail_base_address", "email@example.com") or "email@example.com"
        active_default = "on" if self.config.get("active_mode_default", False) else "off"
        msg = (
            "**InReach bridge**\n\n"
            "- `!inreach sub <name>` — create a per-room webhook (Bearer) and subscribe a Gmail +alias with Apps Script.\n"
            "- `!inreach unsub` — unsubscribe and disable the bridge in this room.\n"
            "- `!inreach show` — show current settings (+address, mode, relay, max chars, last reply link).\n"
            "- `!inreach mode <active|passive>` — active: plain messages are bridged automatically; passive: use `!inreach send`.\n"
            "- `!inreach relay <on|off>` — when on, prefix replies with `nick:` and allow everyone to send.\n"
            "- `!inreach set max <n>` — set per-room max chars (e.g. 160 or 1600). Long messages auto-split.\n"
            "- `!inreach send <text>` — send a reply via the latest InReach link.\n"
            "- `!inreach perms` — show permission diagnostics.\n\n"
            f"Gmail address format: **{base.replace('@', '+<alias>@')}**\n"
            f"Default room mode on subscribe: **{active_default}**\n"
            f"Default max chars: **{int(self.config.get('max_reply_chars', 160))}**."
        )
        await self.client.send_markdown(evt.room_id, msg)

    @inreach.subcommand(name="perms", help="Show permission diagnostics")
    async def _perms(self, evt: MessageEvent) -> None:
        in_adminlist = str(evt.sender) in set(self.config.get("adminlist", []) or [])
        restrict_local = bool(self.config.get("restrict_commands_to_local", False))
        want_domain = (self.config.get("local_homeserver_domain", "") or "").lower()
        local_ok = (self._user_domain(evt.sender) == want_domain) if restrict_local and want_domain else True
        required = int(self.config.get("pl_required", 0) or 0)
        level = await self._get_user_pl(evt.room_id, evt.sender)
        result = (in_adminlist or (local_ok and level >= required))
        await self.client.send_markdown(
            evt.room_id,
            "**InReach permission diagnostics**\n"
            f"- You: {evt.sender} (server: {self._user_domain(evt.sender)})\n"
            f"- In adminlist: **{'yes' if in_adminlist else 'no'}**\n"
            f"- Local OK (needs {want_domain or '(none)'}): **{'yes' if local_ok else 'no'}**\n"
            f"- Required PL: **{required}**\n"
            f"- Your PL: **{level}**\n"
            f"- Result: **{'ALLOWED' if result else 'DENIED'}**"
        )

    @inreach.subcommand(name="relay", help="Toggle relay mode: !inreach relay <on|off>")
    @command.argument("state", required=True)
    async def relay(self, evt: MessageEvent, state: str) -> None:
        if not await self._is_admin(evt.room_id, evt.sender):
            await evt.reply("You are not allowed to do this here.")
            return
        s = (state or "").strip().lower()
        if s not in ("on", "off"):
            await evt.reply("Usage: !inreach relay <on|off>")
            return
        await self.database.execute(
            "UPDATE inreach_room SET relay_mode=$2, updated_ts=$3 WHERE room_id=$1",
            str(evt.room_id), (s == "on"), now_ms(),
        )
        await evt.reply(f"✅ Relay mode **{s}**.")

    @inreach.subcommand(name="set", help="Set per-room options: !inreach set max <n>")
    @command.argument("which", required=True)
    @command.argument("value", required=True)
    async def set_opt(self, evt: MessageEvent, which: str, value: str) -> None:
        if not await self._is_admin(evt.room_id, evt.sender):
            await evt.reply("You are not allowed to do this here.")
            return
        w = which.strip().lower()
        if w != "max":
            await evt.reply("Usage: !inreach set max <n>")
            return
        try:
            n = int(value.strip())
            if n < 20 or n > 5000:
                raise ValueError()
        except Exception:
            await evt.reply("`<n>` must be an integer between 20 and 5000.")
            return
        await self.database.execute(
            "UPDATE inreach_room SET max_chars=$2, updated_ts=$3 WHERE room_id=$1",
            str(evt.room_id), n, now_ms(),
        )
        await evt.reply(f"✅ max chars set to **{n}**.")

    @inreach.subcommand(name="sub", help="Subscribe: !inreach sub <name>")
    @command.argument("name", required=True)
    async def sub(self, evt: MessageEvent, name: str) -> None:
        if not await self._is_admin(evt.room_id, evt.sender):
            await evt.reply("You are not allowed to do this here.")
            return

        # enforce one sub per room
        existing = await self.database.fetchrow(
            "SELECT 1 FROM inreach_alias WHERE room_id=$1 LIMIT 1",
            str(evt.room_id),
        )
        if existing:
            await evt.reply("This room already has an InReach subscription. Use `!inreach show` or `!inreach unsub` first.")
            return

        friendly = self._norm_alias(name)
        if not friendly:
            await evt.reply("Invalid name. Use [a-z0-9._-], max 64.")
            return

        # final alias with random suffix
        alias = await self._make_alias(friendly)

        # rotate per-room inbound token (for our /inreach/send)
        new_token = await self._rotate_token(evt.room_id)

        # our webhook endpoint that Apps Script will call
        webhook_endpoint = f"{self.webapp_url}inreach/send"

        # call backend to subscribe alias → webhook + bearer(new_token)
        ok, data = await self._admin_call("subscribe", {
            "alias": alias,
            "webhook": webhook_endpoint,
            "bearer_token": new_token,
        })
        if not ok:
            await evt.reply(f"Backend subscribe failed: {data.get('error') or data}")
            return

        # store/refresh main room row (with defaults)
        mode_val = "active" if bool(self.config.get("active_mode_default", False)) else "manual"
        await self.database.execute(
            """
            INSERT INTO inreach_room (room_id, friendly, created_by, token_hash, webhook_url,
                                      active, mode, max_chars, relay_mode, created_ts, updated_ts)
            VALUES ($1,$2,$3,$4,$5,TRUE,$6,$7,FALSE,$8,$9)
            ON CONFLICT (room_id)
            DO UPDATE SET friendly=excluded.friendly,
                          created_by=excluded.created_by,
                          token_hash=excluded.token_hash,
                          webhook_url=excluded.webhook_url,
                          active=TRUE,
                          mode=excluded.mode,
                          max_chars=excluded.max_chars,
                          relay_mode=excluded.relay_mode,
                          updated_ts=excluded.updated_ts
            """,
            str(evt.room_id),
            friendly,
            str(evt.sender),
            sha256_hex(new_token),
            webhook_endpoint,
            mode_val,
            int(self.config.get("max_reply_chars", 160) or 160),
            now_ms(),
            now_ms(),
        )

        # store alias mapping
        await self.database.execute(
            """
            INSERT INTO inreach_alias (room_id, alias, label, created_ts)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (room_id, alias)
            DO UPDATE SET label=excluded.label, created_ts=excluded.created_ts
            """,
            str(evt.room_id), alias, friendly, now_ms()
        )

        # confirmation
        plus_addr = self._gmail_plus(alias)
        await self.client.send_markdown(
            evt.room_id,
            "✅ **InReach bridge enabled**\n\n"
            f"- name: `{friendly}`\n"
            f"- alias: `{alias}`\n"
            f"- send email to: `{plus_addr}`\n"
            f"- room mode: **{'active' if self.config.get('active_mode_default', False) else 'passive'}**\n\n"
            "_Tip: if you pasted any secrets earlier, consider redacting that message._"
        )

    @inreach.subcommand(name="unsub", help="Disable the bridge and unsubscribe: !inreach unsub")
    async def unsub(self, evt: MessageEvent) -> None:
        if not await self._is_admin(evt.room_id, evt.sender):
            await evt.reply("You are not allowed to do this here.")
            return

        # Find latest alias in this room (if any)
        arow = await self.database.fetchrow(
            "SELECT alias FROM inreach_alias WHERE room_id=$1 ORDER BY created_ts DESC LIMIT 1",
            str(evt.room_id),
        )
        alias = arow["alias"] if arow else None
        if not alias:
            await evt.reply("No active InReach bridge in this room.")
            return

        ok, data = await self._admin_call("unsubscribe", {"alias": alias})
        if not ok:
            await evt.reply(f"Backend unsubscribe failed: {data.get('error') or data}")
            return

        await self.database.execute("DELETE FROM inreach_alias WHERE room_id=$1", str(evt.room_id))
        await self.database.execute("DELETE FROM inreach_reply WHERE room_id=$1", str(evt.room_id))
        await self.database.execute("DELETE FROM inreach_room WHERE room_id=$1", str(evt.room_id))
        await evt.reply("🗑️ InReach bridge disabled for this room.")

    @inreach.subcommand(name="show", help="Show current settings")
    async def show(self, evt: MessageEvent) -> None:
        room = await self.database.fetchrow(
            "SELECT friendly, active, mode, max_chars, relay_mode FROM inreach_room WHERE room_id=$1",
            str(evt.room_id),
        )
        if not room:
            await evt.reply("No InReach config found here.")
            return
        arow = await self.database.fetchrow(
            "SELECT alias, label FROM inreach_alias WHERE room_id=$1 ORDER BY created_ts DESC LIMIT 1",
            str(evt.room_id),
        )
        plus = self._gmail_plus(arow["alias"]) if arow else "(no alias yet)"
        rrow = await self.database.fetchrow(
            "SELECT last_reply_url FROM inreach_reply WHERE room_id=$1",
            str(evt.room_id),
        )
        rurl = (rrow["last_reply_url"] if rrow else None) or "(not yet received)"
        await self.client.send_markdown(
            evt.room_id,
            "**InReach settings**\n"
            f"- name: `{room['friendly'] or (arow['label'] if arow else '')}`\n"
            f"- alias: `{arow['alias'] if arow else '(none)'}`\n"
            f"- +address: `{plus}`\n"
            f"- last reply link: `{rurl}`\n"
            f"- mode: **{'active' if (room['mode'] == 'active' and room['active']) else 'passive'}**\n"
            f"- relay mode: **{'on' if room['relay_mode'] else 'off'}**\n"
            f"- max chars: **{room['max_chars'] or int(self.config.get('max_reply_chars', 160) or 160)}**"
        )

    @inreach.subcommand(name="mode", help="Set bridging mode: !inreach mode <active|passive>")
    @command.argument("mode", required=True)
    async def mode(self, evt: MessageEvent, mode: str) -> None:
        if not await self._is_admin(evt.room_id, evt.sender):
            await evt.reply("You are not allowed to do this here.")
            return
        m = (mode or "").strip().lower()
        if m not in ("active", "passive", "manual"):
            await evt.reply("Usage: !inreach mode <active|passive>")
            return
        mode_val = "active" if m == "active" else "manual"
        await self.database.execute(
            "UPDATE inreach_room SET mode=$2, active=$3, updated_ts=$4 WHERE room_id=$1",
            str(evt.room_id), mode_val, (m == "active"), now_ms()
        )
        await evt.reply(f"✅ Mode set to **{m}**.")

    @inreach.subcommand(name="send", help="Send a reply: !inreach send <text>")
    @command.argument("text", pass_raw=True, required=True)
    async def send_cmd(self, evt: MessageEvent, text: str) -> None:
        await self._bridge_outgoing(evt, text)

    # -------- passive/active message bridge --------
    @event.on(EventType.ROOM_MESSAGE)
    async def on_message(self, evt: MessageEvent) -> None:
        if not evt.content or not isinstance(evt.content, MessageEventContent):
            return
        if evt.sender == self.client.mxid:
            return
        if evt.content.relates_to and evt.content.relates_to.rel_type:
            return
        # only bridge plain body (ignore commands)
        body = (evt.content.body or "").strip()
        if not body or body.startswith("!"):
            return

        # only in active rooms
        _, _, is_active = await self._load_room_policy(evt.room_id)
        if not is_active:
            return

        await self._bridge_outgoing(evt, body)

    # -------- core: outgoing bridge with relay & chunking --------
    async def _bridge_outgoing(self, evt: MessageEvent, body: str) -> None:
        max_chars, relay_mode, _ = await self._load_room_policy(evt.room_id)

        if not await self._can_user_send(evt.room_id, evt.sender, relay_mode):
            await evt.reply("You are not allowed to send InReach replies in this room.")
            return

        # Need a reply URL
        rrow = await self.database.fetchrow(
            "SELECT last_reply_url FROM inreach_reply WHERE room_id=$1",
            str(evt.room_id),
        )
        if not rrow or not rrow["last_reply_url"]:
            await evt.reply("No reply link yet. Wait for an incoming InReach email first.")
            return

        text = body.strip()

        # Optional relay prefix
        if relay_mode:
            # take localpart before ":" – e.g. @palchrb:example.com -> palchrb
            nick = str(evt.sender).split(":", 1)[0].lstrip("@")
            text = f"{nick}: {text}"

        # Auto-chunk into max_chars-5 windows
        chunk_size = max(1, max_chars - 5)
        chunks: List[str] = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)] or [""]

        # Send all chunks; if any fails, report once
        for part in chunks:
            ok, err = await self._send_inreach(rrow["last_reply_url"], part)
            if not ok:
                await evt.reply(f"Send failed: {err}")
                return

        # React ✅ on success (quiet UX)
        try:
            await self.client.react(evt.room_id, evt.event_id, "✅")
        except Exception:
            # ignore reaction errors silently
            pass

    # -------- HTTP to Garmin --------
    async def _send_inreach(self, reply_url: str, message: str) -> Tuple[bool, Optional[str]]:
        guid = None
        try:
            q = parse_qs(urlparse(reply_url).query)
            guid = q.get("extId", [None])[0]
        except Exception:
            pass
        if not guid:
            return False, "invalid_reply_url"

        adr = self._parse_adr_from_reply_url(reply_url) or (self.config.get("gmail_base_address") or "")
        payload = {
            "ReplyAddress": adr,          # keep '+' intact (we used unquote)
            "ReplyMessage": message,
            "MessageId": str(int(time.time() * 1000) % 10_000_000),
            "Guid": guid,
        }

        body = urlencode(payload)
        try:
            headers = {
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "accept": "*/*",
                "user-agent": "Mozilla/5.0",
            }
            resp = await self.http.post(reply_url, data=body, headers=headers)
            txt = await resp.text()
            if resp.status == 200:
                try:
                    j = json.loads(txt)
                    if j.get("Success"):
                        return True, None
                except Exception:
                    pass
                return False, f"unexpected_response: {txt[:200]}"
            elif resp.status == 500:
                return False, "garmin_500"
            elif resp.status == 403:
                return False, "garmin_403"
            return False, f"http_{resp.status}"
        except Exception as e:
            self.log.exception("Garmin send failed")
            return False, str(e)

    # -------- tiny helpers --------
    async def _make_alias(self, friendly: str) -> str:
        alias = friendly
        if bool(self.config.get("alias_append_random", True)):
            import secrets, string
            n = int(self.config.get("alias_random_len", 8) or 8)
            alphabet = string.ascii_lowercase + string.digits
            suffix = "".join(secrets.choice(alphabet) for _ in range(max(1, n)))
            keep = max(1, 64 - (len(suffix) + 1))
            alias = friendly[:keep] + "-" + suffix
        return alias

    async def _rotate_token(self, room_id: RoomID) -> str:
        import secrets
        tok = secrets.token_urlsafe(24)
        await self.database.execute(
            """
            INSERT INTO inreach_room (room_id, token_hash, created_ts, updated_ts)
            VALUES ($1,$2,$3,$4)
            ON CONFLICT (room_id)
            DO UPDATE SET token_hash=excluded.token_hash, updated_ts=excluded.updated_ts
            """,
            str(room_id), sha256_hex(tok), now_ms(), now_ms()
        )
        return tok
