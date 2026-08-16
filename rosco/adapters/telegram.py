"""Telegram: messages from a phone, in and out.

The first real channel. It long-polls Telegram for messages, resolves each one
through the Doorway, and replies. Pure urllib, no library - the same choice
classify.py made, and for the same reason: one fewer dependency to keep current.

WHAT MAKES TELEGRAM A STRONG CHANNEL. Every update carries the sender's numeric
account id, assigned by Telegram and not settable by the sender. That id is what
identity.resolve() keys on - never the display name, which anyone can set to
"Ross Fusz". So a paired id is proof, and Telegram earns its place in
grants.STRONG. The moment this stops being true - a new channel where the
sender picks their own id - it must not be classed STRONG.

WHAT THIS ADAPTER CANNOT DO. It raises asks (a node fact, anybody may ask) and
it relays replies. It cannot answer an ask, grant anything, or enrol anyone off
its own bat - those need Ross's signature, and a running service does not sign
authority on the say-so of an inbound message. The single exception is the
pairing handshake, and even that is not the adapter deciding: Ross ran
`rosco pair` at the console, the console minted the code, and the message only
carries it back. The authority came from the console; Telegram is the courier.

DELIVERY IS HONEST ABOUT WHAT EXISTS. A cleared request (SELF/ANSWER) means the
person is allowed - but the connector that would actually fetch a spray log or
arm a house is the tools layer, not yet built. So the adapter says exactly that
rather than pretending to have done something. Over-promising is how trust in an
assistant dies.
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.error import HTTPError

from ..arrive import Arrival
from ..asks import Asks
from ..grants import ANSWER, ASK, DECLINE, SELF
from ..identity import People
from ..models import SYSTEM
from ..store import now

CHANNEL = "telegram"
TOKEN_SECRET = "telegram_bot_token"     # vault: system:telegram_bot_token
POLL_TIMEOUT = 25                       # long-poll seconds
CODE_TTL_HINT = "send it within 15 minutes"

_REPLIES = {
    SELF: ("You're cleared for that. I can't fetch it for you yet - that "
           "connector is the next piece being built - but the permission is in "
           "place."),
    ANSWER: ("You're cleared for that. Composing the answer is the next piece "
             "being built; the permission is in place."),
    ASK: "Passed to Ross - he'll get back to you.",
    DECLINE: "That's not something I can share.",
}


class TelegramBot:
    """Long-polls Telegram, routes through the Doorway, replies.

    Built with dependencies injected so it is testable without a network: `send`
    is any callable(chat_id, text), defaulting to a real Telegram call, and
    `handle_update` is the unit the tests drive with fake update dicts.
    """

    def __init__(self, console, doorway, passphrase, token, *, send=None) -> None:
        self.console = console
        self.doorway = doorway
        self.people = People(doorway.log)
        self.asks = Asks(doorway.log)
        self._passphrase = passphrase     # entered at the console at startup
        self.token = token
        self._send = send or self._http_send
        self.offset_path = Path(console.home) / "telegram.offset"

    # ---- construction from the console ----------------------------------

    @classmethod
    def from_console(cls, console, passphrase, *, send=None) -> "TelegramBot":
        """Read the bot token from the vault and assemble the live doorway.

        The token is a system secret, so this needs the vault key - which is why
        the service is started at the console with the passphrase, once.
        """
        from ..vault import Vault

        vault = Vault(console.open(passphrase), key=console._vault_key(passphrase))
        token = vault.get_secret(SYSTEM, TOKEN_SECRET)
        if not token:
            raise SystemExit(
                "no Telegram bot token stored. Set it once, at the console:\n"
                "  rosco secret set system telegram_bot_token")
        doorway = console.doorway(passphrase)
        return cls(console, doorway, passphrase, token, send=send)

    # ---- the network edge (overridable for tests) -----------------------

    def _api(self, method: str, params: dict, timeout: int = 30) -> dict:
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        data = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    def _http_send(self, chat_id, text: str) -> None:
        self._api("sendMessage", {"chat_id": chat_id, "text": text})

    def send(self, chat_id, text: str) -> None:
        try:
            self._send(chat_id, text)
        except Exception:
            # A failed reply must not take the service down. The ask, if one was
            # raised, is already on record; the person simply did not hear back.
            pass

    # ---- the loop -------------------------------------------------------

    def _offset(self) -> int:
        try:
            return int(self.offset_path.read_text())
        except (OSError, ValueError):
            return 0

    def _set_offset(self, value: int) -> None:
        self.offset_path.write_text(str(value))

    def poll_once(self, timeout: int = POLL_TIMEOUT) -> int:
        """One long-poll cycle. Returns how many updates were handled."""
        resp = self._api("getUpdates",
                         {"offset": self._offset(), "timeout": timeout},
                         timeout=timeout + 10)
        updates = resp.get("result") or []
        for u in updates:
            try:
                self.handle_update(u)
            except Exception:
                # One malformed or hostile update must not stop the rest, and
                # must not crash the service. It is dropped; the sender can try
                # again. Nothing was written on a path that raised.
                pass
            # Advancing the offset is what acks the update to Telegram, so it
            # must happen even for a poison message - otherwise the same one
            # returns forever and wedges the poll. Guarded on its own: a
            # non-integer update_id (only a hostile or fake update) is skipped
            # rather than crashing the advance.
            try:
                self._set_offset(int(u["update_id"]) + 1)
            except (KeyError, ValueError, TypeError):
                pass
        return len(updates)

    def whoami(self) -> str:
        """The bot's @username per Telegram, or '' if the token is rejected.

        A startup handshake so a bad token fails LOUDLY instead of the loop
        silently long-polling a bot that will never answer - the exact shape of
        'I stored the token and messaged it and nothing happened'.
        """
        try:
            d = self._api("getMe", {}, timeout=15)
        except Exception:
            return ""
        if d.get("ok") and isinstance(d.get("result"), dict):
            return d["result"].get("username") or "bot"
        return ""

    def serve(self) -> None:
        who = self.whoami()
        if not who:
            print("the stored telegram_bot_token was rejected by Telegram. "
                  "Fix it (dashboard -> Settings -> Telegram bot, or\n"
                  "  rosco secret set system telegram_bot_token\n"
                  "then start again.")
            return
        print(f"listening on Telegram as @{who} as of {now()}. Ctrl-C to stop.")
        if any(h.channel == CHANNEL for h in self.people.handles()):
            print("your phone is paired — text it or send it photos. Authority stays "
                  "at the console; this only carries messages.")
        else:
            print("not paired yet: from your phone message @%s, then run "
                  "`python -m rosco pair` AT THIS CONSOLE (not on your phone) to link "
                  "it." % who)
        warned_conflict = False
        while True:
            try:
                self.poll_once()
                warned_conflict = False
            except KeyboardInterrupt:
                print("\nstopped.")
                return
            except HTTPError as e:
                # 409 = another process is already long-polling this same bot
                # (a second `rosco serve`, or another app - e.g. fusz_agent -
                # sharing the token). Telegram hands each update to ONE poller,
                # so this must be surfaced, not silently retried forever.
                if e.code == 409 and not warned_conflict:
                    print("Telegram 409: another process is polling this bot. "
                          "Two pollers can't share one bot - stop the other "
                          "listener, or give Rosco its own BotFather bot.")
                    warned_conflict = True
                time.sleep(5)
            except Exception:
                # Network blip, Telegram hiccup. Wait a moment and carry on -
                # the service is meant to sit up for weeks.
                time.sleep(5)

    # ---- handling one message -------------------------------------------

    def handle_update(self, update: dict) -> None:
        msg = update.get("message") or update.get("edited_message")
        if not isinstance(msg, dict):
            return
        sender = msg.get("from") or {}
        sender_id = sender.get("id")
        chat_id = (msg.get("chat") or {}).get("id", sender_id)
        text = msg.get("text") or ""
        photos = msg.get("photo") or []
        doc = msg.get("document") or {}
        caption = msg.get("caption") or ""
        if sender_id is None:
            return
        sender_id = str(sender_id)
        if not text.strip():
            # An image gets READ by the vision model, not silently dropped — that
            # empty-text return is why a picture used to get no reply. A screenshot
            # can arrive as a compressed 'photo' OR as an uncompressed image
            # 'document' (sent as a file), so handle both.
            if photos:
                self._see_file(sender_id, chat_id, (photos[-1] or {}).get("file_id", ""), caption)
            elif doc and str(doc.get("mime_type", "")).lower().startswith("image/"):
                self._see_file(sender_id, chat_id, doc.get("file_id", ""), caption,
                               media=doc.get("mime_type", ""))
            elif self._known(sender_id):
                self.send(chat_id, "I got that, but I can only read text or an image "
                                   "right now — send it as text or a picture.")
            return

        # Pairing handshake. If Ross has a pairing open at the console and this
        # message is just the code, complete it. The console did the deciding;
        # this only carries the code back with the sender's real id attached.
        if self._maybe_pair(sender_id, chat_id, text):
            return

        arrival = Arrival(CHANNEL, sender_id, text, at=now())
        handling = self.doorway.handle(arrival)
        # The doorway's reply carries the fulfilled work (an answer, or a
        # "drafted for Ross" note) when a fulfiller is wired; fall back to the
        # plain per-outcome line only when it left the reply empty.
        reply = handling.reply or _REPLIES.get(handling.outcome, _REPLIES[ASK])
        # When the bot couldn't act on it (ASK) but a RECOGNISED sender sent it,
        # don't just let it become an unanswered ask — capture it to the ingest
        # hopper so Rosco can learn/place it on review. Telegram is a capture inbox.
        if handling.outcome == ASK and self._known(sender_id):
            if self._queue_capture(text, "telegram:note"):
                reply += "  \U0001f4e5 Saved to your ingest queue to review."
        self.send(chat_id, reply)

        # A heads-up to Ross when something NEW lands in his queue - read-only.
        # Only a fresh ask, never a repeat: otherwise an enrolled account could
        # nag the same question and flood his phone through the notifier. He
        # still answers at the console; Telegram is not an approval surface.
        if handling.outcome == ASK and handling.new_ask:
            self._notify_ross(handling)

    def _maybe_pair(self, sender_id: str, chat_id, text: str) -> bool:
        code = text.strip()
        if not (code.isdigit() and len(code) == 6):
            return False
        if not self.console.pairing_open():
            return False
        try:
            self.console.pair_claim(self._passphrase, code, sender_id)
        except SystemExit as e:
            self.send(chat_id, f"Pairing didn't work: {e}")
            return True
        self.send(chat_id, "Paired. This account is now recognised as Ross.")
        return True

    def _see_file(self, sender_id, chat_id, file_id, caption, media="") -> None:
        """Read an image (a 'photo' or an image 'document') with the vision model
        and reply. A read, but it spends a model call, so only for a recognised
        sender. Ross's caption, if any, is the prompt."""
        if not self._known(sender_id):
            self.send(chat_id, _REPLIES.get(ASK, "I don't recognise this account."))
            return
        self.send(chat_id, "\U0001f4e5 Got it — reading the image, one sec…")   # quick ack; the read follows
        try:
            b64, dmedia = self._download_photo(file_id)
        except Exception:
            b64, dmedia = "", ""
        media = media or dmedia
        if not b64:
            self.send(chat_id, "I couldn't download that image.")
            return
        b64, media = self._shrink(b64, media)   # a multi-MB screenshot is what times the read out
        from ..llm import NoModel, see
        from ..meter import Meter
        from ..models import Models
        from ..vault import Vault
        log = self.console.open(self._passphrase)
        models = Models(log, Vault(log, key=self.console._vault_key(self._passphrase)))
        prompt = caption.strip() or ("Read this image and tell me what it is and the "
                                     "key details, briefly.")
        try:
            answer = see(models, prompt, b64, media, meter=Meter(log), timeout=120)
        except NoModel:
            self.send(chat_id, "I can see you sent an image, but no vision model is set up.")
            return
        except Exception as e:
            self.send(chat_id, "I couldn't read the image — " + str(e)[:120])
            return
        answer = (answer or "").strip() or "(the vision model returned nothing)"
        # Capture what it read into the ingest hopper — an image sent to the bot is
        # a capture, not a throwaway; Rosco reviews/places it later.
        tail = ""
        if answer and not answer.startswith("("):
            if self._queue_capture(answer, "telegram:image"):
                tail = "\n\n\U0001f4e5 Saved to your ingest queue to review."
        self.send(chat_id, answer + tail)

    def _known(self, sender_id) -> bool:
        """Is this Telegram id a recognised person (Ross paired, or enrolled)?"""
        return any(h.channel == CHANNEL and str(h.address) == str(sender_id)
                   for h in self.people.handles())

    def _queue_capture(self, text, source) -> int:
        """Drop content Ross sent the bot into the ingest hopper for review. A NODE
        write (ingest.proposed) — no learning happens until he reviews it."""
        text = (text or "").strip()
        if not text:
            return 0
        try:
            from ..ingest import Ingest
            return Ingest(self.console.open(self._passphrase)).add(
                [{"text": text, "business": "", "confidence": 0.0,
                  "why": "from telegram", "summary": ""}], source=source)
        except Exception:
            return 0

    def _shrink(self, b64, media, max_side=1600, png_cap=1_400_000):
        """Downscale an oversized image before it goes to the vision model.

        A phone screenshot sent as a *document* is uncompressed and can be several
        MB — ~11MB of base64 to a slow vision endpoint is exactly what timed the
        read out. Cap the long side (text stays legible at 1600px) and keep it as
        PNG while that's still small (lossless is best for screenshots of text),
        else fall back to JPEG. Uses Pillow when present; if it's missing or
        anything goes wrong, the original bytes are sent unchanged — no hard
        dependency, and shrinking is an optimisation, never a gate."""
        try:
            import base64
            import io

            from PIL import Image
        except Exception:
            return b64, media
        try:
            im = Image.open(io.BytesIO(base64.b64decode(b64)))
            im.load()
            if max(im.size) > max_side:
                im.thumbnail((max_side, max_side))   # Pillow's default resample is fine
            buf = io.BytesIO()
            im.convert("RGBA" if im.mode in ("RGBA", "LA", "P") else "RGB").save(
                buf, "PNG", optimize=True)
            if buf.tell() <= png_cap:                 # a UI/text shot stays small as PNG
                return base64.b64encode(buf.getvalue()).decode(), "image/png"
            buf = io.BytesIO()                         # a photo balloons as PNG -> JPEG it
            im.convert("RGB").save(buf, "JPEG", quality=88)
            return base64.b64encode(buf.getvalue()).decode(), "image/jpeg"
        except Exception:
            return b64, media

    def _download_photo(self, file_id):
        """(base64, media_type) for a Telegram photo, or ('', '') if unavailable.
        Two hops: getFile for the path, then the file endpoint for the bytes."""
        import base64
        if not file_id:
            return "", ""
        info = self._api("getFile", {"file_id": file_id})
        path = ((info.get("result") or {}).get("file_path") or "")
        if not path:
            return "", ""
        url = f"https://api.telegram.org/file/bot{self.token}/{path}"
        with urllib.request.urlopen(urllib.request.Request(url), timeout=30) as r:
            data = r.read(8_000_000)          # cap ~8MB
        media = "image/png" if path.lower().endswith(".png") else "image/jpeg"
        return base64.b64encode(data).decode(), media

    def _notify_ross(self, handling) -> None:
        ross = [h for h in self.people.handles(person="ross")
                if h.channel == CHANNEL]
        if not ross:
            return
        a = self.asks.get(handling.ask_id) if handling.ask_id else None
        if a is None:
            return
        who = a.person
        what = f"{a.business}:{a.capability} {a.verb.upper()}"
        self.send(ross[0].address,
                  f"\U0001f514 {who} is asking for {what}. It's in your queue - "
                  f"answer it at the console.")
