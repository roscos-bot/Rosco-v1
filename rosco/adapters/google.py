"""Google Workspace OAuth: the authorize flow behind the settings button.

Ross clicks "Authorize" for an account, consents in HIS OWN browser as that
Google account, and Google redirects back to the local console with a one-time
code. The console - server-side, holding the client secret - trades the code for
a refresh token and seals it in the vault under that account's scope. The token
that can read and write the account never passes through the browser after the
consent, and never through anyone but Ross.

WHY THIS IS SAFE TERRAIN DESPITE MINTING A CREDENTIAL. Two things gate it:

  THE STATE. Every authorize URL carries a random `state` the console minted and
  remembered. The callback is believed only if its state matches an outstanding
  one. A page cannot forge a consent for an account it did not start.

  THE SECRET STAYS SERVER-SIDE. The code->token exchange needs the client secret,
  which lives in the vault and is used only here, over safehttp (https, no
  redirect, no internal target). A stolen code is worthless without it.

FULL SCOPES, ON PURPOSE. Ross asked for full access - the token can do anything
the account can. The restraint that matters ("agents propose, people ship") lives
in the agent and fulfilment layers, not in a narrow token: a read-only grant
would just mean the connector cannot draft the email it will never send anyway.
The scope breadth is a decision recorded here so it is visible, not buried.
"""
from __future__ import annotations

import urllib.parse

from .. import safehttp

# Full access across the surfaces an agent might work in. Space-joined into the
# consent request; Google shows Ross exactly these before he agrees.
SCOPES = (
    "https://mail.google.com/",                        # Gmail (full)
    "https://www.googleapis.com/auth/drive",           # Drive (full)
    "https://www.googleapis.com/auth/calendar",        # Calendar (full)
    "https://www.googleapis.com/auth/documents",       # Docs
    "https://www.googleapis.com/auth/spreadsheets",    # Sheets
    "https://www.googleapis.com/auth/chat.spaces",     # Chat spaces
    "https://www.googleapis.com/auth/chat.messages",   # Chat messages (post)
    "https://www.googleapis.com/auth/contacts",        # Contacts
    "https://www.googleapis.com/auth/tasks",           # Google Tasks (read/write)
    "openid", "email", "profile",                      # who authorized
)

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

CLIENT_ID = "google_client_id"
CLIENT_SECRET = "google_client_secret"
REFRESH_TOKEN = "google_refresh_token"
EMAIL = "google_email"


def consent_url(client_id: str, redirect_uri: str, state: str) -> str:
    """The Google consent URL to open. offline + consent so a refresh token
    actually comes back (Google withholds it on a silent re-auth otherwise)."""
    q = urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
    })
    return f"{AUTH_URL}?{q}"


def exchange_code(client_id: str, client_secret: str, code: str,
                  redirect_uri: str) -> dict:
    """Trade the one-time code for tokens. Server-to-server, secret in the body."""
    return safehttp.call(TOKEN_URL, method="POST", timeout=20, form={
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    })


def refresh_access(client_id: str, client_secret: str, refresh_token: str) -> dict:
    """Mint a fresh access token from a stored refresh token. The connector calls
    this per session; the access token is never persisted (it expires in an hour,
    the refresh token is the durable credential)."""
    return safehttp.call(TOKEN_URL, method="POST", timeout=20, form={
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    })


def whoami(access_token: str) -> dict:
    """Which Google account this token belongs to - shown on the settings row so
    Ross can confirm he authorized the right one (steelhaven, not personal)."""
    return safehttp.call(USERINFO_URL, method="GET", timeout=15, bearer=access_token)


# ---- the live connector: read Ross's Google, per account -------------------
#
# A stored refresh token is durable; an access token lasts an hour and is never
# persisted. access_for() mints a fresh one each time from the sealed creds, and
# the read helpers below run against it over safehttp (https, no redirect, no
# internal target). READS ONLY here - the "agents propose, people ship" line
# means a connector fetches and drafts; it never sends the mail or moves the file.

def access_for(vault, account: str) -> str:
    """A fresh access token for one account, or '' if it is not connected."""
    cid = vault.get_secret(account, CLIENT_ID)
    csec = vault.get_secret(account, CLIENT_SECRET)
    rt = vault.get_secret(account, REFRESH_TOKEN)
    if not (cid and csec and rt):
        return ""
    tok = refresh_access(cid, csec, rt)
    return (tok or {}).get("access_token", "") if isinstance(tok, dict) else ""


def _q(params: dict) -> str:
    import urllib.parse
    return urllib.parse.urlencode(params)


# Shared-drive flags: without these, files.list returns ONLY the user's My Drive
# and silently omits Shared Drive items AND files shared WITH the user — so a pull
# comes back empty for anything living in a team/shared drive.
_ALL_DRIVES = {"supportsAllDrives": "true", "includeItemsFromAllDrives": "true"}


def drive_recent(token: str, n: int = 12) -> list[dict]:
    d = safehttp.call(
        "https://www.googleapis.com/drive/v3/files?" + _q({
            "orderBy": "modifiedTime desc", "pageSize": n, "spaces": "drive",
            "fields": "files(id,name,mimeType,modifiedTime,webViewLink)", **_ALL_DRIVES}),
        method="GET", bearer=token, timeout=15)
    return d.get("files") or []


def drive_search(token: str, text: str, n: int = 12) -> list[dict]:
    safe = (text or "").replace("\\", "\\\\").replace("'", "\\'")
    d = safehttp.call(
        "https://www.googleapis.com/drive/v3/files?" + _q({
            "q": f"(name contains '{safe}' or fullText contains '{safe}') and trashed=false",
            "orderBy": "modifiedTime desc", "pageSize": n,
            "fields": "files(id,name,mimeType,modifiedTime,webViewLink)", **_ALL_DRIVES}),
        method="GET", bearer=token, timeout=15)
    return d.get("files") or []


def drive_meet_transcripts(token: str, match: str = "", n: int = 20) -> list[dict]:
    """Google Meet transcript Docs, newest first. Meet saves each meeting's
    transcript to the organiser's Drive as a Google Doc whose name ends
    '- Transcript'. Pass `match` to keep only those whose name ALSO contains it
    (the meeting title, e.g. 'Tactical'), so a weekly-standup watcher doesn't pull
    every meeting in the workspace. Returns [] on any error (never fatal)."""
    def esc(v):
        return (v or "").replace("\\", "\\\\").replace("'", "\\'")
    clauses = ["name contains 'Transcript'",
               "mimeType='application/vnd.google-apps.document'", "trashed=false"]
    if match:
        clauses.append(f"name contains '{esc(match)}'")
    try:
        d = safehttp.call(
            "https://www.googleapis.com/drive/v3/files?" + _q({
                "q": " and ".join(clauses), "orderBy": "modifiedTime desc",
                "pageSize": n,
                "fields": "files(id,name,mimeType,modifiedTime,webViewLink)", **_ALL_DRIVES}),
            method="GET", bearer=token, timeout=15)
        return d.get("files") or []
    except Exception:
        return []


# How a Google-native file becomes text. A Doc exports to plain text, a Sheet to
# CSV, Slides to text. A plain text/markdown/json file is downloaded as-is. A PDF
# or image has no text extraction here - the connector reads what it can and says
# so for the rest, rather than handing back binary noise.
_EXPORT = {
    "application/vnd.google-apps.document": "text/markdown",
    "application/vnd.google-apps.spreadsheet": "text/csv",
    "application/vnd.google-apps.presentation": "text/plain",
}


def _readable_media(mime: str) -> bool:
    m = (mime or "").lower()
    return (m.startswith("text/") or m in ("application/json", "application/xml")
            or "markdown" in m or "javascript" in m or "csv" in m)


def _export(token: str, file_id: str, export_mime: str) -> str:
    url = (f"https://www.googleapis.com/drive/v3/files/{file_id}/export?"
           + _q({"mimeType": export_mime, "supportsAllDrives": "true"}))
    return safehttp.call(url, method="GET", bearer=token, timeout=25, raw=True) or ""


def _pdf_text(data: bytes) -> str:
    """Embedded text from a PDF's bytes (pypdf). Returns '' for a scanned / image-
    only PDF (no embedded text — that needs OCR) or on any parse error. Page-capped
    so a huge plan set can't hang the pull."""
    try:
        import io
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        out = []
        for pg in reader.pages[:60]:
            try:
                out.append(pg.extract_text() or "")
            except Exception:
                pass
        return "\n".join(out).strip()
    except Exception:
        return ""


def drive_read(token: str, file_id: str, mime: str, max_chars: int = 8000) -> str:
    """The actual text of a Drive file, or '' if its type isn't readable text.

    A Doc is exported as MARKDOWN, not flat text, so its headings survive as
    '# Heading' lines. The ingest chunker uses those to keep each lesson under the
    section it belongs to instead of orphaning a bare heading (a plain-text export
    dropped '# Governing Principle' in as its own contentless item). Markdown
    export is newer, so a Doc that refuses it falls back to plain text.
    """
    if not file_id:
        return ""
    if mime in _EXPORT:
        want = _EXPORT[mime]
        text = ""
        if want == "text/markdown":
            try:
                text = _export(token, file_id, want)
            except Exception:
                text = ""                        # this Doc won't export markdown
        if not text:
            text = _export(token, file_id, "text/plain" if want == "text/markdown" else want)
    elif _readable_media(mime):
        url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media&supportsAllDrives=true"
        text = safehttp.call(url, method="GET", bearer=token, timeout=25, raw=True)
    elif (mime or "").lower() == "application/pdf":
        try:
            data = safehttp.call(
                f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media&supportsAllDrives=true",
                method="GET", bearer=token, timeout=45, binary=True,
                max_bytes=25 * 1024 * 1024)
            text = _pdf_text(data)              # '' for a scanned/image-only PDF (needs OCR)
        except Exception:
            text = ""
    else:
        return ""
    return (text or "")[:max_chars]


def drive_find(token: str, name: str) -> dict | None:
    """Best single file match for a name - what 'read <file>' resolves to."""
    files = drive_search(token, name, 5)
    return files[0] if files else None


def gmail_recent(token: str, query: str = "", n: int = 6) -> list[dict]:
    lst = safehttp.call(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?" + _q({
            "maxResults": n, "q": query or "in:inbox"}),
        method="GET", bearer=token, timeout=15)
    out = []
    for m in (lst.get("messages") or [])[:n]:
        mid = m.get("id")
        if not mid:
            continue
        try:
            md = safehttp.call(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}?" + _q({
                    "format": "metadata",
                    "metadataHeaders": "From"}) + "&metadataHeaders=Subject&metadataHeaders=Date",
                method="GET", bearer=token, timeout=12)
        except Exception:
            continue
        hdrs = {h.get("name", "").lower(): h.get("value", "")
                for h in ((md.get("payload") or {}).get("headers") or [])}
        out.append({"id": mid, "threadId": md.get("threadId", ""),
                    "from": hdrs.get("from", ""),
                    "subject": hdrs.get("subject", ""),
                    "date": hdrs.get("date", ""), "snippet": md.get("snippet", "")})
    return out


def gmail_history_id(token: str) -> str:
    """The mailbox's current historyId — the sync cursor for a watch window. One
    call to users.getProfile; it says nothing ABOUT the mail, just where the
    change-log is right now. Rosco stashes this when Ross says 'about to check
    email', and diffs from it when he says 'done'."""
    d = safehttp.call("https://gmail.googleapis.com/gmail/v1/users/me/profile",
                      method="GET", bearer=token, timeout=15)
    return str((d or {}).get("historyId", "") or "")


def gmail_changes(token: str, start_id: str, cap: int = 300) -> dict | None:
    """What changed since `start_id`, folded to a net label-delta per message.

    Returns {'transitions': {msg_id: {'added': set(labels), 'removed': set(labels),
    'arrived': bool}}, 'historyId': <new cursor>}. Returns None if the cursor is
    too old — Gmail keeps only ~a week of history, and a stale one 404s; the caller
    then re-baselines rather than guessing. Follows nextPageToken up to `cap`
    records so a big session isn't silently truncated without bound.

    A NET delta collapses churn: a message read then archived shows removed
    {UNREAD, INBOX} once, not three separate records. Only Ross's own mailbox is
    read — this is his behaviour in his account, the forgery-resistant signal the
    ranker is built on."""
    import urllib.parse
    base = "https://gmail.googleapis.com/gmail/v1/users/me/history"
    trans, newid, page, seen = {}, start_id, "", 0
    while True:
        # historyTypes is a REPEATED enum param — it must be sent as
        # historyTypes=messageAdded&historyTypes=labelAdded&... A single
        # comma-joined value is rejected 400 "Invalid value at 'history_types'".
        pairs = [("startHistoryId", start_id)]
        pairs += [("historyTypes", t) for t in ("messageAdded", "labelAdded", "labelRemoved")]
        if page:
            pairs.append(("pageToken", page))
        try:
            d = safehttp.call(base + "?" + urllib.parse.urlencode(pairs),
                              method="GET", bearer=token, timeout=20)
        except ValueError as e:
            if "HTTP 404" in str(e):
                return None                       # cursor too old — re-baseline
            raise
        newid = str((d or {}).get("historyId", newid) or newid)
        for h in (d.get("history") or []):
            for ma in h.get("messagesAdded", []):
                mid = (ma.get("message") or {}).get("id")
                if mid:
                    trans.setdefault(mid, {"added": set(), "removed": set(), "arrived": False})["arrived"] = True
            for la in h.get("labelsAdded", []):
                mid = (la.get("message") or {}).get("id")
                if mid:
                    trans.setdefault(mid, {"added": set(), "removed": set(), "arrived": False})["added"].update(la.get("labelIds", []))
            for lr in h.get("labelsRemoved", []):
                mid = (lr.get("message") or {}).get("id")
                if mid:
                    trans.setdefault(mid, {"added": set(), "removed": set(), "arrived": False})["removed"].update(lr.get("labelIds", []))
            seen += 1
            if seen >= cap:
                break
        page = d.get("nextPageToken", "")
        if not page or seen >= cap:
            break
    return {"transitions": trans, "historyId": newid}


def gmail_from_labels(token: str, message_id: str) -> tuple[str, set]:
    """The From header AND current labelIds of one message, from a SINGLE metadata
    fetch (format=metadata returns labelIds alongside the requested headers, so this
    costs no more than reading the sender alone).

    The labels are what let the watch tell engagement from a brush-off: a message
    whose INBOX label is gone but that no longer carries UNREAD was read then filed
    (or was already read — a paid bill), whereas one still UNREAD was cleared without
    a look. On any failure returns ('', set()) so the caller skips the message rather
    than inventing a signal from nothing."""
    try:
        d = safehttp.call(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?" + _q(
                {"format": "metadata", "metadataHeaders": "From"}),
            method="GET", bearer=token, timeout=12)
    except Exception:
        return "", set()
    frm = ""
    for h in ((d.get("payload") or {}).get("headers") or []):
        if h.get("name", "").lower() == "from":
            frm = h.get("value", "")
            break
    return frm, set(d.get("labelIds") or [])


def gmail_from(token: str, message_id: str) -> str:
    """The From header of one message (metadata only — no body). Used to attribute
    an observed read/archive/star to a sender/domain."""
    return gmail_from_labels(token, message_id)[0]


def _b64url(data: str) -> str:
    import base64
    try:
        return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "replace")
    except Exception:
        return ""


def _strip_html(html: str) -> str:
    import re
    t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    for a, b in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&#39;", "'"), ("&quot;", '"')):
        t = t.replace(a, b)
    t = re.sub(r"[ \t]+", " ", t)
    return re.sub(r"\n\s*\n\s*\n+", "\n\n", t).strip()


def _walk_parts(payload, plains, htmls):
    data = (payload.get("body") or {}).get("data")
    mime = payload.get("mimeType", "")
    if data:
        if mime == "text/plain":
            plains.append(_b64url(data))
        elif mime == "text/html":
            htmls.append(_b64url(data))
    for p in (payload.get("parts") or []):
        _walk_parts(p, plains, htmls)


def gmail_read(token: str, message_id: str, max_chars: int = 8000) -> str:
    """The plain-text body of one message. Prefers text/plain, falls back to a
    tag-stripped HTML part - the readable content, not the raw MIME."""
    if not message_id:
        return ""
    d = safehttp.call(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?" + _q({
            "format": "full"}),
        method="GET", bearer=token, timeout=20)
    plains, htmls = [], []
    _walk_parts(d.get("payload") or {}, plains, htmls)
    body = "\n".join(t for t in plains if t).strip()
    if not body:
        body = _strip_html("\n".join(t for t in htmls if t))
    return body[:max_chars]


def calendar_upcoming(token: str, n: int = 8) -> list[dict]:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    d = safehttp.call(
        "https://www.googleapis.com/calendar/v3/calendars/primary/events?" + _q({
            "timeMin": now, "maxResults": n, "singleEvents": "true",
            "orderBy": "startTime"}),
        method="GET", bearer=token, timeout=15)
    out = []
    for e in (d.get("items") or []):
        start = e.get("start") or {}
        out.append({"title": e.get("summary", ""),
                    "when": start.get("dateTime") or start.get("date") or "",
                    "location": e.get("location", "")})
    return out


def calendar_search(token: str, query: str, n: int = 10) -> list[dict]:
    from datetime import datetime, timezone
    d = safehttp.call(
        "https://www.googleapis.com/calendar/v3/calendars/primary/events?" + _q({
            "q": query, "timeMin": datetime.now(timezone.utc).isoformat(),
            "maxResults": n, "singleEvents": "true", "orderBy": "startTime"}),
        method="GET", bearer=token, timeout=15)
    out = []
    for e in (d.get("items") or []):
        start = e.get("start") or {}
        out.append({"title": e.get("summary", ""),
                    "when": start.get("dateTime") or start.get("date") or "",
                    "location": e.get("location", "")})
    return out


def calendar_recent_ended(token: str, match: str = "", hours_back: int = 24,
                          n: int = 20) -> list[dict]:
    """Events that fell within the last `hours_back` (a PAST window), optionally
    filtered to those matching `match` (a meeting-title query). Returns
    {id, title, start, end} — `end` drives the 'wait for the recap' grace, `id`
    the dedup, `start` the transcript match. [] on any error (never fatal)."""
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    params = {"timeMin": (now - timedelta(hours=hours_back)).isoformat(),
              "timeMax": now.isoformat(), "maxResults": n,
              "singleEvents": "true", "orderBy": "startTime"}
    if match:
        params["q"] = match
    try:
        d = safehttp.call(
            "https://www.googleapis.com/calendar/v3/calendars/primary/events?" + _q(params),
            method="GET", bearer=token, timeout=15)
    except Exception:
        return []
    out = []
    for e in (d.get("items") or []):
        s, en = e.get("start") or {}, e.get("end") or {}
        out.append({"id": e.get("id", ""), "title": e.get("summary", ""),
                    "start": s.get("dateTime") or s.get("date") or "",
                    "end": en.get("dateTime") or en.get("date") or ""})
    return out


# ---- Sheets ---------------------------------------------------------------

def sheets_find(token: str, name: str) -> dict | None:
    for f in drive_search(token, name, 8):
        if "spreadsheet" in (f.get("mimeType") or ""):
            return f
    return None


def sheets_read(token: str, spreadsheet_id: str, a1: str = "A1:Z60") -> list[list]:
    d = safehttp.call(
        f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/"
        + urllib.parse.quote(a1, safe=""),
        method="GET", bearer=token, timeout=20)
    return d.get("values") or []


def sheets_append(token: str, spreadsheet_id: str, row: list, a1: str = "A1") -> dict:
    return safehttp.call(
        f"https://sheets.googleapis.com/v4/spreadsheets/{spreadsheet_id}/values/"
        + urllib.parse.quote(a1, safe="") + ":append?" + _q({
            "valueInputOption": "USER_ENTERED", "insertDataOption": "INSERT_ROWS"}),
        method="POST", bearer=token, timeout=20, payload={"values": [row]})


# ---- Contacts (People) ----------------------------------------------------

def contacts_search(token: str, query: str, n: int = 10) -> list[dict]:
    d = safehttp.call(
        "https://people.googleapis.com/v1/people:searchContacts?" + _q({
            "query": query, "pageSize": n,
            "readMask": "names,emailAddresses,phoneNumbers"}),
        method="GET", bearer=token, timeout=15)
    out = []
    for r in (d.get("results") or []):
        p = r.get("person") or {}
        out.append({
            "name": ((p.get("names") or [{}])[0]).get("displayName", ""),
            "email": ((p.get("emailAddresses") or [{}])[0]).get("value", ""),
            "phone": ((p.get("phoneNumbers") or [{}])[0]).get("value", "")})
    return out


# ---- Chat -----------------------------------------------------------------

def chat_spaces(token: str, n: int = 25) -> list[dict]:
    d = safehttp.call("https://chat.googleapis.com/v1/spaces?" + _q({"pageSize": n}),
                      method="GET", bearer=token, timeout=15)
    return [{"name": s.get("name", ""),
             "display": s.get("displayName", "") or s.get("name", "")}
            for s in (d.get("spaces") or [])]


def chat_messages(token: str, space: str, n: int = 12) -> list[dict]:
    d = safehttp.call(
        f"https://chat.googleapis.com/v1/{space}/messages?" + _q({"pageSize": n}),
        method="GET", bearer=token, timeout=15)
    return [{"text": m.get("text", ""),
             "sender": ((m.get("sender") or {}).get("displayName")
                        or (m.get("sender") or {}).get("name", "")),
             "time": m.get("createTime", "")}
            for m in (d.get("messages") or [])]


# ---- WRITES: every one is a DRAFT or a proposal, never an autonomous send --
#
# gmail_draft creates a Gmail DRAFT (unsent, lands in Ross's Drafts - he presses
# send). calendar_create/chat_post/etc. execute only from a confirmed path in the
# console. Nothing here sends or posts on its own; that line is the whole point.

def gmail_draft(token: str, to: str = "", subject: str = "", body: str = "",
                thread_id: str = "", in_reply_to: str = "") -> dict:
    import base64
    lines = []
    if to:
        lines.append(f"To: {to}")
    if subject:
        lines.append(f"Subject: {subject}")
    if in_reply_to:
        lines.append(f"In-Reply-To: {in_reply_to}")
        lines.append(f"References: {in_reply_to}")
    lines += ["Content-Type: text/plain; charset=UTF-8", "", body or ""]
    raw = base64.urlsafe_b64encode("\r\n".join(lines).encode("utf-8")).decode()
    message = {"raw": raw}
    if thread_id:
        message["threadId"] = thread_id
    return safehttp.call("https://gmail.googleapis.com/gmail/v1/users/me/drafts",
                         method="POST", bearer=token, timeout=20,
                         payload={"message": message})


def _addr_domains(value: str) -> set:
    """The email domains in a header value ('A <a@x.com>, b@y.org' -> {x.com,y.org})."""
    import re
    return {m.group(1).lower() for m in
            re.finditer(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})", value or "")}


def gmail_sent_to_domains(token: str, n: int = 25) -> set:
    """Domains Ross has SENT mail to - the 'people I actually reply to' signal the
    importance ranker seeds on. Reads recent Sent, pulls each To header, returns
    the set of recipient domains. Bounded (n messages) and cache it - it's the
    slow part of building the queue."""
    lst = safehttp.call(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages?" + _q({
            "maxResults": n, "q": "in:sent"}),
        method="GET", bearer=token, timeout=15)
    doms = set()
    for m in (lst.get("messages") or [])[:n]:
        mid = m.get("id")
        if not mid:
            continue
        try:
            md = safehttp.call(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{mid}?" + _q({
                    "format": "metadata"}) + "&metadataHeaders=To",
                method="GET", bearer=token, timeout=10)
        except Exception:
            continue
        for h in ((md.get("payload") or {}).get("headers") or []):
            if h.get("name", "").lower() == "to":
                doms |= _addr_domains(h.get("value", ""))
    return doms


def gmail_modify(token: str, message_id: str, *, add: list | None = None,
                 remove: list | None = None) -> dict:
    """Add/remove Gmail label ids on one message - the reversible primitive under
    archive (remove INBOX), star (add STARRED), mark-read (remove UNREAD) and
    spam (add SPAM, remove INBOX). A label change, never a delete."""
    if not message_id:
        return {}
    return safehttp.call(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}/modify",
        method="POST", bearer=token, timeout=15,
        payload={"addLabelIds": add or [], "removeLabelIds": remove or []})


def gmail_trash(token: str, message_id: str) -> dict:
    """Move a message to Trash - recoverable for 30 days. The permanent-delete
    endpoint (messages/{id} DELETE) is deliberately never wired here."""
    if not message_id:
        return {}
    return safehttp.call(
        f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}/trash",
        method="POST", bearer=token, timeout=15, payload={})


def gtasks_insert(token: str, title: str, notes: str = "") -> str:
    """Create a task in the user's DEFAULT Google Tasks list, so a '→ Task' in the
    console also lands in the phone's Tasks app. Returns the new task's id, or ''.
    Needs the tasks scope — without it the API 403s and this returns '' (the caller
    keeps the Rosco-side task regardless, so a missing scope never loses the to-do).
    """
    title = (title or "").strip()
    if not title:
        return ""
    body = {"title": title[:1024]}
    if notes:
        body["notes"] = notes[:8000]
    try:
        d = safehttp.call("https://tasks.googleapis.com/tasks/v1/lists/@default/tasks",
                          method="POST", bearer=token, payload=body, timeout=15)
    except Exception:
        return ""
    return (d.get("id", "") if isinstance(d, dict) else "") or ""


# Ross is in the St. Louis metro - Central. Calendar rejects a naive dateTime
# ("Missing time zone"), so every event carries the zone explicitly; a bare
# "3pm" is then read as 3pm Central, and a dateTime that already has an offset
# still resolves to the same instant.
CENTRAL_TZ = "America/Chicago"


def calendar_create(token: str, summary: str, start_iso: str, end_iso: str,
                    location: str = "", description: str = "",
                    tz: str = CENTRAL_TZ) -> dict:
    ev = {"summary": summary,
          "start": {"dateTime": start_iso, "timeZone": tz},
          "end": {"dateTime": end_iso, "timeZone": tz}}
    if location:
        ev["location"] = location
    if description:
        ev["description"] = description
    return safehttp.call(
        "https://www.googleapis.com/calendar/v3/calendars/primary/events",
        method="POST", bearer=token, timeout=20, payload=ev)


def chat_post(token: str, space: str, text: str) -> dict:
    return safehttp.call(
        f"https://chat.googleapis.com/v1/{space}/messages",
        method="POST", bearer=token, timeout=20, payload={"text": text})
