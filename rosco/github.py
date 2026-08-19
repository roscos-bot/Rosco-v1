"""GitHub - where what agents build lands, and how they propose a change.

Ross wants version control under the agents: when one builds something or needs
to change something, GitHub is there. In this system's terms that is a business
linked to a repo, a credential in the vault, and operations gated by grants -
the same spine as the tool registry, with one rule made structural.

AGENTS PROPOSE. THEY DO NOT MERGE. An agent may read a repo, open a branch,
commit to it, and open a pull request. It cannot merge to the default branch,
because merging is shipping, and shipping is a human's call. This is the
git-native form of the rule the whole system runs on - build anywhere, ship from
a person - and it is enforced by there being no merge operation here at all, not
by remembering not to call one. Ross merges on GitHub, where he can read the diff.

    Linking a repo is authority (only Ross, signed). It declares which business
    owns which repo and which vault secret holds the token.

    Reading is the capability 'git:read'. Proposing - branch, commit, PR - is
    'git:propose', a DO. grants.decide() gates both exactly as it gates the
    bound book: an agent gets them because Ross granted them, not because the
    repo exists.

    The token never leaves the vault in the clear. safehttp carries it to
    api.github.com over https, follows no redirect, and refuses an internal
    target - so a compromised or mistyped host cannot walk off with it.

    Every proposal is recorded (github.proposed) so the mesh and the log show
    what the agents have been building, not just that they can.
"""
from __future__ import annotations

import base64
import re
import secrets
import urllib.parse
from dataclasses import dataclass

from . import safehttp
from .keys import ROSS
from .models import SYSTEM
from .store import Log

API = "https://api.github.com"
GH_HEADERS = {"Accept": "application/vnd.github+json",
              "X-GitHub-Api-Version": "2022-11-28",
              "User-Agent": "rosco"}

CAP_READ = "git:read"
CAP_PROPOSE = "git:propose"     # branch + commit + PR. Never merge.


@dataclass
class Repo:
    business: str
    owner: str
    name: str
    default_branch: str
    token_secret: str
    note: str = ""
    linked: str = ""

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.name}"


class GitHub:
    """The repo registry and the propose-only operations, over the log."""

    def __init__(self, log: Log) -> None:
        self.log = log

    # ---- writing (authority) ---------------------------------------------

    def link(self, business: str, owner: str, name: str, *,
             default_branch: str = "main", token_secret: str = "github_token",
             note: str = "", by: str = ROSS) -> dict:
        """Point a business at a repo. Only Ross, and it is signed.

        Linking widens what the system can reach and act on, the same class of
        decision as a grant, so a node without Ross's key cannot introduce one.
        """
        if by != ROSS:
            raise PermissionError(f"only Ross links a repo; {by!r} tried {owner}/{name}")
        if not all((business, owner, name)):
            raise ValueError("a link needs a business, an owner and a repo name")
        # token_secret is the NAME of a vault entry, not the token. A real token
        # value here would be written to the plaintext log - the one thing the
        # vault exists to prevent - so refuse anything that looks like a credential.
        if re.match(r"^(gh[pousr]_|github_pat_)", (token_secret or "").strip()):
            raise ValueError(
                "token_secret is the NAME of a vault secret (default 'github_token'), "
                "not the token itself. Store the token with `rosco secret set system "
                "github_token`, then link with the default name — never pass the token "
                "here, or it lands in the log in the clear.")
        return self.log.append(
            "github.linked",
            {"business": business.strip().lower(), "owner": owner.strip(),
             "name": name.strip(), "default_branch": default_branch,
             "token_secret": token_secret, "note": note},
            subject=business.strip().lower(), actor=ROSS,
        )

    def unlink(self, business: str, *, by: str = ROSS) -> dict:
        if by != ROSS:
            raise PermissionError(f"only Ross unlinks a repo; {by!r} tried")
        return self.log.append("github.unlinked", {"business": business.strip().lower()},
                               subject=business.strip().lower(), actor=ROSS)

    # ---- reading ---------------------------------------------------------

    def all(self) -> list[Repo]:
        live: dict[str, Repo] = {}
        gone: set[str] = set()
        for ev in self.log.replay(kind="github.linked"):
            b = ev["body"]
            live[b["business"]] = Repo(
                business=b["business"], owner=b["owner"], name=b["name"],
                default_branch=b.get("default_branch", "main"),
                token_secret=b.get("token_secret", "github_token"),
                note=b.get("note", ""), linked=ev["ts"])
        for ev in self.log.replay(kind="github.unlinked"):
            gone.add(ev["body"]["business"])
        return [r for biz, r in live.items() if biz not in gone]

    def find(self, business: str) -> Repo | None:
        b = (business or "").strip().lower()
        for r in self.all():
            if r.business == b:
                return r
        return None

    # ---- operations ------------------------------------------------------
    #
    # Each reads the token from the vault at the moment of the call and passes
    # it through safehttp. The caller is responsible for having checked the grant
    # (git:read for reads, git:propose for the rest) - the doorway/console does
    # that via grants.decide() before ever getting here, exactly as with a tool.

    def _repo(self, business: str) -> Repo:
        r = self.find(business)
        if r is None:
            raise ValueError(f"no repo linked for {business!r}")
        return r

    def _token(self, r: Repo, vault) -> str:
        tok = vault.get_secret(SYSTEM, r.token_secret)
        if not tok:
            raise RuntimeError(
                f"{r.slug} needs the vault secret system:{r.token_secret}, which is "
                f"not set. `rosco secret set system {r.token_secret}`")
        return tok

    def read_file(self, business: str, path: str, *, vault, ref: str = "") -> str:
        r = self._repo(business)
        tok = self._token(r, vault)
        ref = ref or r.default_branch
        url = f"{API}/repos/{r.owner}/{r.name}/contents/{path}?ref={ref}"
        got = safehttp.call(url, method="GET", bearer=tok, headers=GH_HEADERS)
        return base64.b64decode(got.get("content", "")).decode("utf-8", "replace")

    def propose(self, business: str, branch: str, path: str, content: str,
                message: str, *, vault, agent: str = "rosco",
                pr_title: str = "", pr_body: str = "") -> dict:
        """Open a branch, commit one file to it, and open a PR. Never merge.

        The whole propose step is one call so an agent cannot leave a half-made
        change: a branch off the default head, a commit of the file, a PR back to
        the default branch for a human to read and merge.
        """
        r = self._repo(business)
        tok = self._token(r, vault)
        h = dict(GH_HEADERS)

        # 1. base head
        base = safehttp.call(f"{API}/repos/{r.owner}/{r.name}/git/ref/heads/{r.default_branch}",
                             method="GET", bearer=tok, headers=h)
        base_sha = (base.get("object") or {}).get("sha")
        if not base_sha:
            raise RuntimeError(f"could not read {r.default_branch} head of {r.slug}")

        # 2. branch (idempotent-ish: a duplicate ref errors, which surfaces)
        safehttp.call(f"{API}/repos/{r.owner}/{r.name}/git/refs",
                      method="POST", bearer=tok, headers=h,
                      payload={"ref": f"refs/heads/{branch}", "sha": base_sha})

        # 3. commit the file onto the branch
        safehttp.call(f"{API}/repos/{r.owner}/{r.name}/contents/{path}",
                      method="PUT", bearer=tok, headers=h,
                      payload={"message": message, "branch": branch,
                               "content": base64.b64encode(content.encode()).decode()})

        # 4. the PR - back to default, for a human to merge
        pr = safehttp.call(f"{API}/repos/{r.owner}/{r.name}/pulls",
                           method="POST", bearer=tok, headers=h,
                           payload={"title": pr_title or message, "head": branch,
                                    "base": r.default_branch, "body": pr_body or
                                    f"Proposed by {agent} via Rosco."})
        url = pr.get("html_url", "")
        self.log.append("github.proposed",
                        {"business": business, "agent": agent, "branch": branch,
                         "path": path, "pr": url, "message": message[:200]},
                        subject=business, actor=agent)
        return {"pr": url, "branch": branch}


# ---- direct-by-repo connector (what the console chat uses) -----------------
#
# The GitHub class above is keyed by BUSINESS (a linked repo, gated by grants).
# The chat, though, browses whatever the stored token can reach - the way the
# Google connector reads the account it is signed into. These take (token, owner,
# repo) directly, read over safehttp, and the one write still only OPENS a PR;
# there is no merge here either. The token is 'github_token' in the system vault.

TOKEN_SECRET = "github_token"


def gh_token(vault) -> str:
    return (vault.get_secret(SYSTEM, TOKEN_SECRET) or "") if vault else ""


def gh_repos(token: str, n: int = 30) -> list[dict]:
    d = safehttp.call(
        f"{API}/user/repos?" + urllib.parse.urlencode({
            "per_page": min(n, 100), "sort": "pushed",
            "affiliation": "owner,collaborator,organization_member"}),
        method="GET", bearer=token, headers=GH_HEADERS)
    return [{"full": r.get("full_name", ""), "name": r.get("name", ""),
             "owner": (r.get("owner") or {}).get("login", ""),
             "private": bool(r.get("private")), "desc": r.get("description") or "",
             "default": r.get("default_branch", "main"),
             "pushed": (r.get("pushed_at") or "")[:10]}
            for r in (d if isinstance(d, list) else [])]


def gh_find_repo(token: str, name: str) -> dict | None:
    want = (name or "").strip().lower().lstrip("/")
    repos = gh_repos(token, 100)
    for r in repos:                       # exact name/full-name first
        if r["name"].lower() == want or r["full"].lower() == want:
            return r
    for r in repos:                       # then a suffix / contains match
        if want and (r["full"].lower().endswith("/" + want) or want in r["name"].lower()):
            return r
    return None


def gh_default_branch(token: str, owner: str, repo: str) -> str:
    d = safehttp.call(f"{API}/repos/{owner}/{repo}", method="GET",
                      bearer=token, headers=GH_HEADERS)
    return d.get("default_branch", "main")


def gh_read(token: str, owner: str, repo: str, path: str, ref: str = "",
            max_chars: int = 12000):
    """A file's text, or a directory listing. Returns (content|None, listing|None)."""
    url = f"{API}/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}"
    if ref:
        url += "?ref=" + urllib.parse.quote(ref, safe="")
    got = safehttp.call(url, method="GET", bearer=token, headers=GH_HEADERS)
    if isinstance(got, list):
        return None, [{"name": x.get("name", ""), "type": x.get("type", ""),
                       "path": x.get("path", "")} for x in got]
    text = base64.b64decode(got.get("content", "") or "").decode("utf-8", "replace")
    return text[:max_chars], None


def gh_tree(token: str, owner: str, repo: str, ref: str = "", limit: int = 300) -> list[str]:
    ref = ref or gh_default_branch(token, owner, repo)
    d = safehttp.call(
        f"{API}/repos/{owner}/{repo}/git/trees/{urllib.parse.quote(ref, safe='')}?recursive=1",
        method="GET", bearer=token, headers=GH_HEADERS)
    return [t.get("path", "") for t in (d.get("tree") or [])
            if t.get("type") == "blob"][:limit]


def gh_search_code(token: str, owner: str, repo: str, q: str, n: int = 10) -> list[dict]:
    d = safehttp.call(
        f"{API}/search/code?" + urllib.parse.urlencode({
            "q": f"{q} repo:{owner}/{repo}", "per_page": n}),
        method="GET", bearer=token, headers=GH_HEADERS)
    return [{"path": i.get("path", ""), "name": i.get("name", "")}
            for i in (d.get("items") or [])]


def gh_open_pr(token: str, owner: str, repo: str, path: str, content: str,
               message: str, *, branch: str = "", pr_title: str = "",
               pr_body: str = "") -> dict:
    """Branch off default, commit ONE file, open a PR back to default. No merge.

    If the file already exists on the default branch its sha is supplied so the
    commit updates rather than 400s. A human reads the diff and merges on GitHub.
    """
    h = dict(GH_HEADERS)
    default = gh_default_branch(token, owner, repo)
    branch = branch or ("rosco/" + urllib.parse.quote(message[:24].strip().replace(" ", "-"), safe="") + "-" + secrets.token_hex(3))
    base = safehttp.call(f"{API}/repos/{owner}/{repo}/git/ref/heads/{default}",
                         method="GET", bearer=token, headers=h)
    base_sha = (base.get("object") or {}).get("sha")
    if not base_sha:
        raise RuntimeError(f"could not read {default} head of {owner}/{repo}")
    safehttp.call(f"{API}/repos/{owner}/{repo}/git/refs", method="POST",
                  bearer=token, headers=h,
                  payload={"ref": f"refs/heads/{branch}", "sha": base_sha})
    put = {"message": message, "branch": branch,
           "content": base64.b64encode(content.encode()).decode()}
    try:                                   # existing file needs its blob sha to update
        cur = safehttp.call(
            f"{API}/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}?ref={default}",
            method="GET", bearer=token, headers=h)
        if isinstance(cur, dict) and cur.get("sha"):
            put["sha"] = cur["sha"]
    except Exception:
        pass
    safehttp.call(f"{API}/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}",
                  method="PUT", bearer=token, headers=h, payload=put)
    pr = safehttp.call(f"{API}/repos/{owner}/{repo}/pulls", method="POST",
                       bearer=token, headers=h,
                       payload={"title": pr_title or message, "head": branch,
                                "base": default, "body": pr_body or "Proposed via Rosco."})
    return {"pr": pr.get("html_url", ""), "branch": branch}


def gh_open_pr_multi(token: str, owner: str, repo: str, files: list, message: str, *,
                     branch: str = "", pr_title: str = "", pr_body: str = "") -> dict:
    """Branch off default, commit SEVERAL files onto it, open ONE PR back to default.
    No merge — the same rule as gh_open_pr, widened so a real fix that spans files is
    expressible. `files` is [{path, content}]. Each file is committed with its blob sha
    ON THE BRANCH so an update doesn't 400. A human reads the diff and merges on GitHub."""
    if not files:
        raise ValueError("no files to propose")
    h = dict(GH_HEADERS)
    default = gh_default_branch(token, owner, repo)
    branch = branch or ("rosco/" + urllib.parse.quote(message[:24].strip().replace(" ", "-"), safe="") + "-" + secrets.token_hex(3))
    base = safehttp.call(f"{API}/repos/{owner}/{repo}/git/ref/heads/{default}",
                         method="GET", bearer=token, headers=h)
    base_sha = (base.get("object") or {}).get("sha")
    if not base_sha:
        raise RuntimeError(f"could not read {default} head of {owner}/{repo}")
    safehttp.call(f"{API}/repos/{owner}/{repo}/git/refs", method="POST",
                  bearer=token, headers=h,
                  payload={"ref": f"refs/heads/{branch}", "sha": base_sha})
    for f in files:
        path = str(f.get("path", "")).strip()
        content = f.get("content", "")
        if not path:
            raise ValueError("a proposed file needs a path")
        put = {"message": message, "branch": branch,
               "content": base64.b64encode(content.encode()).decode()}
        try:                               # the file's sha ON THE BRANCH, so a PUT updates
            cur = safehttp.call(
                f"{API}/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}"
                f"?ref={urllib.parse.quote(branch, safe='')}",
                method="GET", bearer=token, headers=h)
            if isinstance(cur, dict) and cur.get("sha"):
                put["sha"] = cur["sha"]
        except Exception:
            pass
        safehttp.call(f"{API}/repos/{owner}/{repo}/contents/{urllib.parse.quote(path)}",
                      method="PUT", bearer=token, headers=h, payload=put)
    pr = safehttp.call(f"{API}/repos/{owner}/{repo}/pulls", method="POST",
                       bearer=token, headers=h,
                       payload={"title": pr_title or message, "head": branch,
                                "base": default, "body": pr_body or "Proposed via Rosco."})
    return {"pr": pr.get("html_url", ""), "branch": branch,
            "files": [str(f.get("path", "")) for f in files]}
