"""RustXec step 1, fetch (docs/build-plan.md section 7.4): resolve every `fix commit links` entry
of metadata.csv to a repository and a fix commit, and materialise two snapshots per case.

    eval/corpus/rustxec/
        api-cache.json        every GitHub/GitLab API response, keyed by URL; never re-requested
        fetch.json            one record per case: repo, revisions, member, or the failure reason
        <id>/repo.git         bare repository holding a shallow fetch of the fix commit
        <id>/vuln             worktree at the fix commit's first parent (the vulnerable snapshot)
        <id>/fixed            worktree at the fix commit

Link kinds: a commit URL is used as is (a short hash is completed through the API); a pull request
goes through the GitHub REST API to `merge_commit_sha`; a GitLab merge request through the GitLab
API; anything else needs an entry in MANUAL below. A pull or merge request that upstream never
merged is used as it stands: its head commit is the fixed snapshot, its base the vulnerable one,
and the record says so. The vulnerable revision is otherwise the fix commit's first parent. When
a pull request was rebase-merged as several commits, it is the commit before the first of them;
the script tells that apart from a squash by comparing the diff size against the pull request's
own additions/deletions and records which rule it used.

Nothing from a cloned repository is built or executed. git runs without the user's or the system's
configuration (no hooks, no filters, no credential helpers, no LFS smudge), submodules are never
initialised, symlinks are checked out as plain files, and Cargo.toml files are read through
`git show`, not from the worktree.

The script is resumable: a case whose record is `ok` and whose worktrees are at the recorded
revisions is skipped. A failure is recorded with its reason and the run goes on.

    backend/.venv/bin/python eval/rustxec/fetch.py [--resolve-only] [--force] [case id ...]
"""
import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_METADATA = HERE / "metadata.csv"
DEFAULT_CORPUS = HERE.parent / "corpus" / "rustxec"

# Links that cannot be resolved mechanically, resolved by hand: `link` replaces the link of the
# index and is then resolved like any other, `why` says where it came from.
MANUAL: dict[str, dict[str, str]] = {
    "RUSTSEC-2021-0118": {
        "link": "https://github.com/apache/arrow-rs/pull/810",
        "why": "the index links umbrella issue #817, which three pull requests worked off (#822 try_new and "
               "unsafe new_unchecked, #810 buffer validation, #921 full validation, which closed it). #810 "
               "'Validate arguments to ArrayData::new and null bit buffer and buffers' adds the buffer-length "
               "check that the advisory (issue #774) says is missing. Chosen by hand on 2026-11-11 from the "
               "issue timeline; a judgment, to be confirmed",
    },
}

# Cases whose Cargo.toml cannot be found by package name at either revision, with the reason.
MEMBER_OVERRIDE: dict[str, dict[str, str]] = {
    "RUSTSEC-2021-0011": {
        "member": "ocl",
        "why": "fil-ocl is a fork of ocl; the fix link points at the upstream repository, where the package "
               "is named `ocl` and the fixed file is ocl/src/standard/event.rs",
    },
    "RUSTSEC-2021-0143": {
        "member": "",
        "why": "the repository's only Cargo.toml names the package `exif`; it is published as kamadak-exif",
    },
}

GIT_ENV = {
    **os.environ,
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_LFS_SKIP_SMUDGE": "1",
    "GIT_ASKPASS": "true",
}
GIT_OPTS = [
    "-c", "core.hooksPath=" + os.devnull,
    "-c", "core.symlinks=false",
    "-c", "core.fsmonitor=false",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "submodule.recurse=false",
    "-c", "advice.detachedHead=false",
    "-c", "gc.auto=0",
]

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class Failure(Exception):
    """A case could not be resolved or fetched; the message is the recorded reason."""


def git(args: list[str], cwd: Path | None = None, timeout: int = 900) -> str:
    proc = subprocess.run(["git", *GIT_OPTS, *args], cwd=cwd, env=GIT_ENV, capture_output=True,
                          text=True, errors="replace", timeout=timeout, check=False)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-3:]
        raise Failure(f"git {' '.join(args[:3])} failed: {' / '.join(tail)}")
    return proc.stdout


class ApiCache:
    """GET a JSON API once and keep the answer (including 404s) on disk."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, dict] = json.loads(path.read_text()) if path.exists() else {}

    def get(self, url: str) -> dict:
        if url not in self.data:
            self.data[url] = self._request(url)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1, sort_keys=True))
            tmp.replace(self.path)
        entry = self.data[url]
        if entry["status"] != 200:
            raise Failure(f"API {url} answered {entry['status']}: {entry.get('message', '')}")
        return entry["body"]

    @staticmethod
    def _request(url: str) -> dict:
        req = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "rustxec-fetch (thesis evaluation)"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return {"status": 200, "body": json.load(resp)}
        except urllib.error.HTTPError as err:
            text = err.read().decode("utf-8", "replace")[:300]
            limited = err.headers.get("x-ratelimit-remaining") == "0" or err.code == 429
            if limited:  # transient: do not cache
                raise Failure(f"API rate limit reached at {url}; rerun after the limit resets") from err
            return {"status": err.code, "message": text}
        except (urllib.error.URLError, TimeoutError, OSError) as err:  # transient: do not cache
            raise Failure(f"network error at {url}: {err}") from err


def classify(link: str) -> tuple[str, dict[str, str]]:
    """Return (kind, parts) for a fix link."""
    patterns = [
        ("github-pr-commit", r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)/commits/(?P<sha>[0-9a-f]{7,40})"),
        ("github-commit", r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-f]{7,40})"),
        ("github-pr", r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<number>\d+)"),
        ("github-other", r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"),
        ("gitlab-commit", r"^https://gitlab\.com/(?P<path>.+?)/-/commit/(?P<sha>[0-9a-f]{7,40})"),
        ("gitlab-mr", r"^https://gitlab\.com/(?P<path>.+?)/-/merge_requests/(?P<number>\d+)"),
        ("gitlab-other", r"^https://gitlab\.com/(?P<path>.+?)/-/"),
    ]
    for kind, pattern in patterns:
        m = re.match(pattern, link)
        if m:
            return kind, m.groupdict()
    return "other", {}


def resolve(case_id: str, link: str, api: ApiCache) -> dict:
    """Turn a fix link into {repo, fixed_rev, and how the vulnerable revision is to be found}."""
    kind, p = classify(link)
    out: dict = {"link_kind": kind}
    if case_id in MANUAL:
        out["manual"] = MANUAL[case_id]
        kind, p = classify(MANUAL[case_id]["link"])
    if kind in ("github-commit", "github-pr-commit"):
        out["repo"] = f"https://github.com/{p['owner']}/{p['repo']}"
        sha = p["sha"]
        if not FULL_SHA.match(sha):
            body = api.get(f"https://api.github.com/repos/{p['owner']}/{p['repo']}/commits/{sha}")
            sha = body["sha"]
            out["resolved_by"] = f"short hash {p['sha']} completed through the GitHub API"
        else:
            out["resolved_by"] = "commit URL"
        out["fixed_rev"] = sha
    elif kind == "github-pr":
        out["repo"] = f"https://github.com/{p['owner']}/{p['repo']}"
        body = api.get(f"https://api.github.com/repos/{p['owner']}/{p['repo']}/pulls/{p['number']}")
        out["pr"] = {"number": int(p["number"]), "merged": body.get("merged"), "commits": body.get("commits"),
                     "additions": body.get("additions"), "deletions": body.get("deletions"),
                     "changed_files": body.get("changed_files"), "base_ref": (body.get("base") or {}).get("ref"),
                     "head_sha": (body.get("head") or {}).get("sha"), "merged_at": body.get("merged_at")}
        if body.get("merged") and body.get("merge_commit_sha"):
            out["fixed_rev"] = body["merge_commit_sha"]
            out["resolved_by"] = f"merge_commit_sha of pull request #{p['number']}"
        elif out["pr"]["head_sha"]:
            # Upstream never merged the fix the index points at: the pull request's head commit is
            # the fixed snapshot, and vulnerable_rev() walks back over the pull request's commits.
            out["fixed_rev"] = out["pr"]["head_sha"]
            out["resolved_by"] = (f"head commit of unmerged pull request #{p['number']} (state {body.get('state')}); "
                                  "the fix is not in the upstream history")
        else:
            raise Failure(f"pull request #{p['number']} is unmerged and has no head commit")
    elif kind == "gitlab-commit":
        out["repo"] = f"https://gitlab.com/{p['path']}"
        sha = p["sha"]
        if not FULL_SHA.match(sha):
            project = urllib.parse.quote(p["path"], safe="")
            sha = api.get(f"https://gitlab.com/api/v4/projects/{project}/repository/commits/{sha}")["id"]
        out.update(fixed_rev=sha, resolved_by="commit URL")
    elif kind == "gitlab-mr":
        out["repo"] = f"https://gitlab.com/{p['path']}"
        project = urllib.parse.quote(p["path"], safe="")
        body = api.get(f"https://gitlab.com/api/v4/projects/{project}/merge_requests/{p['number']}")
        refs = body.get("diff_refs") or {}
        out["mr"] = {"number": int(p["number"]), "state": body.get("state"),
                     "merge_commit_sha": body.get("merge_commit_sha"), "squash_commit_sha": body.get("squash_commit_sha"),
                     "sha": body.get("sha"), "base_sha": refs.get("base_sha"), "start_sha": refs.get("start_sha")}
        if body.get("state") != "merged":
            if not (body.get("sha") and refs.get("base_sha")):
                raise Failure(f"merge request !{p['number']} is {body.get('state')} and has no head or base commit")
            out.update(fixed_rev=body["sha"], vuln_rev_manual=refs["base_sha"],
                       resolved_by=f"head commit of unmerged merge request !{p['number']} (state {body.get('state')}), "
                                   "base from diff_refs; the fix is not in the upstream history")
        elif body.get("merge_commit_sha"):
            out.update(fixed_rev=body["merge_commit_sha"], resolved_by=f"merge_commit_sha of merge request !{p['number']}")
        elif body.get("squash_commit_sha"):
            out.update(fixed_rev=body["squash_commit_sha"], resolved_by=f"squash_commit_sha of merge request !{p['number']}")
        elif body.get("sha") and refs.get("base_sha"):
            # Fast-forward merge: the head of the merge request is on the target branch and the
            # vulnerable revision is the merge request's base.
            out.update(fixed_rev=body["sha"], vuln_rev_manual=refs["base_sha"],
                       resolved_by=f"fast-forwarded merge request !{p['number']}: head sha, base from diff_refs")
        else:
            raise Failure(f"merge request !{p['number']} has no merge, squash or head commit")
    else:
        raise Failure(f"link kind {kind} cannot be resolved mechanically and has no MANUAL entry: {link}")
    return out


def numstat(repo: Path, old: str, new: str) -> tuple[int, int]:
    added = deleted = 0
    for line in git(["diff", "--numstat", old, new], cwd=repo).splitlines():
        a, d, _ = line.split("\t", 2)
        if a != "-":
            added += int(a)
            deleted += int(d)
    return added, deleted


def shallow_fetch(repo: Path, url: str, sha: str, depth: int) -> None:
    git(["fetch", "--quiet", "--no-tags", "--no-recurse-submodules", f"--depth={depth}", url + ".git", sha], cwd=repo)


def vulnerable_rev(repo: Path, url: str, fixed: str, info: dict) -> tuple[str, str]:
    """Return (vuln sha, the rule that picked it)."""
    if info.get("vuln_rev_manual"):
        vuln = info["vuln_rev_manual"]
        try:
            git(["cat-file", "-e", vuln + "^{commit}"], cwd=repo)
        except Failure:
            shallow_fetch(repo, url, vuln, 1)
        return vuln, "given by the manual entry or the merge request base"
    parents = git(["rev-list", "--parents", "-n", "1", fixed], cwd=repo).split()[1:]
    if not parents:
        raise Failure("fix commit has no parent")
    first = parents[0]
    if len(parents) > 1:
        return first, f"first parent of a merge commit with {len(parents)} parents"
    pr = info.get("pr")
    if not pr or (pr.get("commits") or 1) <= 1:
        return first, "parent of the fix commit"
    want = (pr["additions"], pr["deletions"])
    got = numstat(repo, first, fixed)
    if got == want:
        return first, f"parent of the squash commit (diff +{got[0]}/-{got[1]} equals the pull request's)"
    count = pr["commits"]
    shallow_fetch(repo, url, fixed, count + 1)
    base = git(["rev-parse", "--verify", f"{fixed}~{count}"], cwd=repo).strip()
    got_all = numstat(repo, base, fixed)
    if got_all == want:
        return base, f"rebase-merged pull request of {count} commits: the commit before the first of them"
    raise Failure(f"pull request #{pr['number']} has {count} commits and +{want[0]}/-{want[1]}, but the merge commit "
                  f"alone is +{got[0]}/-{got[1]} and the last {count} commits are +{got_all[0]}/-{got_all[1]}; "
                  "the vulnerable revision has to be chosen by hand")


def find_member(repo: Path, rev: str, package: str) -> tuple[str | None, list[str]]:
    """Directory of the Cargo.toml whose [package] name is `package` ("" = repository root)."""
    names = git(["ls-tree", "-r", "--name-only", rev], cwd=repo).splitlines()
    hits = []
    for path in names:
        if path != "Cargo.toml" and not path.endswith("/Cargo.toml"):
            continue
        try:
            manifest = tomllib.loads(git(["show", f"{rev}:{path}"], cwd=repo))
        except (tomllib.TOMLDecodeError, Failure):
            continue
        name = (manifest.get("package") or {}).get("name")
        if isinstance(name, str) and name == package:
            hits.append(path.rpartition("/")[0])
    hits.sort(key=lambda d: (d.count("/") + bool(d), d))
    return (hits[0] if hits else None), hits[1:]


def worktree_rev(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    try:
        return git(["rev-parse", "HEAD"], cwd=path).strip()
    except Failure:
        return None


def materialise(case_dir: Path, info: dict, package: str) -> dict:
    repo = case_dir / "repo.git"
    url, fixed = info["repo"], info["fixed_rev"]
    if not (repo / "HEAD").exists():
        repo.mkdir(parents=True, exist_ok=True)
        git(["init", "--quiet", "--bare", "."], cwd=repo)
    try:
        git(["cat-file", "-e", fixed + "^{commit}"], cwd=repo)
        git(["rev-parse", "--verify", fixed + "^1"], cwd=repo)
    except Failure:
        shallow_fetch(repo, url, fixed, 2)
    if git(["rev-parse", "--verify", fixed + "^{commit}"], cwd=repo).strip() != fixed:
        raise Failure(f"{fixed} did not resolve to itself after the fetch")
    vuln, rule = vulnerable_rev(repo, url, fixed, info)
    git(["worktree", "prune"], cwd=repo)
    for name, rev in (("vuln", vuln), ("fixed", fixed)):
        tree = case_dir / name
        if worktree_rev(tree) == rev:
            continue
        if tree.exists():
            shutil.rmtree(tree)
            git(["worktree", "prune"], cwd=repo)
        git(["worktree", "add", "--quiet", "--detach", "--force", str(tree), rev], cwd=repo)
    out = {"vuln_rev": vuln, "vuln_rule": rule}
    if case_dir.name in MEMBER_OVERRIDE:
        out["member"] = MEMBER_OVERRIDE[case_dir.name]["member"]
        out["member_note"] = "manual: " + MEMBER_OVERRIDE[case_dir.name]["why"]
        return out
    member, others = find_member(repo, vuln, package)
    if member is None:
        member, others = find_member(repo, fixed, package)
        if member is not None:
            out["member_note"] = "package name found at the fixed revision only"
    if member is None:
        out["member"] = None
        out["member_note"] = f"no Cargo.toml with [package] name = \"{package}\" at either revision"
    else:
        out["member"] = member
        if others:
            out["member_alternatives"] = others
    return out


def is_done(record: dict | None, case_dir: Path) -> bool:
    return bool(record and record.get("status") == "ok"
                and worktree_rev(case_dir / "vuln") == record.get("vuln_rev")
                and worktree_rev(case_dir / "fixed") == record.get("fixed_rev"))


def save(path: Path, records: dict[str, dict]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(records, indent=1, sort_keys=True) + "\n")
    tmp.replace(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("ids", nargs="*", help="case ids (default: all)")
    ap.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    ap.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    ap.add_argument("--resolve-only", action="store_true", help="resolve links, do not fetch")
    ap.add_argument("--force", action="store_true", help="redo cases that are already ok")
    args = ap.parse_args()

    args.corpus.mkdir(parents=True, exist_ok=True)
    api = ApiCache(args.corpus / "api-cache.json")
    record_path = args.corpus / "fetch.json"
    records: dict[str, dict] = json.loads(record_path.read_text()) if record_path.exists() else {}
    with args.metadata.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))

    for row in rows:
        case_id, package = row["id"], row["package"]
        if args.ids and case_id not in args.ids:
            continue
        case_dir = args.corpus / case_id
        if not args.force and not args.resolve_only and is_done(records.get(case_id), case_dir):
            continue
        links = row["fix commit links"].split()
        record: dict = {"id": case_id, "package": package, "link": links[0] if links else None}
        if len(links) > 1:
            record["extra_links"] = links[1:]
        try:
            if not links:
                raise Failure("no fix link in metadata.csv")
            record.update(resolve(case_id, links[0], api))
            if not args.resolve_only:
                record.update(materialise(case_dir, record, package))
            record["status"] = "resolved" if args.resolve_only else "ok"
        except Failure as err:
            record.update(status="failed", reason=str(err))
        except subprocess.TimeoutExpired as err:
            record.update(status="failed", reason=f"timeout: {' '.join(map(str, err.cmd[-4:]))}")
        records[case_id] = record
        save(record_path, records)
        detail = record.get("reason") or f"{record.get('fixed_rev', '')[:12]} member={record.get('member')!r}"
        print(f"{case_id}  {package:22} {record['status']:8} {detail}", flush=True)

    ok = sum(r.get("status") == "ok" for r in records.values())
    failed = [r for r in records.values() if r.get("status") == "failed"]
    print(f"\n{ok} ok, {len(failed)} failed, {len(rows)} cases in the index")
    for r in failed:
        print(f"  {r['id']}  {r['package']}: {r['reason']}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
