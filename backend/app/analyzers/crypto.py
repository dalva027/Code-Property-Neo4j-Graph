"""Class C: cryptography and secrets (docs/build-plan.md section 3).

The patterns live in the catalogue (weak_crypto.yaml, secret_patterns.yaml). Call sites that match
the catalogue are `Call` nodes, item paths passed as values are `External` nodes reached by
REFERENCES, and secret-looking string literals are redacted `Literal` nodes.

With the extractor's data-flow graph four rules also look at what flows where (phase 3): a weak
hash is an error when a password-named variable feeds it (C1); a password feeding any
general-purpose digest is its own finding (C2); a non-cryptographic RNG is an error when its
output ends up in a key, token, nonce or salt (C3); and a nonce built from a constant is an
insecure mode (C6). Without the graph those forms are silent and the rest is unchanged.
"""
import json
import re
from typing import Any

from app.analyzers.base import Analyzer, register
from app.graph.repository import GraphRepository
from app.models.analysis import Category, Confidence, Finding, Severity
from app.rules import Match, load_catalogue

# Every catalogue-matching call site and referenced item of a project, with its literal arguments.
SITES = """
MATCH (f:Function {project_id: $pid})-[:HAS_CALL]->(c:Call {subkind: 'call'})
WHERE NOT coalesce(f.in_test, false)
RETURN f.id AS fn, f.qualified_name AS qname, c.id AS id, c.callee_path AS path, c.file AS file,
       c.line_start AS line, c.literal_args AS literal_args, 'call' AS how
UNION ALL
MATCH (f:Function {project_id: $pid})-[r:REFERENCES]->(e:External)
WHERE NOT coalesce(f.in_test, false)
RETURN f.id AS fn, f.qualified_name AS qname, e.id AS id, e.path AS path, f.file AS file,
       r.line AS line, '[]' AS literal_args, 'reference' AS how
"""
# Variables that flow into a call site within a few steps (`password` -> as_bytes() -> digest()).
FEEDERS = """
UNWIND $ids AS id
MATCH (c:Call {id: id})
MATCH (v:Var)-[:FLOWS_TO|PASSES|RETURNS_TO*1..4]->(c)
RETURN c.id AS site, collect(DISTINCT v.name) AS names
"""
# Variables a call site's result flows into (`SmallRng::..` -> rng -> gen() -> token).
RECEIVERS = """
UNWIND $ids AS id
MATCH (c:Call {id: id})
MATCH (c)-[:FLOWS_TO|PASSES|RETURNS_TO*1..5]->(v:Var)
RETURN c.id AS site, collect(DISTINCT v.name) AS names
"""
# Locals passed to a call that nothing ever flows into: they hold a constant.
CONSTANT_ARGS = """
UNWIND $ids AS id
MATCH (c:Call {id: id})
MATCH (v:Var {subkind: 'local'})-[l:FLOWS_TO]->(c)
WHERE any(x IN l.vias WHERE x STARTS WITH 'arg:')
  AND NOT EXISTS { ()-[:FLOWS_TO|PASSES|RETURNS_TO]->(v) }
RETURN c.id AS site, collect(DISTINCT v.name) AS names
"""
_INT = re.compile(r"^(0x[0-9a-fA-F]+|0o[0-7]+|0b[01]+|[0-9]+)")
CRATE_USES = """
MATCH (file:File {project_id: $pid}) WHERE file.uses_crates IS NOT NULL AND NOT coalesce(file.in_test, false)
RETURN file.id AS id, file.file AS file, file.uses_crates AS crates
"""


def _literals(row: dict[str, Any]) -> dict[int, tuple[str, str]]:
    """{argument index: (kind, text)} from a Call node's literal_args JSON."""
    try:
        return {int(i): (k, t) for i, k, t in json.loads(row["literal_args"] or "[]")}
    except (ValueError, TypeError):
        return {}


def _int(text: str) -> int | None:
    """Parse a Rust integer literal: `100_000`, `32u32`, `0x10`."""
    match = _INT.match(text.replace("_", ""))
    return int(match.group(1), 0) if match else None


class _CryptoRule(Analyzer):
    category = Category.crypto
    languages = ("rust",)
    group: str = ""

    async def sites(self, repo: GraphRepository, project_id: str) -> list[tuple[dict[str, Any], list[Match]]]:
        """Call sites and referenced items that match this rule's group, in source order.

        A site that matches only wide entries (a whole crate such as `md5`, or `SmallRng::*`) is
        left out when its function already has a site for the same entry. With resolved receiver types
        `hasher.update()` and `rng.gen()` are known to belong to the flagged crate or type too, and
        three findings for one use of SHA-1 would say nothing more than one.
        """
        matcher = load_catalogue().matcher()
        found = []
        seen: set[tuple[str, str]] = set()
        rows = await repo.query(SITES, pid=project_id)
        for r in sorted(rows, key=lambda r: (r["file"] or "", r["line"] or 0, r["id"])):
            hits = [m for m in matcher.match(r["path"], "weak_crypto") if m.group == self.group]
            if not hits:
                continue
            wide = {(r["fn"], m.entry.path) for m in hits if m.entry.kind == "crate" or m.entry.last == "*"}
            if len(wide) == len(hits) and wide <= seen:
                continue
            seen |= wide
            found.append((r, hits))
        return found

    def site_finding(self, project_id: str, r: dict[str, Any], message: str, severity: Severity | None = None,
                     confidence: Confidence = Confidence.high) -> Finding:
        return self.finding(project_id, message, node_id=r["fn"], file=r["file"], line=r["line"],
                            severity=severity, confidence=confidence, evidence=[r["fn"], r["id"]])

    async def crate_use_findings(self, repo: GraphRepository, project_id: str, crates: set[str],
                                 skip_files: set[str], what: str) -> list[Finding]:
        """Info findings for files that `use` a flagged crate without a matched call site."""
        findings = []
        for r in await repo.query(CRATE_USES, pid=project_id):
            if r["file"] in skip_files:
                continue
            used = sorted(crates & set(r["crates"]))
            if used:
                findings.append(self.finding(
                    project_id, f"{r['file']} uses {what} crate(s) {', '.join(used)}", node_id=r["id"],
                    file=r["file"], line=1, severity=Severity.info, confidence=Confidence.medium, evidence=[r["id"]],
                ))
        return findings

    def crate_names(self) -> set[str]:
        return {e.path for e in load_catalogue().weak_crypto.get(self.group, []) if e.kind == "crate"}

    @staticmethod
    async def named(repo: GraphRepository, query: str, sites: list[dict[str, Any]],
                    patterns: list[str]) -> dict[str, list[str]]:
        """Per call site, the names of the variables `query` relates it to that match `patterns`
        (password-like or key-material names from the catalogue). Empty without a data-flow graph."""
        ids = [r["id"] for r in sites if r["how"] == "call"]
        if not ids or not patterns:
            return {}
        regexes = [re.compile(p) for p in patterns]
        found = {}
        for row in await repo.query(query, ids=ids):
            names = sorted(n for n in row["names"] if any(rx.search(n) for rx in regexes))
            if names:
                found[row["site"]] = names
        return found


@register
class WeakHashAlgorithm(_CryptoRule):
    rule = "weak-hash-algorithm"
    severity = Severity.warning
    cwe = ("CWE-327", "CWE-328")
    group = "weak_hash"
    description = ("MD5 or SHA-1 in use: the md5/sha1 crates, openssl MessageDigest::{md5,sha1}, or ring's "
                   "SHA1_FOR_LEGACY_USE_ONLY. Fine for checksums of trusted data, not for signatures, "
                   "certificates or passwords: an error when a password-named value flows into the call.")
    version = "2"

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings, files = [], set()
        sites = await self.sites(repo, project_id)
        secrets = load_catalogue().secrets
        passwords = await self.named(repo, FEEDERS, [r for r, _ in sites], secrets.passwords if secrets else [])
        for r, _ in sites:
            files.add(r["file"])
            if names := passwords.get(r["id"]):
                findings.append(self.site_finding(
                    project_id, r, f"{r['qname']} hashes `{names[0]}` with the weak hash {r['path']}",
                    severity=Severity.error))
            else:
                findings.append(self.site_finding(project_id, r, f"{r['qname']} uses the weak hash {r['path']}"))
        findings += await self.crate_use_findings(repo, project_id, self.crate_names(), files, "the weak-hash")
        return findings


@register
class WeakPasswordHashing(_CryptoRule):
    rule = "weak-password-hashing"
    severity = Severity.error
    cwe = ("CWE-916",)
    group = "fast_hash"
    description = ("A password-named value is hashed with a general-purpose digest (SHA-2, SHA-3, BLAKE, MD5, "
                   "SHA-1) instead of a password hash such as argon2, bcrypt, scrypt or pbkdf2. Fast digests "
                   "make offline guessing cheap. Needs the data-flow graph; names decide what a password is.")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        matcher = load_catalogue().matcher()
        secrets = load_catalogue().secrets
        rows = [r for r in await repo.query(SITES, pid=project_id)
                if r["how"] == "call" and any(m.group == self.group for m in matcher.match(r["path"], "weak_crypto"))]
        passwords = await self.named(repo, FEEDERS, rows, secrets.passwords if secrets else [])
        findings, seen = [], set()
        for r in sorted(rows, key=lambda r: (r["file"] or "", r["line"] or 0, r["id"])):
            names = passwords.get(r["id"])
            if not names or (r["fn"], r["line"]) in seen:
                continue
            seen.add((r["fn"], r["line"]))
            findings.append(self.site_finding(
                project_id, r,
                f"{r['qname']} hashes `{names[0]}` with {r['path']}, a fast general-purpose digest; use a "
                "password hash (argon2, bcrypt, scrypt, pbkdf2)",
                confidence=Confidence.medium))
        return findings


@register
class InsecureRandomness(_CryptoRule):
    rule = "insecure-randomness"
    severity = Severity.warning
    cwe = ("CWE-338",)
    group = "insecure_rng"
    description = ("A non-cryptographic or deterministically seeded random number generator: SmallRng, StepRng, "
                   "fastrand, oorandom, or seed_from_u64/from_seed with a constant seed. thread_rng, OsRng and "
                   "getrandom are fine. An error when the output flows into a variable named like key material "
                   "(key, token, nonce, salt, secret).")
    version = "2"

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings, files = [], set()
        sites = await self.sites(repo, project_id)
        secrets = load_catalogue().secrets
        feeds = await self.named(repo, RECEIVERS, [r for r, _ in sites], secrets.key_material if secrets else [])
        for r, hits in sites:
            seed_entries = [m for m in hits if m.entry.args]
            literals = _literals(r)
            if seed_entries and not any(i in literals for m in seed_entries for i in (m.entry.args or [])):
                if all(m.entry.args for m in hits):
                    continue                                     # seeded from a variable: say nothing
                message = f"{r['qname']} constructs a non-cryptographic RNG with {r['path']}"
                confidence = Confidence.medium
            elif seed_entries:
                seed = ", ".join(t for _, t in literals.values())
                message = f"{r['qname']} seeds an RNG with the constant {seed} via {r['path']}"
                confidence = Confidence.high
            else:
                message = f"{r['qname']} uses the non-cryptographic RNG {r['path']}"
                confidence = Confidence.medium
            files.add(r["file"])
            if names := feeds.get(r["id"]):
                findings.append(self.site_finding(
                    project_id, r, f"{message}; its output becomes `{names[0]}`", severity=Severity.error,
                    confidence=Confidence.high))
            else:
                findings.append(self.site_finding(project_id, r, message, confidence=confidence))
        findings += await self.crate_use_findings(repo, project_id, self.crate_names(), files,
                                                  "the non-cryptographic RNG")
        return findings


@register
class HardcodedSecret(_CryptoRule):
    rule = "hardcoded-secret"
    severity = Severity.warning
    cwe = ("CWE-798",)
    description = ("A string literal bound to a secret-like name (password, api_key, token, ...) or matching a "
                   "known key format (AWS access key, GitHub/Slack token, PEM private key, JWT). Values are never "
                   "stored: the finding carries a redacted preview and a hash. Test code is skipped.")

    QUERY = """
    MATCH (l:Literal {project_id: $pid}) WHERE NOT coalesce(l.in_test, false)
    OPTIONAL MATCH (owner)-[:HAS_LITERAL]->(l)
    RETURN l.id AS id, l.file AS file, l.line_start AS line, l.preview AS preview, l.binding AS binding,
           l.pattern AS pattern, l.entropy AS entropy, l.length AS length, owner.id AS owner,
           owner.qualified_name AS owner_name
    ORDER BY l.file, l.line_start
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        secrets = load_catalogue().secrets
        min_entropy = secrets.min_entropy if secrets else 3.5
        min_length = secrets.min_length if secrets else 16
        findings = []
        for r in await repo.query(self.QUERY, pid=project_id):
            where = f" in {r['owner_name']}" if r["owner_name"] and r["owner"] != r["file"] else ""
            if r["pattern"]:
                severity, confidence = Severity.error, Confidence.high
                what = f"a literal in the {r['pattern'].replace('_', ' ')} format"
            elif r["entropy"] >= min_entropy and r["length"] >= min_length:
                severity, confidence = Severity.error, Confidence.high
                what = f"a high-entropy literal ({r['length']} chars)"
            elif r["length"] >= 8:
                severity, confidence = Severity.warning, Confidence.medium
                what = f"a literal ({r['length']} chars)"
            else:
                severity, confidence = Severity.info, Confidence.low
                what = f"a short literal ({r['length']} chars), possibly a placeholder"
            bound = f" bound to `{r['binding']}`" if r["binding"] else ""
            findings.append(self.finding(
                project_id, f"{what}{bound}{where}: {r['preview']} (hard-coded secret)",
                node_id=r["owner"] or r["id"], file=r["file"], line=r["line"], severity=severity,
                confidence=confidence, evidence=[r["id"]],
            ))
        return findings


@register
class TlsVerificationDisabled(_CryptoRule):
    rule = "tls-verification-disabled"
    severity = Severity.error
    cwe = ("CWE-295",)
    group = "tls_disabled"
    description = ("Certificate or hostname verification switched off: danger_accept_invalid_certs(true), "
                   "danger_accept_invalid_hostnames(true), SslVerifyMode::NONE, rustls `.dangerous()`, or a "
                   "custom ServerCertVerifier implementation (medium confidence: it may still verify).")

    IMPLS = """
    MATCH (c:Class {project_id: $pid})-[:IMPLEMENTS]->(e:External)
    WHERE e.name = 'ServerCertVerifier'
    RETURN c.id AS id, c.qualified_name AS qname, c.file AS file, c.line_start AS line, e.id AS trait
    """

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings = []
        for r, hits in await self.sites(repo, project_id):
            literals = _literals(r)
            name = r["path"].rsplit("::", 1)[-1]
            if any(m.entry.args for m in hits):
                arg = literals.get(0)
                if arg and arg[0] == "path":
                    arg = None                                   # a named constant: value unknown
                if arg and arg[1] == "false":
                    continue
                if arg:
                    findings.append(self.site_finding(project_id, r, f"{r['qname']} calls {name}(true)"))
                else:
                    findings.append(self.site_finding(
                        project_id, r, f"{r['qname']} calls {name} with a non-literal argument",
                        severity=Severity.warning, confidence=Confidence.medium))
            elif r["how"] == "reference":
                findings.append(self.site_finding(project_id, r, f"{r['qname']} uses {r['path']}"))
            else:
                findings.append(self.site_finding(
                    project_id, r, f"{r['qname']} calls {r['path']}, which bypasses certificate verification",
                    severity=Severity.warning, confidence=Confidence.medium))
        for r in await repo.query(self.IMPLS, pid=project_id):
            findings.append(self.finding(
                project_id, f"{r['qname']} implements ServerCertVerifier; make sure it rejects invalid certificates",
                node_id=r["id"], file=r["file"], line=r["line"], severity=Severity.warning,
                confidence=Confidence.medium, evidence=[r["id"], r["trait"]],
            ))
        return findings


@register
class InsecureCipherOrMode(_CryptoRule):
    rule = "insecure-cipher-or-mode"
    severity = Severity.warning
    cwe = ("CWE-327",)
    group = "insecure_cipher"
    description = ("A broken or unauthenticated cipher or mode: the des, rc2, rc4, blowfish or ecb crates, or "
                   "openssl's DES, RC4, Blowfish and AES-ECB ciphers. Also an AEAD nonce built from a constant "
                   "(a literal, or a local nothing flows into): reusing a nonce under one key breaks AES-GCM "
                   "and ChaCha20-Poly1305 (CWE-323).")
    version = "2"

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings, files = [], set()
        for r, _ in await self.sites(repo, project_id):
            files.add(r["file"])
            findings.append(self.site_finding(project_id, r, f"{r['qname']} uses the insecure cipher {r['path']}"))
        findings += await self.crate_use_findings(repo, project_id, self.crate_names(), files, "the insecure-cipher")
        findings += await self.constant_nonces(repo, project_id)
        return findings

    async def constant_nonces(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        matcher = load_catalogue().matcher()
        rows = [r for r in await repo.query(SITES, pid=project_id)
                if r["how"] == "call" and any(m.group == "nonce" for m in matcher.match(r["path"], "weak_crypto"))]
        if not rows:
            return []
        constants = {row["site"]: sorted(row["names"])
                     for row in await repo.query(CONSTANT_ARGS, ids=[r["id"] for r in rows])}
        findings = []
        for r in sorted(rows, key=lambda r: (r["file"] or "", r["line"] or 0, r["id"])):
            literal = next((text for kind, text in _literals(r).values() if kind in ("str", "array")), None)
            names = constants.get(r["id"])
            if literal is None and not names:
                continue
            what = f"the constant `{names[0]}`" if names else "a literal"
            findings.append(self.finding(
                project_id, f"{r['qname']} builds a nonce from {what} via {r['path']}; a repeated nonce breaks "
                "the cipher's confidentiality and authenticity",
                node_id=r["fn"], file=r["file"], line=r["line"], cwe=["CWE-323"],
                confidence=Confidence.medium, evidence=[r["fn"], r["id"]],
            ))
        return findings


@register
class WeakKdfParameters(_CryptoRule):
    rule = "weak-kdf-parameters"
    severity = Severity.warning
    cwe = ("CWE-916",)
    group = "weak_kdf"
    description = ("A password hashing or key derivation call with a literal work factor below the OWASP minimum: "
                   "PBKDF2 under 100 000 rounds, Argon2 memory under 19 MiB or time under 2, scrypt log_n under "
                   "15, bcrypt cost under 10. Only literal arguments are checked.")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings = []
        for r, hits in await self.sites(repo, project_id):
            literals = _literals(r)
            for m in hits:
                for index, minimum in (m.entry.min or {}).items():
                    lit = literals.get(index)
                    value = _int(lit[1]) if lit and lit[0] == "int" else None
                    if value is not None and value < minimum:
                        findings.append(self.site_finding(
                            project_id, r,
                            f"{r['qname']} calls {r['path']} with {m.entry.note or 'parameter'} {value} "
                            f"(minimum {minimum})"))
        return findings
