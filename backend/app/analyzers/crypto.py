"""Class C: cryptography and secrets (docs/build-plan.md section 3).

The patterns live in the catalogue (weak_crypto.yaml, secret_patterns.yaml). Call sites that match
the catalogue are `Call` nodes, item paths passed as values are `External` nodes reached by
REFERENCES, and secret-looking string literals are redacted `Literal` nodes.
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
        matcher = load_catalogue().matcher()
        found = []
        for r in await repo.query(SITES, pid=project_id):
            hits = [m for m in matcher.match(r["path"], "weak_crypto") if m.group == self.group]
            if hits:
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


@register
class WeakHashAlgorithm(_CryptoRule):
    rule = "weak-hash-algorithm"
    severity = Severity.warning
    cwe = ("CWE-327", "CWE-328")
    group = "weak_hash"
    description = ("MD5 or SHA-1 in use: the md5/sha1 crates, openssl MessageDigest::{md5,sha1}, or ring's "
                   "SHA1_FOR_LEGACY_USE_ONLY. Fine for checksums of trusted data, not for signatures, "
                   "certificates or passwords (phase 3 raises it to error when a password flows in).")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings, files = [], set()
        for r, _ in await self.sites(repo, project_id):
            files.add(r["file"])
            findings.append(self.site_finding(project_id, r, f"{r['qname']} uses the weak hash {r['path']}"))
        findings += await self.crate_use_findings(repo, project_id, self.crate_names(), files, "the weak-hash")
        return findings


@register
class InsecureRandomness(_CryptoRule):
    rule = "insecure-randomness"
    severity = Severity.warning
    cwe = ("CWE-338",)
    group = "insecure_rng"
    description = ("A non-cryptographic or deterministically seeded random number generator: SmallRng, StepRng, "
                   "fastrand, oorandom, or seed_from_u64/from_seed with a constant seed. thread_rng, OsRng and "
                   "getrandom are fine. Whether the output becomes a key or token is phase 3 work.")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings, files = [], set()
        for r, hits in await self.sites(repo, project_id):
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
                   "openssl's DES, RC4, Blowfish and AES-ECB ciphers. A constant nonce reaching an AEAD is "
                   "phase 3 work.")

    async def run(self, repo: GraphRepository, project_id: str) -> list[Finding]:
        findings, files = [], set()
        for r, _ in await self.sites(repo, project_id):
            files.add(r["file"])
            findings.append(self.site_finding(project_id, r, f"{r['qname']} uses the insecure cipher {r['path']}"))
        findings += await self.crate_use_findings(repo, project_id, self.crate_names(), files, "the insecure-cipher")
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
