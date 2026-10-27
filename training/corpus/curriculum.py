"""The curriculum: a taxonomy of topic areas the corpus can be measured against.

The corpus has 63 sources because 63 upstreams were reachable, not because
anyone drew a map of what a purple-team model needs to know. That is fine as an
acquisition strategy and useless as a coverage model: nothing here could answer
*"is this model actually good at Active Directory?"* except by looking at a
sample and feeling optimistic. One benchmark probe, ``attck-real``, has sat at
0/10 since it was written, and nobody could say whether that was a data gap, a
tokenizer gap or a bug in the adapter, because there was no ruler to hold
against the data.

This module is the ruler's scale. It does not measure anything — it declares
**what is worth measuring**, as :data:`TOPICS`: leaf topic areas, each with the
vocabulary a document about that topic actually contains.

**Why not a vendor syllabus.** The obvious move is to take a well-known course
outline and use its module list. The topic *names* in this field are shared
vocabulary and belong to nobody — "Kerberoasting", "unquoted service path",
"padding oracle" are terms of art — but a vendor's outline is their expressive
work, and course material behind a per-student licence is not ours to read.
So the spine here is the open frameworks, which are also simply better for this
job because they are versioned, machine-readable and already in the corpus:

* **MITRE ATT&CK** is the field's real taxonomy and carries the identifiers the
  model must learn to emit. Every topic that corresponds to adversary behaviour
  names its ATT&CK ids in :attr:`Topic.attack_ids`.
* **OWASP** WSTG / ASVS / Top 10 for the web-application half, where ATT&CK has
  one technique (``T1190``) covering what a tester spends weeks on.
* **NIST SP 800-115**, **PTES** and **OSSTMM** for assessment workflow.
* **NICE** (NIST SP 800-181) for knowledge and task framing.
* **D3FEND** for defensive countermeasures, **MITRE ATLAS** for AI/ML.
* Openly-published **certification objective lists** — exam objectives, which
  vendors publish as marketing, not course content — used *only* to cross-check
  that practitioner areas are not missing. Nothing here is phrased in anyone
  else's words; every description in this file was written for this file.

**Where ATT&CK is silent, and that silence is the point.** ATT&CK describes
adversary behaviour observed in the wild. It does not describe a tester's
workflow, so whole areas of practitioner competence have no technique id at
all: stack and heap exploitation, ROP, fuzzing, wireless, lock picking, risk
rating, and **report writing** — the deliverable the client actually buys.
Those topics carry ``attack_ids = ()`` and ``spine`` naming what placed them
instead. A coverage report that only walked ATT&CK would score the corpus as
complete while the model could not write a finding.

**ATT&CK facts verified against data, not recalled.** Model priors on this are
stale, so the tactic names in :data:`ATTACK_TACTICS` were read out of the STIX
bundle cached on this machine (``enterprise-attack.json.gz``, collection
``Enterprise ATT&CK 19.2``, 26,086 objects) rather than remembered:

* ``TA0005`` is **"Stealth"**. It was "Defense Evasion" for nine years and the
  rename is recent enough that most writing about it, including
  :mod:`~training.corpus.sources.threathunt`'s hardcoded tactic map, still says
  the old name.
* ``TA0112`` **"Defense Impairment"** exists, which makes fifteen enterprise
  tactics, not fourteen. ``T1562 Impair Defenses`` is gone from the live set;
  its content now sits under ``T1685 Disable or Modify Tools`` in the new
  tactic.
* The site-scraped id list in the curriculum scratch directory on the external
  build volume (``whetstone/curriculum/``, path deliberately not written here —
  the volume name is one of the values the corpus audit flags) is a
  strict superset of the cached 19.2 bundle: 706 ids against 697, the nine new
  ones being ``T1608.007``, ``T1685.007``, ``T1696`` and its two
  sub-techniques, ``T1697``, ``T1698``, ``T1699`` and ``T1700``. Five of those
  nine are AI-agent techniques, which is why :data:`Domain` ``aisec`` names
  ATT&CK ids as well as ATLAS ones.

**Granularity is a measurement decision, not taste.** 208,346 documents
against 2,000 leaf topics gives a hundred documents a topic and a report made
of noise; against 20 topics it gives "the corpus contains Windows, yes" and
measures nothing. This file declares **192 topics in 22 domains**, which is
roughly a thousand documents a topic on average, and deliberately *unbalanced*
between domains: ``webapp`` has 23 leaves because that is where ATT&CK is
thinnest and where practitioner depth lives, while macOS is one topic inside
``nix`` rather than a domain of its own, because the corpus has little macOS
text to cut finely. :data:`COLLAPSED` records what was deliberately not split,
including the decision not to treat ATT&CK sub-techniques as leaves.

**Matcher terms are the part that can quietly be wrong, and were.** The next
step measures coverage by looking for these strings, so a term appearing in
half the corpus measures nothing while reporting 100% — the exact failure this
project has already paid for three times, where the ruler was wrong and the
model was accused. The terms were therefore calibrated against the corpus in
three reads, and the first read failed in the *other* direction:

* **399 of the first draft's 952 terms matched nothing at all.** Not because
  the corpus lacks the topics, but because the terms were tidy compounds
  nobody writes. The corpus says ``sudoers``, ``psexec``, ``logsource``; the
  first draft said "sudoers misconfiguration", "psexec service creation",
  "logsource product". A term is the field's own surface form or it is fiction.
* **The matcher refused plurals.** "yara rule" could not match "yara rules",
  so a term with 10,462 documents behind it measured 0. :func:`term_pattern`
  now allows an optional trailing ``s``.
* **Two terms passed every frequency check and still measured one adapter.**
  "shodan" is reconnaissance vocabulary and is nuclei template metadata in
  5,531 of its 5,570 documents; "cvss base score" is the same metadata block.
  A third read measured, per term, how much of its frequency comes from a
  single source — :data:`SOURCE_CONCENTRATION` — because frequency alone
  cannot see this.

What survived: **1,071 terms**, median 28 documents each, none above 4.2% of
the corpus, every topic with at least one term that actually occurs.
:data:`TERM_DOC_FREQ` carries the count for every one of them,
:data:`REJECTED_TERMS` and :data:`REJECTION_CLASSES` carry what was thrown out
and why. A coverage score of 100% or 0% across the board means the matcher is
broken, not that the corpus is perfect or empty.

**A term with zero hits is a finding, not a bug** — provided it is spelled the
way the field spells it, which is why rejection is by *excess* frequency and by
source concentration, never by absence. 178 live terms are at zero and kept:
``nice framework work role`` matching nothing is the module reporting that this
corpus contains no workforce-framework text, which is true and worth knowing.
The thin topics are the ones to read first — adversarial examples (4 documents
across every term), beaconing (14), fuzzing (17), report writing (100).

**Registers were assigned by judgement, not measured.** Each topic names the
register its documents would mostly live in, and that is an authored claim, not
a count. Where this file quotes corpus shares it uses the **by-character**
ruler (``clean-v7``: system 36.0%, detection 20.8%, advisory 14.4%, shell 8.0%,
trajectory 7.8%, adversary 6.8%, prose 6.2%), not the post-balance token share
quoted in the ROADMAP, which disagrees — notably shell 8.0% against 15.6%.
That disagreement is unresolved and is named here rather than averaged away.

Nothing in this module touches the network, the filesystem or any corpus
generation. It is data and three small functions, standard library only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterator

from .source import Register

__all__ = [
    "ATTACK_SOURCES_VERIFIED",
    "ATTACK_TACTICS",
    "ATTACK_ID_RE",
    "ATLAS_ID_RE",
    "COLLAPSED",
    "CURRICULUM_VERSION",
    "DOMAINS",
    "Domain",
    "REJECTED_TERMS",
    "RejectedTerm",
    "TOPICS",
    "Topic",
    "CALIBRATION_DOCS",
    "CALIBRATION_GENERATION",
    "MEASURED_GAPS",
    "REJECTION_CLASSES",
    "SOURCE_CONCENTRATION",
    "TERM_DOC_FREQ",
    "atlas_index",
    "attack_index",
    "by_domain",
    "by_id",
    "by_register",
    "domain_ids",
    "term_pattern",
    "topic_ids",
    "topic_pattern",
]

#: Bumped when topic ids are added, removed or renamed. Coverage reports quote
#: it so a number from an older taxonomy is not compared against a newer one.
CURRICULUM_VERSION = "1.0"

#: The generation of ATT&CK the tactic names and ids here were checked against.
#: Two rulers, named rather than averaged: the STIX bundle cached on this
#: machine, and the id list scraped from the site in an earlier session.
ATTACK_SOURCES_VERIFIED = (
    "enterprise-attack.json.gz (x-mitre-collection 'Enterprise ATT&CK 19.2')",
    "curriculum/attack_v20_live.json + attack_v20_{page1,rest}.tsv (706 ids)",
)

#: Well-formed ATT&CK technique or tactic id. Sub-techniques are three digits.
ATTACK_ID_RE = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|TA\d{4})$")

#: Well-formed MITRE ATLAS id. Sub-techniques are three digits and start at
#: ``.000``, which is ATLAS's own convention and not a typo for ``.001``.
ATLAS_ID_RE = re.compile(r"^AML\.(?:T|TA|M)\d{4}(?:\.\d{3})?$")

#: Enterprise tactic id to name, read out of the cached STIX bundle. Fifteen
#: entries: ``TA0112`` is new and ``TA0005`` is **"Stealth"**, not "Defense
#: Evasion". Kept here so a coverage report can label a tactic without parsing
#: 50 MB of STIX, and so the rename is written down somewhere the tests check.
ATTACK_TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Stealth",
    "TA0112": "Defense Impairment",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


@dataclass(frozen=True, slots=True)
class Domain:
    """A grouping of topics, and the open framework that justified it.

    ``spine`` is recorded per domain because the honest answer differs by
    domain and the difference is the interesting part: ``winad`` is ATT&CK
    almost end to end, ``webapp`` is OWASP with ATT&CK contributing one
    technique, and ``binexp`` has no ATT&CK coverage whatsoever.
    """

    id: str
    label: str
    #: Which open framework(s) placed this domain. Free text, short.
    spine: str
    #: Why this domain exists as a separate axis of measurement.
    note: str = ""


@dataclass(frozen=True, slots=True)
class Topic:
    """One leaf topic area: what it is, where it came from, how to find it.

    ``terms`` is the load-bearing field. It is not a description of the topic
    in keywords — it is the vocabulary that documents *about* this topic
    contain, which is a different and narrower thing. "web application" is a
    fine description and a useless term.
    """

    id: str
    domain: str
    #: One or two sentences, written for this file. Never a vendor's wording.
    description: str
    #: The register the corpus text for this topic predominantly lives in.
    register: Register
    #: ATT&CK technique or tactic ids, empty when ATT&CK does not describe it.
    attack_ids: tuple[str, ...] = ()
    #: MITRE ATLAS ids, for the AI/ML topics.
    atlas_ids: tuple[str, ...] = ()
    #: Discriminating strings. Matched case-insensitively, with internal
    #: whitespace allowed to span a newline, and word boundaries enforced on
    #: any end that is alphanumeric.
    terms: tuple[str, ...] = ()
    #: What placed this topic when it is not ATT&CK — "OWASP WSTG", "PTES",
    #: "cert objectives" and so on. Empty means ATT&CK alone.
    spine: str = ""

    def matches(self, text: str) -> bool:
        """True if any term appears in ``text``."""
        return topic_pattern(self.id).search(text) is not None

    def hits(self, text: str) -> dict[str, int]:
        """Per-term occurrence counts, for terms that occur at all.

        Counts occurrences rather than returning a bool so a caller can see
        that a topic "matched" on one passing mention of one term versus
        saturating a document, which is the difference between a document that
        is *about* the topic and one that name-drops it.
        """
        found: dict[str, int] = {}
        for term in self.terms:
            n = len(term_pattern(term).findall(text))
            if n:
                found[term] = n
        return found


@dataclass(frozen=True, slots=True)
class RejectedTerm:
    """A candidate term that was measured and thrown out as too broad.

    Kept in the module rather than deleted in an editor, because "we
    calibrated" is a claim and this is the evidence. ``doc_freq`` is the number
    of ``clean-v7`` documents the term appeared in, out of 208,346.
    """

    term: str
    #: Documents out of 208,346 containing it. ``-1`` when the term was
    #: rejected on reasoning rather than measurement (see ``reason``).
    doc_freq: int
    reason: str
    #: What replaced it, where something did.
    replaced_by: str = ""


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

DOMAINS: tuple[Domain, ...] = (
    Domain("recon", "Reconnaissance and OSINT", "ATT&CK TA0043 + PTES intelligence gathering",
           "Pre-engagement information gathering, almost all of it outside the target's logs."),
    Domain("scanning", "Enumeration and vulnerability scanning", "NIST SP 800-115 + ATT&CK T1595",
           "The first thing a tester does with a scope and the first thing a defender sees."),
    Domain("webapp", "Web application testing", "OWASP WSTG / ASVS / Top 10",
           "Largest domain on purpose: ATT&CK compresses all of it into T1190."),
    Domain("netsvc", "Network services and protocols", "ATT&CK + NIST SP 800-115",
           "Service-by-service attack surface, the part of a network test that is not AD."),
    Domain("winad", "Windows and Active Directory", "ATT&CK (near-complete coverage)",
           "The densest ATT&CK region and the one the corpus has most text for."),
    Domain("nix", "Linux, Unix and macOS", "ATT&CK + GTFOBins vocabulary",
           "macOS is one topic here rather than its own domain; see COLLAPSED."),
    Domain("cloud", "Cloud and containers", "ATT&CK cloud/container matrices + CIS benchmarks",
           "Identity-shaped rather than host-shaped, which is why it is not under netsvc."),
    Domain("binexp", "Binary exploitation and memory safety", "cert objectives + CWE; ATT&CK silent",
           "Zero ATT&CK ids across the whole domain. The clearest evidence that an "
           "ATT&CK-only coverage model would have scored a blind spot as complete."),
    Domain("credaccess", "Credential access and cracking", "ATT&CK TA0006",
           "Separated from winad because half of it is host-agnostic."),
    Domain("evasion", "Stealth, defence impairment and anti-forensics", "ATT&CK TA0005 + TA0112",
           "Two tactics since the v20 split; TA0112 did not exist a year ago."),
    Domain("lateral", "Lateral movement, tunnelling and pivoting", "ATT&CK TA0008 + cert objectives",
           "Tunnelling mechanics are a tester skill ATT&CK describes only as an outcome."),
    Domain("c2exfil", "Command and control, collection and exfiltration", "ATT&CK TA0011 / TA0009 / TA0010",
           "Three tactics collapsed into one domain; see COLLAPSED."),
    Domain("socialclient", "Social engineering and client-side attacks", "ATT&CK T1566 + cert objectives",
           "ATT&CK covers delivery well and the pretext work not at all."),
    Domain("wireless", "Wireless, RF and physical", "cert objectives + protocol specs; ATT&CK thin",
           "One ATT&CK sub-technique for Bluetooth exfiltration and nothing else useful."),
    Domain("detect", "Detection engineering", "Sigma / D3FEND + rule-language references",
           "The blue register the corpus is richest in, so it needs fine topics to be measurable."),
    Domain("dfir", "Digital forensics, IR and malware analysis", "NIST SP 800-61/86 + D3FEND",
           "Artifact-level, which is what makes it measurable at all."),
    Domain("harden", "Defensive countermeasures and hardening", "D3FEND + NIST SP 800-53 + CIS",
           "The answer half of a purple pairing; D3FEND is the only real taxonomy for it."),
    Domain("aisec", "AI and ML security", "MITRE ATLAS + ATT&CK v20 additions",
           "Five of the nine ids new in v20 are here, which dates this domain precisely."),
    Domain("method", "Methodology, scoping and reporting", "PTES / OSSTMM / NIST SP 800-115 / NICE",
           "Includes report writing, which no ATT&CK technique describes and every "
           "engagement ends with."),
    Domain("tooling", "Operator tooling and scripting", "cert objectives (scripting) + the SHELL register",
           "The register the tokenizer measurement rewarded most; needs its own axis."),
    Domain("vulnmgmt", "Vulnerability and advisory knowledge", "CVE / CVSS / CWE / KEV",
           "The ADVISORY register: 14.4% of the corpus by character, and identifier-dense."),
    Domain("crypto", "Cryptography and protocol security", "OWASP ASVS V6 + IETF RFCs",
           "Split out because the RFC source is large and crypto failures cut across domains."),
)


# ---------------------------------------------------------------------------
# Topics
# ---------------------------------------------------------------------------

def _t(
    tid: str,
    domain: str,
    description: str,
    register: Register,
    terms: tuple[str, ...],
    attack_ids: tuple[str, ...] = (),
    atlas_ids: tuple[str, ...] = (),
    spine: str = "",
) -> Topic:
    return Topic(
        id=tid,
        domain=domain,
        description=description,
        register=register,
        attack_ids=attack_ids,
        atlas_ids=atlas_ids,
        terms=terms,
        spine=spine,
    )


TOPICS: tuple[Topic, ...] = (
    # -- recon ------------------------------------------------------------
    _t("recon.subdomain-enumeration", "recon",
       "Finding a target's hostnames from public records: certificate logs, DNS "
       "brute force, and the dangling records that let someone else claim them.",
       Register.PROSE,
       ("dnsrecon", "subfinder", "cname record", "dns brute force",
        "subdomain takeover", "certificate transparency"),
       ("T1590.002", "T1596.001"), spine="ATT&CK + PTES"),
    _t("recon.domain-registration", "recon",
       "Registration and ownership records for domains and netblocks, and what "
       "they reveal about an organisation's infrastructure.",
       Register.PROSE,
       ("rdap", "whois lookup", "whois record", "registrant contact",
        "registrar abuse contact"),
       ("T1590.001", "T1596.002"), spine="ATT&CK + PTES"),
    _t("recon.people-and-identity-osint", "recon",
       "Building a roster of staff, email formats and credentials already exposed "
       "in public breach data, which is where most phishing starts.",
       Register.PROSE,
       ("linkedin", "theharvester", "haveibeenpwned",
        "breach credential dump", "open source intelligence",
        "credential stuffing list"),
       ("T1589.002", "T1589.003", "T1593.003"), spine="ATT&CK + PTES"),
    _t("recon.search-and-device-indexes", "recon",
       "Querying search engines and internet-wide scan indexes with operators "
       "that surface exposed files, panels and services.",
       Register.PROSE,
       ("censys", "zoomeye", "google dork", "search engine",
        "google hacking database", "internet-wide scan index"),
       ("T1593.002", "T1596.005"), spine="ATT&CK"),
    _t("recon.code-and-artifact-exposure", "recon",
       "Secrets and internal detail left in public repositories, package "
       "registries, build artifacts and exposed version-control directories.",
       Register.PROSE,
       ("gitleaks", "trufflehog", ".git/config", "git history",
        "secret scanning", "exposed git directory"),
       ("T1593.003",), spine="ATT&CK"),
    _t("recon.infrastructure-mapping", "recon",
       "Turning scattered records into a picture of the target's address space, "
       "autonomous systems, hosting providers and perimeter devices.",
       Register.PROSE,
       ("ip range", "netblock", "traceroute", "asn lookup", "bgp.he.net",
        "reverse ip lookup"),
       ("T1590.004", "T1590.005", "T1595.001"), spine="ATT&CK"),
    _t("recon.threat-actor-profiling", "recon",
       "Reading published reporting on a named adversary to derive what they do, "
       "with what tooling, in what order.",
       Register.ADVERSARY,
       ("ttps", "apt group", "kill chain", "diamond model",
        "threat actor group", "adversary tradecraft"),
       ("TA0043",), spine="ATT&CK groups"),

    # -- scanning ---------------------------------------------------------
    _t("scanning.port-scanning", "scanning",
       "Establishing which TCP and UDP ports answer, the scan types that do it, "
       "and the trade-off between stealth, speed and accuracy.",
       Register.SHELL,
       ("nmap", "syn-ack", "masscan", "syn scan", "rustscan",
        "half-open scan"),
       ("T1046", "T1595.001"), spine="NIST SP 800-115"),
    _t("scanning.service-fingerprinting", "scanning",
       "Identifying what is actually listening on an open port and which version, "
       "from banners and probe responses rather than the port number.",
       Register.SHELL,
       ("nse script", "banner grabbing", "version detection",
        "os fingerprinting", "nmap scripting engine"),
       ("T1046",), spine="NIST SP 800-115"),
    _t("scanning.vulnerability-scanning", "scanning",
       "Running an automated scanner against a scope, and the authenticated-versus-"
       "unauthenticated and false-positive questions that make the output usable.",
       Register.PROSE,
       ("nessus", "qualys", "openvas", "scanner plugin",
        "authenticated scan", "vulnerability scanner"),
       ("T1595.002",), spine="NIST SP 800-115"),
    _t("scanning.dns-enumeration", "scanning",
       "Pulling records out of DNS directly: transfers, reverse lookups, record "
       "types that leak internal naming.",
       Register.SHELL,
       ("axfr", "nslookup", "ptr record", "zone transfer",
        "reverse dns lookup", "srv record enumeration"),
       ("T1590.002",), spine="NIST SP 800-115"),
    _t("scanning.smb-and-rpc-enumeration", "scanning",
       "Enumerating Windows file sharing and RPC interfaces for shares, users and "
       "policy, including the unauthenticated cases.",
       Register.SHELL,
       ("nbtscan", "smbclient", "crackmapexec", "null session",
        "netbios name service", "smb share permission"),
       ("T1135", "T1018"), spine="ATT&CK + cert objectives"),
    _t("scanning.management-protocol-enumeration", "scanning",
       "Management and monitoring protocols that answer unauthenticated queries "
       "with inventory detail: SNMP, IPMI, printer and UPS services.",
       Register.SHELL,
       ("snmpwalk", "ipmitool", "onesixtyone", "community string",
        "ipmi cipher zero", "management interface"),
       ("T1046",), spine="NIST SP 800-115"),
    _t("scanning.web-content-discovery", "scanning",
       "Finding paths, parameters and virtual hosts a web server does not link to, "
       "by wordlist rather than by crawling.",
       Register.SHELL,
       ("ffuf", "wordlist", "gobuster", "dirsearch", "forced browsing",
        "virtual host discovery"),
       ("T1595.003",), spine="OWASP WSTG"),

    # -- webapp -----------------------------------------------------------
    _t("webapp.sql-injection", "webapp",
       "Injecting SQL through application input, and the families that differ by "
       "what the application gives back: errors, booleans, timing, or nothing.",
       Register.ADVERSARY,
       ("sqli", "union select", "sql injection", "time-based blind",
        "information_schema"),
       ("T1190",), spine="OWASP WSTG"),
    _t("webapp.nosql-and-orm-injection", "webapp",
       "Injection into document stores and ORM query builders, where the payload "
       "is an operator or object rather than a quoted string.",
       Register.ADVERSARY,
       ("$where", "nosqli", "mongodb", "nosql injection",
        "operator injection", "orm query injection"),
       ("T1190",), spine="OWASP WSTG"),
    _t("webapp.command-injection", "webapp",
       "Application input reaching a shell or an exec call, and the metacharacters "
       "and argument-level tricks that get there.",
       Register.ADVERSARY,
       ("; id", "$(id)", "|| whoami", "rce via parameter",
        "argument injection", "backtick execution"),
       ("T1190", "T1059"), spine="OWASP WSTG"),
    _t("webapp.cross-site-scripting", "webapp",
       "Getting script to run in another user's browser session, by context: "
       "stored, reflected, and sink-driven DOM cases.",
       Register.ADVERSARY,
       ("onerror=", "stored xss", "<script>alert", "reflected xss",
        "cross-site scripting"),
       ("T1189", "T1059.007"), spine="OWASP WSTG"),
    _t("webapp.csrf", "webapp",
       "Making an authenticated browser issue a state-changing request the user "
       "did not intend, and the token and cookie defences against it.",
       Register.ADVERSARY,
       ("csrf", "xsrf", "referer check", "state-changing request",
        "cross-site request forgery"),
       (), spine="OWASP WSTG / ASVS V4"),
    _t("webapp.ssrf", "webapp",
       "Coercing a server into making requests of the attacker's choosing, which "
       "on a cloud host usually means the metadata service.",
       Register.ADVERSARY,
       ("ssrf", "gopher://", "file:// scheme", "169.254.169.254",
        "server-side request forgery", "internal service reachable from"),
       ("T1190",), spine="OWASP Top 10"),
    _t("webapp.xxe-and-xml", "webapp",
       "XML parsers that resolve external entities or recurse, yielding file reads, "
       "SSRF and denial of service.",
       Register.ADVERSARY,
       ("<!entity", "<!doctype", "billion laughs", "entity expansion",
        "xml external entity"),
       ("T1190",), spine="OWASP WSTG"),
    _t("webapp.deserialization", "webapp",
       "Untrusted serialized objects reaching a deserializer, and the gadget "
       "chains in common libraries that turn that into execution.",
       Register.ADVERSARY,
       ("ysoserial", "unserialize", "gadget chain", "java deserialization",
        "insecure deserialization", "serialized object payload"),
       ("T1190",), spine="OWASP Top 10"),
    _t("webapp.template-injection", "webapp",
       "User input evaluated by a server-side template engine, which generally "
       "escalates from expression evaluation to command execution.",
       Register.ADVERSARY,
       ("ssti", "jinja2", "freemarker", "expression language injection",
        "server-side template injection", "template engine sandbox escape"),
       ("T1190",), spine="OWASP WSTG"),
    _t("webapp.path-traversal-and-inclusion", "webapp",
       "Escaping an intended directory with relative paths or encodings, and the "
       "inclusion variants that execute what they read.",
       Register.ADVERSARY,
       ("/etc/passwd", "path traversal", "directory traversal",
        "local file inclusion", "null byte truncation",
        "remote file inclusion"),
       ("T1190", "T1083"), spine="OWASP WSTG"),
    _t("webapp.file-upload", "webapp",
       "Upload handlers that accept and then serve or execute attacker-chosen "
       "content, and the validation they get wrong.",
       Register.ADVERSARY,
       (".php.jpg", "file upload", "upload directory", "double extension",
        "magic byte check", "multipart/form-data"),
       ("T1190", "T1505.003"), spine="OWASP WSTG"),
    _t("webapp.authentication-flaws", "webapp",
       "Login, registration, reset and lockout logic: enumeration, guessing at "
       "scale, and reset flows that can be redirected.",
       Register.ADVERSARY,
       ("login brute force", "default credentials", "credential stuffing",
        "password reset token", "username enumeration",
        "account lockout bypass"),
       ("T1110",), spine="OWASP ASVS V2"),
    _t("webapp.session-management", "webapp",
       "How session state is issued, carried and destroyed, and the failures that "
       "let a session be fixed, stolen or outlived.",
       Register.ADVERSARY,
       ("httponly", "phpsessid", "session id", "set-cookie",
        "session fixation", "session token entropy"),
       ("T1539",), spine="OWASP ASVS V3"),
    _t("webapp.jwt-and-bearer-tokens", "webapp",
       "Token formats carrying their own validation metadata, and the header and "
       "algorithm confusions that let a token be forged.",
       Register.ADVERSARY,
       ("jwks", "hs256", "rs256", "alg none", "bearer token",
        "\"alg\":\"none\""),
       ("T1550.001",), spine="OWASP ASVS V3"),
    _t("webapp.authorization-and-idor", "webapp",
       "Access control enforced per object and per function: references that can "
       "be swapped, functions reachable without the role, fields that bind blindly.",
       Register.ADVERSARY,
       ("mass assignment", "object reference", "privilege boundary",
        "authorization check", "broken access control"),
       (), spine="OWASP Top 10 / ASVS V4"),
    _t("webapp.business-logic", "webapp",
       "Abuse that breaks no technical rule but breaks the application's intent: "
       "skipped steps, replayed discounts, concurrent requests.",
       Register.ADVERSARY,
       ("toctou", "coupon abuse", "race condition", "business logic",
        "replay of request", "price manipulation"),
       (), spine="OWASP WSTG"),
    _t("webapp.api-and-graphql", "webapp",
       "APIs as their own attack surface: schema introspection, batching, "
       "versioned endpoints left exposed, and rate limits that can be sidestepped.",
       Register.ADVERSARY,
       ("grpc", "graphql", "openapi", "rest api", "batch query attack",
        "introspection query"),
       ("T1190",), spine="OWASP API Top 10"),
    _t("webapp.cors-and-origin-policy", "webapp",
       "Cross-origin sharing headers and the trust they grant, including reflected "
       "origins, null origin, and legacy policy files.",
       Register.ADVERSARY,
       ("cors", "crossdomain.xml", "preflight request",
        "same-origin policy", "access-control-allow-credentials",
        "access-control-allow-origin wildcard"),
       (), spine="OWASP WSTG"),
    _t("webapp.request-smuggling-and-cache", "webapp",
       "Disagreements between a front end and a back end about where a request "
       "ends, and the cache poisoning that follows.",
       Register.ADVERSARY,
       ("te.cl", "cl.te", "cache poisoning", "x-forwarded-host",
        "request smuggling"),
       ("T1190",), spine="OWASP WSTG"),
    _t("webapp.redirects-and-ui-redress", "webapp",
       "Trust in a URL or a rendered frame: redirects that carry a user off-site, "
       "and overlays that make a click land somewhere else.",
       Register.ADVERSARY,
       ("clickjacking", "open redirect", "frame busting", "x-frame-options",
        "ui redress attack", "content-security-policy frame-ancestors"),
       ("T1189",), spine="OWASP WSTG"),
    _t("webapp.websocket-and-realtime", "webapp",
       "Long-lived bidirectional channels, which usually inherit the page's "
       "credentials and skip the page's authorisation checks.",
       Register.ADVERSARY,
       ("ws://", "websocket", "socket.io", "server-sent events endpoint"),
       (), spine="OWASP WSTG"),
    _t("webapp.cms-and-framework-flaws", "webapp",
       "Known-vulnerable application platforms and plugins, where the test is "
       "version identification and the exploit already exists.",
       Register.ADVISORY,
       ("wpscan", "joomla", "struts", "wordpress", "spring4shell",
        "cms version disclosure"),
       ("T1190",), spine="OWASP WSTG"),
    _t("webapp.client-side-pollution", "webapp",
       "Attacks that stay in the browser's own object graph and message passing "
       "rather than reaching the server.",
       Register.ADVERSARY,
       ("__proto__", "postmessage", "dom clobbering", "prototype pollution",
        "constructor.prototype"),
       (), spine="OWASP WSTG"),

    # -- netsvc -----------------------------------------------------------
    _t("netsvc.smb-services", "netsvc",
       "SMB as a service rather than as a credential path: dialects, signing, "
       "share permissions and the legacy versions still deployed.",
       Register.SYSTEM,
       ("smbv1", "port 445", "net share", "smb signing", "signing required",
        "guest access to share"),
       ("T1021.002",), spine="ATT&CK + cert objectives"),
    _t("netsvc.remote-desktop-services", "netsvc",
       "Graphical remote access services, their authentication modes and the "
       "session handling that makes them both a target and a foothold.",
       Register.SYSTEM,
       ("mstsc", "port 3389", "restricted admin mode",
        "remote desktop protocol", "rdp certificate warning",
        "network level authentication"),
       ("T1021.001",), spine="ATT&CK"),
    _t("netsvc.ssh-services", "netsvc",
       "SSH server configuration and the key, agent and forwarding features that "
       "quietly widen access.",
       Register.SYSTEM,
       ("ssh-keygen", "sshd_config", "known_hosts", "authorized_keys",
        "permitrootlogin"),
       ("T1021.004",), spine="ATT&CK"),
    _t("netsvc.database-services", "netsvc",
       "Database engines reachable over the network, their built-in command and "
       "file primitives, and default or absent authentication.",
       Register.SHELL,
       ("mysql", "mssql", "mongodb", "postgresql", "xp_cmdshell",
        "database link abuse"),
       ("T1190", "T1059"), spine="cert objectives"),
    _t("netsvc.mail-services", "netsvc",
       "Mail transport and retrieval services: relaying, address verification, "
       "and the DNS records that authorise senders.",
       Register.SYSTEM,
       ("smtp", "dkim", "dmarc", "open relay", "spf record",
        "imap folder enumeration"),
       ("T1114",), spine="RFC 5321/7208 + cert objectives"),
    _t("netsvc.file-transfer-services", "netsvc",
       "File transfer and network file systems, where anonymous access and "
       "export permissions do most of the damage.",
       Register.SYSTEM,
       ("tftp", "rsync", "showmount", "anonymous ftp", "anonymous login"),
       ("T1039",), spine="cert objectives"),
    _t("netsvc.network-protocol-attacks", "netsvc",
       "Attacks on the fabric itself — address resolution, switching, routing and "
       "name resolution — from a position already on the wire.",
       Register.ADVERSARY,
       ("dhcp", "vlan", "mitm", "arp cache", "arp spoofing",
        "stp root bridge"),
       ("T1557", "T1565.002"), spine="ATT&CK + cert objectives"),

    # -- winad ------------------------------------------------------------
    _t("winad.directory-enumeration", "winad",
       "Reading a domain's own directory for users, groups, computers, policy and "
       "trusts, which any authenticated account can largely do.",
       Register.SHELL,
       ("dsquery", "powerview", "net group", "ldapsearch", "sharphound",
        "adsi search"),
       ("T1087.002", "T1069.002", "T1482", "T1018"), spine="ATT&CK"),
    _t("winad.kerberoasting", "winad",
       "Requesting service tickets for accounts with a service principal name and "
       "cracking them offline, which needs no privilege beyond a domain account.",
       Register.ADVERSARY,
       ("krbtgt", "rubeus", "kerberoast", "getuserspns", "tgs-rep hash",
        "service principal name"),
       ("T1558.003",), spine="ATT&CK"),
    _t("winad.asreproasting", "winad",
       "Accounts configured without Kerberos pre-authentication hand out a "
       "crackable blob to any requester.",
       Register.ADVERSARY,
       ("as-rep", "preauth", "asreproast", "getnpusers"),
       ("T1558.004",), spine="ATT&CK"),
    _t("winad.kerberos-delegation", "winad",
       "Delegation lets a service act as a user; unconstrained, constrained and "
       "resource-based variants each fail differently.",
       Register.ADVERSARY,
       ("rbcd", "s4u2self", "printerbug", "constrained delegation",
        "unconstrained delegation"),
       ("T1134.001", "T1550.003"), spine="ATT&CK"),
    _t("winad.ticket-forgery", "winad",
       "Forging Kerberos tickets from stolen key material, which converts a "
       "hash into durable domain-wide authority.",
       Register.ADVERSARY,
       ("krbtgt hash", "golden ticket", "silver ticket", "forged ticket",
        "diamond ticket"),
       ("T1558.001", "T1558.002"), spine="ATT&CK"),
    _t("winad.ntlm-relay-and-coercion", "winad",
       "Making a host authenticate somewhere of the attacker's choosing and "
       "relaying that authentication to a service that accepts it.",
       Register.ADVERSARY,
       ("llmnr", "mitm6", "ntlmrelayx", "ntlm relay", "petitpotam",
        "ntlmv1 downgrade"),
       ("T1557.001", "T1187"), spine="ATT&CK"),
    _t("winad.pass-the-hash", "winad",
       "Authenticating with a stored hash or key instead of a password, the "
       "primitive that makes NTLM hashes as good as credentials.",
       Register.ADVERSARY,
       ("wmiexec", "sekurlsa", "ntlm hash", "pass-the-hash",
        "overpass-the-hash", "nt hash authentication"),
       ("T1550.002",), spine="ATT&CK"),
    _t("winad.dcsync-and-replication", "winad",
       "Abusing directory replication rights to pull every credential in the "
       "domain without touching a domain controller's disk.",
       Register.ADVERSARY,
       ("dcsync", "lsadump", "drsuapi", "ntds.dit", "secretsdump",
        "replication rights abuse"),
       ("T1003.006", "T1003.003"), spine="ATT&CK"),
    _t("winad.acl-and-object-abuse", "winad",
       "Directory object permissions as an attack graph: rights that let one "
       "principal rewrite another's credentials or group membership.",
       Register.ADVERSARY,
       ("writedacl", "genericall", "adminsdholder", "writeowner right",
        "shadow credentials", "msds-keycredentiallink"),
       ("T1098.007", "T1222"), spine="ATT&CK"),
    _t("winad.group-policy-abuse", "winad",
       "Group Policy as a delivery mechanism: whoever can edit a policy or write "
       "to its files can run code on everything it applies to.",
       Register.ADVERSARY,
       ("sysvol", "gpupdate", "group policy", "sharpgpoabuse",
        "gpo modification", "immediate scheduled task via policy"),
       ("T1484.001", "T1552.006"), spine="ATT&CK"),
    _t("winad.certificate-services-abuse", "winad",
       "Enterprise PKI misconfiguration, where a template that lets the requester "
       "name the subject is a domain-wide credential issuer.",
       Register.ADVERSARY,
       ("adcs", "esc1", "pkinit", "certipy", "certificate template"),
       ("T1649",), spine="ATT&CK"),
    _t("winad.trusts-and-forests", "winad",
       "Authentication across domain and forest boundaries, and the filtering "
       "that is supposed to stop a compromise crossing one.",
       Register.ADVERSARY,
       ("nltest", "sidhistory", "domain trust", "forest trust",
        "trust relationship"),
       ("T1482", "T1484.002", "T1134.005"), spine="ATT&CK"),
    _t("winad.privesc-services-and-paths", "winad",
       "Local escalation through how Windows resolves and launches binaries: "
       "service paths, permissions, and library search order.",
       Register.ADVERSARY,
       ("icacls", "winpeas", "accesschk", "dll hijacking",
        "unquoted service path", "service binary replacement"),
       ("T1574.009", "T1574.001", "T1543.003"), spine="ATT&CK"),
    _t("winad.privesc-tokens-and-privileges", "winad",
       "Escalation by holding a privilege rather than owning a file: impersonation "
       "privileges, token theft, and the named-pipe tricks that use them.",
       Register.ADVERSARY,
       ("juicypotato", "potato attack", "sedebugprivilege",
        "token impersonation", "seimpersonateprivilege",
        "named pipe impersonation"),
       ("T1134", "T1134.001", "T1134.002"), spine="ATT&CK"),
    _t("winad.uac-and-integrity-levels", "winad",
       "The split-token elevation model, integrity levels, and the auto-elevating "
       "binaries and hijackable paths that bypass the prompt.",
       Register.ADVERSARY,
       ("eventvwr", "fodhelper", "uac bypass", "consent.exe",
        "high integrity", "auto-elevate binary"),
       ("T1548.002",), spine="ATT&CK"),
    _t("winad.windows-persistence", "winad",
       "Keeping execution across reboot and logon through documented Windows "
       "extensibility: run keys, tasks, services, WMI subscriptions, hijacks.",
       Register.ADVERSARY,
       ("run key", "schtasks", "startup folder",
        "image file execution options",
        "hkcu\\software\\microsoft\\windows\\currentversion\\run"),
       ("T1547.001", "T1053.005", "T1546.003", "T1546.012", "T1546.015"),
       spine="ATT&CK"),
    _t("winad.local-credential-stores", "winad",
       "Where a Windows host keeps secrets — process memory, SAM, DPAPI, the "
       "credential vault — and what reading each one yields.",
       Register.ADVERSARY,
       ("lsass", "wdigest", "mimikatz", "vaultcmd", "sam hive",
        "dpapi masterkey"),
       ("T1003.001", "T1003.002", "T1003.004", "T1555.004"), spine="ATT&CK"),
    _t("winad.windows-internals", "winad",
       "The kernel and user-mode structures security tooling depends on: tokens, "
       "security descriptors, the object namespace, syscall transitions.",
       Register.SYSTEM,
       ("sddl", "ntdll", "syscall", "kernel32", "security descriptor",
        "access token structure"),
       (), spine="cert objectives + vendor API docs"),

    # -- nix --------------------------------------------------------------
    _t("nix.privesc-setuid-and-sudo", "nix",
       "Escalation through programs that run with more authority than their "
       "caller: setuid binaries, file capabilities, and sudo rules.",
       Register.SHELL,
       ("sudoers", "linpeas", "nopasswd", "gtfobins", "setuid root",
        "file capability cap_setuid"),
       ("T1548.001", "T1548.003"), spine="ATT&CK + GTFOBins"),
    _t("nix.privesc-kernel", "nix",
       "Local escalation by exploiting the kernel itself, where the bug class and "
       "the kernel version decide everything.",
       Register.ADVISORY,
       ("pwnkit", "dirtycow", "dirty pipe", "cve-2021-4034",
        "kernel version", "exploit-db local"),
       ("T1068",), spine="ATT&CK + CVE records"),
    _t("nix.scheduled-and-service-execution", "nix",
       "Unix scheduling and service managers as execution paths: cron, systemd "
       "units and timers, init scripts, and library preloading.",
       Register.SYSTEM,
       ("crontab", "systemctl", "ld_preload", "service file",
        "systemd unit", "cron job writable"),
       ("T1053.003", "T1543.002", "T1574.006"), spine="ATT&CK"),
    _t("nix.file-permissions-and-acls", "nix",
       "The Unix permission model in practice: ownership, mode bits, the sticky "
       "bit, extended ACLs and attributes.",
       Register.SYSTEM,
       ("setfacl", "getfacl", "chmod 777", "sticky bit", "world-writable",
        "immutable attribute chattr"),
       ("T1222.002",), spine="ATT&CK + man pages"),
    _t("nix.persistence", "nix",
       "Surviving reboot and login on Unix hosts through shell startup files, "
       "authorized keys, preload paths and kernel modules.",
       Register.ADVERSARY,
       (".bashrc", "rc.local", "kernel module", "systemd timer",
        "authorized_keys"),
       ("T1546.004", "T1037.004", "T1098.004", "T1547.006"), spine="ATT&CK"),
    _t("nix.credential-locations", "nix",
       "Where credentials sit on a Unix host: the shadow file, private keys, "
       "cloud credential files, shell history, process arguments.",
       Register.ADVERSARY,
       ("id_rsa", "/etc/passwd", "/etc/shadow", ".bash_history",
        ".aws/credentials", "ssh private key harvest"),
       ("T1003.008", "T1552.001", "T1552.003", "T1552.004"), spine="ATT&CK"),
    _t("nix.logging-and-audit", "nix",
       "Unix audit and logging subsystems: what auditd and the journal record, "
       "where it lands, and how it is queried.",
       Register.DETECTION,
       ("auditd", "rsyslog", "auditctl", "journalctl", "auth.log entry",
        "syslog facility"),
       (), spine="D3FEND + man pages"),
    _t("nix.macos-specifics", "nix",
       "What is different about macOS: launchd jobs, the privacy consent "
       "database, code signing and quarantine, and AppleScript automation.",
       Register.SYSTEM,
       ("plist", "launchd", "osascript", "launchctl", "launchdaemon",
        "codesign verification"),
       ("T1543.001", "T1647", "T1553.001", "T1059.002"), spine="ATT&CK"),
    _t("nix.shell-mechanics", "nix",
       "The shell as a language: expansion, redirection, field splitting, job "
       "control and signal handling, which is what makes one-liners readable.",
       Register.SHELL,
       ("set -e", "globbing", "subshell", "parameter expansion",
        "trap signal handler", "command substitution"),
       (), spine="cert objectives (scripting) + man pages"),

    # -- cloud ------------------------------------------------------------
    _t("cloud.identity-and-privilege", "cloud",
       "Cloud authorisation as the real perimeter: roles, policies, assumption "
       "chains and the permission combinations that escalate.",
       Register.SYSTEM,
       ("iam policy", "assume role", "managed identity", "instance profile",
        "service principal"),
       ("T1078.004", "T1098.001", "T1098.003"), spine="ATT&CK cloud"),
    _t("cloud.instance-metadata", "cloud",
       "The link-local metadata service that hands credentials to anything that "
       "can make an HTTP request from the instance.",
       Register.SYSTEM,
       ("imds", "imdsv2", "169.254.169.254", "instance metadata",
        "metadata token header", "metadata.google.internal"),
       ("T1552.005",), spine="ATT&CK cloud"),
    _t("cloud.storage-exposure", "cloud",
       "Object storage made readable or writable by the wrong principals, and the "
       "policy and signing mechanics behind that.",
       Register.SYSTEM,
       ("s3 bucket", "presigned", "blob storage", "bucket policy",
        "public read access", "blob container public access"),
       ("T1530", "T1619"), spine="ATT&CK cloud"),
    _t("cloud.serverless-and-functions", "cloud",
       "Function platforms, where the execution role and the environment are the "
       "whole attack surface and there is no host to harden.",
       Register.SYSTEM,
       ("serverless", "function app", "azure function", "cloud function",
        "execution role"),
       ("T1648",), spine="ATT&CK cloud"),
    _t("cloud.audit-logging", "cloud",
       "Control-plane audit trails: what the provider records by default, where "
       "the gaps are, and how the events are queried.",
       Register.DETECTION,
       ("audit log", "guardduty", "cloudtrail", "stackdriver",
        "activity log", "control plane audit event"),
       ("T1685.002",), spine="D3FEND + provider docs"),
    _t("cloud.container-escape", "cloud",
       "Getting out of a container to the host, which is usually a configuration "
       "that was never a boundary: mounts, capabilities, privileged mode.",
       Register.ADVERSARY,
       ("hostpath", "cap_sys_admin", "container escape",
        "docker socket mount", "privileged container",
        "/var/run/docker.sock"),
       ("T1611", "T1610"), spine="ATT&CK containers"),
    _t("cloud.kubernetes-attacks", "cloud",
       "Cluster-level attack paths: service account tokens, RBAC bindings, the "
       "kubelet and etcd interfaces, and workload admission.",
       Register.SYSTEM,
       ("etcd", "kubectl", "kubelet", "kubernetes", "service account token"),
       ("T1613", "T1552.007"), spine="ATT&CK containers"),
    _t("cloud.image-and-registry", "cloud",
       "Container images as a distribution channel: layer contents, build-time "
       "secrets, registry credentials and provenance.",
       Register.SYSTEM,
       ("dockerfile", "image layer", "docker build", "image scanning",
        "registry credential", "base image vulnerability"),
       ("T1525", "T1612"), spine="ATT&CK containers + CIS"),
    _t("cloud.cicd-supply-chain", "cloud",
       "Build systems as production access: workflow injection, secret exposure "
       "in pipelines, trust policies, and dependency resolution order.",
       Register.SYSTEM,
       ("jenkins", "ci pipeline", "github actions", "oidc federation",
        "oidc trust policy", "pull_request_target"),
       ("T1195.002", "T1199"), spine="ATT&CK + SLSA"),

    # -- binexp -----------------------------------------------------------
    _t("binexp.stack-overflow", "binexp",
       "Overwriting saved control data on the stack, the classic exploitation "
       "path and the offset work it requires.",
       Register.ADVERSARY,
       ("gets()", "nop sled", "stack canary", "rip overwrite",
        "stack overflow", "pattern_offset"),
       (), spine="cert objectives; ATT&CK has no technique for this"),
    _t("binexp.heap-exploitation", "binexp",
       "Corrupting allocator state or reusing freed memory, where the exploit is "
       "built out of allocation order rather than a single overwrite.",
       Register.ADVERSARY,
       ("malloc", "tcache", "double free", "heap overflow",
        "use-after-free", "chunk metadata corruption"),
       (), spine="cert objectives + CWE"),
    _t("binexp.format-string", "binexp",
       "Passing attacker-controlled text as a format specifier, which yields "
       "both arbitrary reads and arbitrary writes.",
       Register.ADVERSARY,
       ("%p%p%p", "printf(", "varargs", "format string",
        "format specifier abuse"),
       (), spine="cert objectives + CWE"),
    _t("binexp.rop-and-mitigation-bypass", "binexp",
       "Reusing existing code once memory is no longer executable, and the "
       "information leaks that randomisation defences require first.",
       Register.ADVERSARY,
       ("aslr", "srop", "ret2libc", "rop chain", "rop gadget",
        "return-oriented programming"),
       (), spine="cert objectives"),
    _t("binexp.shellcode", "binexp",
       "Writing position-independent machine code that survives the transport "
       "constraints of the bug it is delivered through.",
       Register.ADVERSARY,
       ("\\x90", "msfvenom", "shellcode", "egghunter", "null-free",
        "position independent"),
       (), spine="cert objectives"),
    _t("binexp.windows-exploit-development", "binexp",
       "Windows-specific exploitation mechanics: exception-handler overwrites, "
       "module protection flags, and the debugger workflow around them.",
       Register.ADVERSARY,
       ("windbg", "safeseh", "mona.py", "seh overwrite",
        "immunity debugger", "dep bypass rop chain"),
       (), spine="cert objectives"),
    _t("binexp.fuzzing", "binexp",
       "Finding memory-safety bugs by generating input at scale, and turning the "
       "resulting crashes into something a developer can act on.",
       Register.SYSTEM,
       ("libfuzzer", "fuzz target", "coverage-guided", "address sanitizer",
        "corpus minimization"),
       (), spine="cert objectives + sanitizer docs"),
    _t("binexp.reverse-engineering", "binexp",
       "Recovering behaviour from a binary: disassembly, decompilation, calling "
       "conventions, and reconstructing structure from stripped code.",
       Register.SYSTEM,
       ("ghidra", "radare2", "objdump", "decompiler", "disassembly listing",
        "control flow graph recovery"),
       (), spine="cert objectives"),
    _t("binexp.memory-safety-bug-classes", "binexp",
       "The defect classes themselves, as a developer and an advisory describe "
       "them, rather than as an exploit technique.",
       Register.ADVISORY,
       ("off-by-one", "out-of-bounds", "uninitialized", "integer overflow",
        "null pointer dereference"),
       (), spine="CWE"),
    _t("binexp.kernel-exploitation", "binexp",
       "Exploiting kernel-mode bugs, where the primitives are pool allocations "
       "and the mitigations are supervisor-mode protections.",
       Register.ADVERSARY,
       ("smap", "smep", "kaslr", "ring 0", "kernel exploit",
        "kernel heap spray"),
       (), spine="cert objectives"),

    # -- credaccess -------------------------------------------------------
    _t("credaccess.password-cracking", "credaccess",
       "Recovering plaintext from captured hashes offline: attack modes, rules, "
       "masks and the cost of each hash format.",
       Register.SHELL,
       ("hashcat", "rockyou", "-m 1000", "rainbow table", "wordlist rule",
        "john the ripper"),
       ("T1110.002",), spine="ATT&CK"),
    _t("credaccess.online-guessing", "credaccess",
       "Guessing against a live service, where lockout policy and detection, not "
       "compute, set the budget.",
       Register.ADVERSARY,
       ("kerbrute", "brute force", "lockout policy", "password spraying",
        "login attempt throttling", "account lockout threshold"),
       ("T1110.001", "T1110.003", "T1110.004"), spine="ATT&CK"),
    _t("credaccess.host-credential-dumping", "credaccess",
       "Extracting credential material from a host's own stores and process "
       "memory once code is running on it.",
       Register.ADVERSARY,
       ("pypykatz", "cachedump", "lsa secrets", "credential dumping",
        "cached domain credentials", "proc filesystem memory read"),
       ("T1003", "T1003.005", "T1003.007"), spine="ATT&CK"),
    _t("credaccess.unsecured-credentials", "credaccess",
       "Credentials sitting in files, scripts, images and management systems "
       "where no exploitation is needed to read them.",
       Register.ADVERSARY,
       (".env file", "web.config", "credential file",
        "hardcoded credential", "plaintext credentials",
        "cleartext password in script"),
       ("T1552", "T1552.001", "T1552.002", "T1552.006"), spine="ATT&CK"),
    _t("credaccess.token-and-cookie-theft", "credaccess",
       "Stealing the artefact that proves an authentication already happened, "
       "which sidesteps the password and often the second factor.",
       Register.ADVERSARY,
       ("oauth token", "refresh token", "session cookie",
        "access token theft"),
       ("T1539", "T1550.001", "T1528"), spine="ATT&CK"),
    _t("credaccess.mfa-bypass", "credaccess",
       "Defeating a second factor without breaking its cryptography: proxying "
       "the login, exhausting the user, or registering a new factor.",
       Register.ADVERSARY,
       ("evilginx", "sim swap", "mfa bypass", "device code", "mfa fatigue",
        "mfa registration abuse"),
       ("T1621", "T1556.006"), spine="ATT&CK"),
    _t("credaccess.input-capture", "credaccess",
       "Collecting credentials as they are typed or prompted for, in user space "
       "or by imitating the operating system's own prompt.",
       Register.ADVERSARY,
       ("keylogger", "input capture", "setwindowshookex",
        "getasynckeystate", "keystroke logging",
        "credential prompt spoofing"),
       ("T1056", "T1056.001", "T1056.002"), spine="ATT&CK"),

    # -- evasion ----------------------------------------------------------
    _t("evasion.process-injection", "evasion",
       "Running code inside another process's address space, the family that "
       "separates a payload's code from its apparent owner.",
       Register.ADVERSARY,
       ("reflective dll", "process injection", "process hollowing",
        "writeprocessmemory", "createremotethread"),
       ("T1055", "T1055.001", "T1055.012"), spine="ATT&CK TA0005"),
    _t("evasion.script-logging-bypass", "evasion",
       "Defeating the in-process inspection and logging that scripting hosts "
       "perform before they execute anything.",
       Register.ADVERSARY,
       ("amsibypass", "etw bypass", "amsi bypass", "script block logging",
        "constrained language mode"),
       ("T1685",), spine="ATT&CK TA0112"),
    _t("evasion.endpoint-sensor-evasion", "evasion",
       "Avoiding or removing the hooks and callbacks an endpoint product relies "
       "on, including loading a vulnerable driver to do it.",
       Register.ADVERSARY,
       ("byovd", "unhooking", "direct syscall", "userland hook bypass",
        "kernel callback removal", "bring your own vulnerable driver"),
       ("T1685", "T1068"), spine="ATT&CK TA0112"),
    _t("evasion.obfuscation-and-packing", "evasion",
       "Changing a payload's surface form without changing what it does, so that "
       "signatures and analysts both have more work to do.",
       Register.ADVERSARY,
       ("xor encoded", "base64 encoded", "software packing",
        "invoke-obfuscation", "command obfuscation", "encoded command line"),
       ("T1027", "T1027.002", "T1027.010"), spine="ATT&CK TA0005"),
    _t("evasion.living-off-the-land", "evasion",
       "Using the platform's own signed utilities to download, execute and proxy, "
       "so nothing new has to be dropped on disk.",
       Register.SHELL,
       ("wmic", "mshta", "lolbas", "lolbin", "rundll32",
        "regsvr32 scriptlet"),
       ("T1218", "T1218.011", "T1218.010", "T1216"), spine="ATT&CK TA0005"),
    _t("evasion.log-tampering-and-anti-forensics", "evasion",
       "Removing or corrupting the record after the fact: event logs, file "
       "timestamps, journals and shell history.",
       Register.ADVERSARY,
       ("wevtutil", "timestomp", "history -c", "fsutil usn",
        "clear-eventlog"),
       ("T1070", "T1070.003", "T1070.006", "T1685.005", "T1685.006"),
       spine="ATT&CK TA0112"),
    _t("evasion.masquerading-and-trust-abuse", "evasion",
       "Looking legitimate: names, paths, icons, extensions and signatures that "
       "make a payload read as something expected.",
       Register.ADVERSARY,
       ("masquerading", "signed binary", "icon spoofing",
        "double extension", "match legitimate name",
        "right-to-left override"),
       ("T1036", "T1036.005", "T1553", "T1553.002"), spine="ATT&CK TA0005"),
    _t("evasion.sandbox-and-analysis-evasion", "evasion",
       "Deciding not to run: checks for virtualisation, instrumentation, analyst "
       "tooling, or an environment that does not match the target.",
       Register.ADVERSARY,
       ("sleep evasion", "sandbox evasion", "isdebuggerpresent",
        "sandbox detection", "debugger detection", "anti-analysis check"),
       ("T1497", "T1497.001", "T1480"), spine="ATT&CK TA0005"),
    _t("evasion.rootkits-and-kernel-tampering", "evasion",
       "Hiding below the layer that does the looking, by modifying kernel "
       "structures, drivers or the boot path.",
       Register.ADVERSARY,
       ("ssdt", "dkom", "rootkit", "bootkit", "unsigned driver",
        "direct kernel object manipulation"),
       ("T1014", "T1542", "T1601"), spine="ATT&CK TA0005"),
    _t("evasion.defence-impairment", "evasion",
       "Turning the defences off rather than sneaking past them: stopping agents, "
       "adding exclusions, killing telemetry, opening the firewall.",
       Register.ADVERSARY,
       ("stop-service", "disable defender", "netsh advfirewall",
        "tamper protection", "disable etw provider", "disable security tool"),
       ("TA0112", "T1685", "T1685.001", "T1686"), spine="ATT&CK TA0112"),

    # -- lateral ----------------------------------------------------------
    _t("lateral.remote-execution", "lateral",
       "Starting a process on another host with credentials you already have, "
       "through the platform's own remote management surfaces.",
       Register.SHELL,
       ("winrs", "psexec", "wmiexec", "smbexec", "invoke-command",
        "wmi remote process create"),
       ("T1021", "T1047", "T1021.006", "T1569.002"), spine="ATT&CK TA0008"),
    _t("lateral.credential-reuse-movement", "lateral",
       "Moving with stolen authentication material rather than a password, using "
       "tickets, hashes and cached credential files.",
       Register.ADVERSARY,
       ("klist", "ccache", "pass-the-ticket", "ticket cache file",
        "kerberos ticket injection", "credential reuse across hosts"),
       ("T1550", "T1550.003"), spine="ATT&CK TA0008"),
    _t("lateral.port-forwarding-and-tunnelling", "lateral",
       "Carrying a connection through a host you control: local, remote and "
       "dynamic forwards, and the OS features that do it without tooling.",
       Register.SHELL,
       ("plink", "ssh -l", "netsh portproxy", "socks proxy pivot",
        "dynamic port forward", "tunnel through compromised host"),
       ("T1572", "T1090", "T1090.001"), spine="cert objectives (ATT&CK describes only the outcome)"),
    _t("lateral.pivoting-and-routing", "lateral",
       "Making an internal network reachable from the operator's tooling, and "
       "keeping track of which route a given request takes.",
       Register.SHELL,
       ("ligolo", "sshuttle", "autoroute", "pivot host", "proxychains",
        "network route through implant"),
       ("T1090",), spine="cert objectives"),
    _t("lateral.covert-tunnelling-protocols", "lateral",
       "Tunnelling over protocols that are allowed outbound when nothing else "
       "is: DNS, ICMP, and HTTP as a transport rather than a protocol.",
       Register.ADVERSARY,
       ("dnscat", "ptunnel", "txt record", "icmp tunnel", "dns tunneling",
        "dns tunnelling"),
       ("T1071.004", "T1095", "T1572"), spine="ATT&CK + cert objectives"),
    _t("lateral.internal-spread", "lateral",
       "Spreading without remote execution: writing to shares, poisoning content "
       "others open, and scheduling work on the far host.",
       Register.ADVERSARY,
       ("at.exe", "c$ share", "admin share", "schtasks /s", "copy to share",
        "remote scheduled task"),
       ("T1021.002", "T1080", "T1534"), spine="ATT&CK TA0008"),
    _t("lateral.session-hijacking", "lateral",
       "Taking over an interactive session that someone else already "
       "authenticated, locally or remotely.",
       Register.ADVERSARY,
       ("tscon", "screen -x", "rdp hijack", "tmux attach",
        "session hijacking", "terminal multiplexer"),
       ("T1563", "T1563.001", "T1563.002"), spine="ATT&CK TA0008"),

    # -- c2exfil ----------------------------------------------------------
    _t("c2exfil.channel-selection", "c2exfil",
       "Choosing what the implant talks over and how that traffic is shaped to "
       "look like the environment's normal egress.",
       Register.ADVERSARY,
       ("c2 channel", "c2 profile", "cobalt strike", "domain fronting",
        "web service as c2", "command and control channel"),
       ("T1071", "T1071.001", "T1102", "T1090.004"), spine="ATT&CK TA0011"),
    _t("c2exfil.beaconing-patterns", "c2exfil",
       "The timing of implant check-ins — interval, jitter, sleep behaviour — "
       "which is both an operator setting and a detection signal.",
       Register.DETECTION,
       ("sleep mask", "beacon jitter", "beacon timing", "sleep interval",
        "beacon interval", "beaconing detection"),
       ("T1029", "T1071"), spine="ATT&CK + detection practice"),
    _t("c2exfil.encrypted-and-encoded-c2", "c2exfil",
       "Protecting channel content from inspection, and the fingerprints that "
       "the protection itself leaves behind.",
       Register.ADVERSARY,
       ("jarm", "ja3s", "rc4 key", "encrypted c2", "tls fingerprint",
        "aes-256 payload"),
       ("T1573", "T1573.001", "T1573.002", "T1132"), spine="ATT&CK TA0011"),
    _t("c2exfil.resilient-resolution", "c2exfil",
       "Keeping a channel reachable when infrastructure is taken down: generated "
       "domains, rapidly rotating records, and fallback paths.",
       Register.ADVERSARY,
       ("dead drop", "fast flux", "fallback channel", "domain generation"),
       ("T1568", "T1568.001", "T1568.002", "T1008", "T1102.001"),
       spine="ATT&CK TA0011"),
    _t("c2exfil.collection-and-staging", "c2exfil",
       "Gathering data on the target side and preparing it for transfer: staging "
       "directories, archiving, splitting and encrypting.",
       Register.ADVERSARY,
       ("7z a -p", "rar a -hp", "staging directory", "local data staging",
        "archive before exfil", "archive collected data"),
       ("T1074", "T1560", "T1560.001", "T1005"), spine="ATT&CK TA0009"),
    _t("c2exfil.exfiltration-paths", "c2exfil",
       "Getting the data out, and the choice of path: the existing channel, a "
       "cloud service, a different protocol, or physical media.",
       Register.ADVERSARY,
       ("curl -t", "data exfil", "exfil over dns", "upload to pastebin",
        "exfiltration over c2 channel", "exfiltration over web service"),
       ("T1041", "T1567", "T1567.002", "T1048", "T1030"), spine="ATT&CK TA0010"),
    _t("c2exfil.server-side-implants", "c2exfil",
       "Persistence on an internet-facing server as both foothold and channel: "
       "web shells, server modules and exposed management agents.",
       Register.ADVERSARY,
       ("webshell", "web shell", "iis module", "china chopper",
        "aspx shell upload", "server software component"),
       ("T1505", "T1505.003", "T1505.004"), spine="ATT&CK"),

    # -- socialclient -----------------------------------------------------
    _t("socialclient.phishing-email", "socialclient",
       "Mail-delivered social engineering: the pretext, the sender trust it "
       "borrows, and whether the payload is a link or a file.",
       Register.ADVERSARY,
       ("spearphishing", "phishing email", "lookalike domain",
        "from header spoofing"),
       ("T1566", "T1566.001", "T1566.002"), spine="ATT&CK"),
    _t("socialclient.document-and-file-payloads", "socialclient",
       "The container that carries the first stage: macro documents, shortcut "
       "files, archive and image formats that bypass mark-of-the-web.",
       Register.ADVERSARY,
       (".lnk", "maldoc", "html smuggling", "iso attachment",
        "mark-of-the-web", "lnk file payload"),
       ("T1204.002", "T1137", "T1027.006", "T1553.005"), spine="ATT&CK"),
    _t("socialclient.browser-and-client-exploitation", "socialclient",
       "Attacking the software the user opens content with, rather than asking "
       "the user to run something.",
       Register.ADVERSARY,
       ("drive-by", "exploit kit", "watering hole", "browser exploit",
        "malicious extension"),
       ("T1189", "T1203", "T1176"), spine="ATT&CK + cert objectives"),
    _t("socialclient.voice-and-message-pretexting", "socialclient",
       "Social engineering over channels with no attachment to inspect: calls, "
       "text messages, chat platforms and in-person pretexts.",
       Register.PROSE,
       ("vishing", "smishing", "pretexting", "helpdesk impersonation",
        "social engineering call"),
       ("T1598", "T1566.003", "T1566.004"), spine="ATT&CK + cert objectives"),
    _t("socialclient.phishing-infrastructure", "socialclient",
       "The operator's side: domains, certificates, landing pages and the "
       "proxying tooling that makes a credential capture convincing.",
       Register.ADVERSARY,
       ("gophish", "evilginx2", "phishing page", "typosquatting",
        "credential harvester", "credential capture page"),
       ("T1583.001", "T1608", "T1587.003"), spine="ATT&CK"),
    _t("socialclient.awareness-and-reporting", "socialclient",
       "The defensive side of social engineering: simulation programmes, "
       "reporting paths, and what measurably changes user behaviour.",
       Register.PROSE,
       ("user training", "security awareness", "phishing simulation",
        "user reported message", "report phishing button",
        "report suspicious email"),
       (), spine="NICE + D3FEND"),

    # -- wireless ---------------------------------------------------------
    _t("wireless.wifi-authentication-attacks", "wireless",
       "Attacking WPA personal authentication: capturing the material that lets "
       "a passphrase be cracked, and the newer handshake's own weaknesses.",
       Register.SHELL,
       ("wpa2", "pmkid", "deauth", "aircrack-ng", "airodump-ng",
        "hcxdumptool"),
       (), spine="cert objectives + IEEE 802.11; ATT&CK silent"),
    _t("wireless.rogue-access-points", "wireless",
       "Standing up an access point the client trusts, and the portal and "
       "association behaviour that makes clients connect to it.",
       Register.SHELL,
       ("hostapd", "rogue ap", "evil twin", "wifiphisher", "captive portal",
        "rogue access point"),
       (), spine="cert objectives"),
    _t("wireless.enterprise-wifi", "wireless",
       "802.1X wireless, where the attack is against certificate validation and "
       "the inner authentication method rather than a passphrase.",
       Register.SYSTEM,
       ("802.1x", "eap-tls", "eaphammer", "radius server", "wpa enterprise",
        "credential capture"),
       (), spine="cert objectives + RFC 5216"),
    _t("wireless.bluetooth-and-ble", "wireless",
       "Short-range personal-area radio: pairing and bonding, GATT services, "
       "and what an unauthenticated scanner can read.",
       Register.SYSTEM,
       ("gatt", "pairing", "hcitool", "bluetooth", "ble advertisement"),
       ("T1011.001",), spine="cert objectives + Bluetooth spec"),
    _t("wireless.rfid-and-nfc", "wireless",
       "Contactless credentials at high and low frequency, their ciphers and "
       "formats, and cloning versus relaying them.",
       Register.SYSTEM,
       ("rfid", "mifare", "em4100", "wiegand", "iso14443", "proxmark"),
       (), spine="cert objectives + ISO 14443"),
    _t("wireless.sdr-and-subghz", "wireless",
       "Capturing and replaying arbitrary radio below the familiar bands, where "
       "modulation and encoding are the first problem.",
       Register.SYSTEM,
       ("hackrf", "sub-ghz", "rtl-sdr", "gnuradio", "ook modulation",
        "software defined radio"),
       (), spine="cert objectives"),
    _t("wireless.physical-access", "wireless",
       "Getting into the building and onto the network physically: doors, badges, "
       "ports and dropped devices.",
       Register.PROSE,
       ("usb drop", "lock pick", "tailgating", "rubber ducky",
        "badge cloning", "physical security"),
       ("T1200", "T1091"), spine="cert objectives + OSSTMM"),

    # -- detect -----------------------------------------------------------
    _t("detect.sigma-rules", "detect",
       "Vendor-neutral detection rules: the selection and condition structure, "
       "log source declarations, and how they translate per platform.",
       Register.DETECTION,
       ("sigmac", "logsource", "sigma rule", "falsepositives",
        "sigma field mapping", "condition: selection"),
       (), spine="Sigma specification"),
    _t("detect.windows-telemetry", "detect",
       "The Windows event and sensor data detections are written against, "
       "channel by channel and event id by event id.",
       Register.DETECTION,
       ("4688", "4624", "sysmon", "event id", "winlogbeat",
        "security event log channel"),
       (), spine="D3FEND + vendor event reference"),
    _t("detect.linux-telemetry", "detect",
       "The equivalent on Unix hosts: audit subsystem records, kernel-level "
       "probes and endpoint query tooling.",
       Register.DETECTION,
       ("ebpf", "auditd", "sysdig", "osquery", "audit.log"),
       (), spine="D3FEND"),
    _t("detect.network-detection", "detect",
       "Detection from traffic rather than hosts: signature engines, protocol "
       "logs, and fingerprints of encrypted sessions.",
       Register.DETECTION,
       ("pcap", "netflow", "conn.log", "snort signature", "ja3 fingerprint"),
       (), spine="D3FEND + rule-language references"),
    _t("detect.siem-query-languages", "detect",
       "Expressing a detection as a query in a specific analytics platform's "
       "language, including sequence and join semantics.",
       Register.DETECTION,
       ("splunk", "tstats", "index=", "eql sequence", "stats by command",
        "elasticsearch query"),
       (), spine="vendor query references"),
    _t("detect.file-and-malware-signatures", "detect",
       "Matching files rather than behaviour: byte and string signatures, "
       "structural hashes, and fuzzy similarity.",
       Register.DETECTION,
       ("ssdeep", "imphash", "pe header", "import hash", "rule condition",
        "fuzzy hash similarity"),
       (), spine="YARA documentation"),
    _t("detect.threat-hunting", "detect",
       "Looking for what no rule fires on: forming a hypothesis, choosing the "
       "data, and the aggregation patterns that make outliers visible.",
       Register.PROSE,
       ("threat hunting", "stack counting", "pyramid of pain",
        "anomaly detection", "hypothesis-driven", "parent-child process"),
       (), spine="D3FEND + hunting methodology"),
    _t("detect.detection-lifecycle", "detect",
       "Treating detections as software: version control, tuning, triage "
       "workflow, and measuring the coverage you claim.",
       Register.PROSE,
       ("rule tuning", "alert fatigue", "validation test",
        "false positive rate", "detection engineering",
        "alert triage workflow"),
       (), spine="D3FEND + detection-engineering practice"),
    _t("detect.countermeasure-mapping", "detect",
       "Mapping defences to the behaviours they address, which is what makes "
       "'we cover that' a checkable claim rather than an assertion.",
       Register.PROSE,
       ("d3fend", "mitre engage", "digital artifact ontology",
        "attack technique coverage mapping"),
       (), spine="D3FEND"),

    # -- dfir -------------------------------------------------------------
    _t("dfir.disk-forensics", "dfir",
       "Reading the filesystem below the API: allocation structures, journals, "
       "deleted content and acquired images.",
       Register.SYSTEM,
       ("usnjrnl", "sleuthkit", "mft record", "shadow copy", "ntfs metadata"),
       (), spine="NIST SP 800-86"),
    _t("dfir.memory-forensics", "dfir",
       "Analysing a captured memory image for process, network and injected-code "
       "state that no disk artefact records.",
       Register.SYSTEM,
       ("pslist", "malfind", "memory dump", "volatility plugin",
        "kernel structure scan", "injected code in memory"),
       (), spine="NIST SP 800-86"),
    _t("dfir.windows-artifacts", "dfir",
       "The execution and user-activity artefacts Windows writes as a side "
       "effect, which is where most host timelines come from.",
       Register.SYSTEM,
       ("amcache", "lnk file", "prefetch", "shimcache", "shellbags"),
       (), spine="DFIR practice + vendor documentation"),
    _t("dfir.timeline-analysis", "dfir",
       "Merging artefacts from many sources into one ordered account of what "
       "happened, and pivoting within it.",
       Register.PROSE,
       ("mactime", "timeline", "log2timeline", "event correlation",
        "correlation window", "timestamp analysis"),
       (), spine="NIST SP 800-86"),
    _t("dfir.incident-response-process", "dfir",
       "The process around the analysis: phases, decision points, evidence "
       "handling, and what is written down afterwards.",
       Register.PROSE,
       ("postmortem", "chain of custody", "incident response",
        "post-incident review", "containment eradication recovery",
        "incident severity classification"),
       (), spine="NIST SP 800-61"),
    _t("dfir.malware-triage", "dfir",
       "Working out what a sample does, quickly: static indicators, controlled "
       "execution, unpacking, and pulling out its configuration.",
       Register.PROSE,
       ("unpacking", "import table", "sandbox report", "malware analysis",
        "config extraction", "static analysis of sample"),
       (), spine="D3FEND + malware-analysis practice"),
    _t("dfir.cloud-and-saas-investigation", "dfir",
       "Investigating with only provider-side records: audit logs, consent "
       "grants, and identity events across tenants.",
       Register.DETECTION,
       ("m365 audit", "sign-in log", "oauth consent", "unified audit log",
        "tenant investigation"),
       (), spine="NIST SP 800-61 + provider documentation"),

    # -- harden -----------------------------------------------------------
    _t("harden.windows-hardening", "harden",
       "Reducing what a Windows host will execute and what its secrets are worth: "
       "execution control, credential isolation, surface reduction.",
       Register.SYSTEM,
       ("wdac", "applocker", "lsa protection", "credential guard",
        "attack surface reduction rule"),
       (), spine="D3FEND + CIS benchmarks"),
    _t("harden.linux-hardening", "harden",
       "Confining Unix processes to what they need: mandatory access control, "
       "syscall filtering, kernel tunables and service sandboxing.",
       Register.SYSTEM,
       ("sysctl", "selinux", "seccomp", "apparmor", "capabilities drop",
        "systemd sandboxing option"),
       (), spine="D3FEND + CIS benchmarks"),
    _t("harden.network-segmentation", "harden",
       "Limiting where a compromise can go: segmentation, egress control, and "
       "per-request access decisions instead of network location.",
       Register.PROSE,
       ("zero trust", "acl on vlan", "egress filtering", "firewall ruleset",
        "microsegmentation", "network segmentation"),
       (), spine="D3FEND + NIST SP 800-207"),
    _t("harden.identity-hardening", "harden",
       "Protecting the accounts that matter: administrative tiering, dedicated "
       "workstations, conditional policy, and time-bound privilege.",
       Register.PROSE,
       ("tier 0", "just-in-time", "protected users", "privileged access",
        "conditional access", "tiered administration model"),
       (), spine="D3FEND + vendor guidance"),
    _t("harden.patch-and-configuration-management", "harden",
       "Keeping the estate at a known state: patch cycles, baselines, images, "
       "and detecting drift away from them.",
       Register.PROSE,
       ("stig", "patch management", "configuration drift",
        "configuration baseline", "golden image hardening"),
       (), spine="NIST SP 800-53 + CIS"),
    _t("harden.backup-and-resilience", "harden",
       "The control that decides whether destructive impact is an outage or a "
       "catastrophe: isolated copies, and tested restoration.",
       Register.PROSE,
       ("3-2-1 backup", "offline backup", "immutable backup",
        "backup isolation", "restore procedure", "recovery time objective"),
       (), spine="NIST SP 800-53"),
    _t("harden.secrets-management", "harden",
       "Keeping credentials out of files and short-lived where possible: vaults, "
       "dynamic issuance, rotation and key custody.",
       Register.SYSTEM,
       ("key rotation", "hashicorp vault", "secrets management",
        "credential hygiene", "key management service",
        "secret injection at runtime"),
       (), spine="D3FEND + ASVS V6"),
    _t("harden.control-frameworks", "harden",
       "Control catalogues and the mapping work around them, which is how "
       "technical hardening is reported to people who buy it.",
       Register.PROSE,
       ("800-53", "nist csf", "iso 27001", "control mapping",
        "compensating control", "control assessment procedure"),
       (), spine="NIST SP 800-53 + ISO 27001"),

    # -- aisec ------------------------------------------------------------
    _t("aisec.prompt-injection", "aisec",
       "Instructions reaching a model from its data rather than its operator, "
       "directly or through content it retrieves.",
       Register.ADVERSARY,
       ("llm01", "jailbreak", "system prompt", "prompt injection",
        "indirect injection", "instruction override in content"),
       ("T1698", "T1699"), ("AML.T0051", "AML.T0051.000", "AML.T0069"),
       spine="ATLAS + ATT&CK v20"),
    _t("aisec.data-and-model-poisoning", "aisec",
       "Corrupting what a model learned or what it retrieves, so the failure is "
       "built in rather than induced at inference time.",
       Register.ADVERSARY,
       ("rag poisoning", "data poisoning", "backdoor attack",
        "backdoor trigger in model"),
       ("T1608.007",), ("AML.T0018", "AML.T0020", "AML.T0070", "AML.T0071"),
       spine="ATLAS"),
    _t("aisec.model-theft-and-inference-attacks", "aisec",
       "Extracting the asset through the interface: the weights, the training "
       "data membership, or a usable replica.",
       Register.ADVERSARY,
       ("proxy model", "model stealing", "model inversion",
        "model extraction", "distillation attack", "membership inference"),
       (), ("AML.T0024", "AML.T0005", "AML.T0057"),
       spine="ATLAS"),
    _t("aisec.adversarial-examples", "aisec",
       "Inputs crafted to be classified wrongly while looking unchanged, and the "
       "transfer of those inputs between models.",
       Register.ADVERSARY,
       ("adversarial attack", "adversarial example",
        "adversarial perturbation", "evasion attack on classifier"),
       (), ("AML.T0015", "AML.T0043"),
       spine="ATLAS"),
    _t("aisec.ai-supply-chain", "aisec",
       "The artefacts an AI system loads at startup — weights, datasets, "
       "notebooks, tool definitions — as a code-execution surface.",
       Register.ADVERSARY,
       ("pickle file", "safetensors", "model artifact", "untrusted model",
        "huggingface model", "supply chain compromise"),
       ("T1195.002",), ("AML.T0010", "AML.T0010.003"),
       spine="ATLAS"),
    _t("aisec.agent-and-tool-abuse", "aisec",
       "Autonomous systems that can act: tool invocation chains, over-broad "
       "authority, and the boundary where a plan becomes an action.",
       Register.TRAJECTORY,
       ("tool call", "tool abuse", "agent action", "agent guardrail",
        "function calling", "excessive agency"),
       ("T1700", "T1685.007"), ("AML.T0053", "AML.T0072"),
       spine="ATLAS + ATT&CK v20"),
    _t("aisec.ai-system-defences", "aisec",
       "Controls specific to model-driven systems: input and output mediation, "
       "privilege separation for tools, and adversarial evaluation.",
       Register.PROSE,
       ("ai red teaming", "ai safety control",
        "input sanitisation for prompts",
        "output filtering for model responses"),
       (), ("AML.TA0012",),
       spine="ATLAS mitigations"),

    # -- method -----------------------------------------------------------
    _t("method.engagement-scoping", "method",
       "Agreeing what may be tested, when, by whom and under what authority, "
       "which is the document that makes the work lawful.",
       Register.PROSE,
       ("in-scope", "out of scope", "authorisation", "testing window",
        "engagement letter", "rules of engagement"),
       (), spine="PTES + NIST SP 800-115"),
    _t("method.assessment-phases", "method",
       "The ordered phases of an assessment and what each is for, including the "
       "distinction between a scan, a test and an emulation.",
       Register.PROSE,
       ("ptes", "post-exploitation", "assessment methodology",
        "penetration testing execution standard",
        "open source security testing methodology"),
       (), spine="PTES + OSSTMM + NIST SP 800-115"),
    _t("method.evidence-handling", "method",
       "Capturing proof that is reproducible and defensible, and keeping a record "
       "of what the tester did and when.",
       Register.PROSE,
       ("activity log", "proof of concept", "reproduction steps",
        "audit trail of testing", "evidence capture during test"),
       (), spine="NIST SP 800-115 + PTES"),
    _t("method.risk-rating", "method",
       "Turning a technical finding into a rating a business can act on: scoring "
       "systems, likelihood and impact, and context adjustment.",
       Register.PROSE,
       ("risk rating", "impact rating", "business impact",
        "likelihood and impact", "severity justification"),
       (), spine="NIST SP 800-115 + CVSS"),
    _t("method.report-writing", "method",
       "The deliverable: executive framing, finding structure, remediation "
       "advice, and retest. No ATT&CK technique describes any of it.",
       Register.PROSE,
       ("report template", "summary section", "findings section",
        "executive summary", "remediation recommendation"),
       (), spine="cert objectives + PTES; ATT&CK silent"),
    _t("method.threat-modelling", "method",
       "Reasoning about where a system can be attacked before testing it, using "
       "decomposition and trust boundaries rather than a scanner.",
       Register.PROSE,
       ("abuse case", "attack tree", "threat model", "trust boundary",
        "stride category", "data flow diagram"),
       (), spine="NIST SP 800-154 + practice"),
    _t("method.purple-team-exercise", "method",
       "Running a known attack specifically to see whether detection fires, and "
       "measuring the result rather than the activity.",
       Register.PROSE,
       ("caldera", "atomic test", "purple team", "atomic red team",
        "adversary emulation", "detection validation run"),
       ("TA0043",), spine="MITRE Engage + ATT&CK Evaluations"),
    _t("method.legal-and-disclosure", "method",
       "The rules around the work: authority to test, disclosure handling, and "
       "the protections that make reporting a bug safe.",
       Register.PROSE,
       ("bug bounty", "safe harbor", "safe harbour clause",
        "responsible disclosure", "coordinated disclosure",
        "computer misuse legislation"),
       (), spine="cert objectives + ISO 29147"),
    _t("method.workforce-knowledge-framework", "method",
       "The public workforce taxonomy: work roles described as knowledge, skill "
       "and task statements, which is the nearest open thing to a syllabus.",
       Register.PROSE,
       ("800-181", "work role", "nice framework", "knowledge statement"),
       (), spine="NICE (NIST SP 800-181)"),

    # -- tooling ----------------------------------------------------------
    _t("tooling.shell-scripting", "tooling",
       "Writing and reading shell scripts well enough to automate an engagement "
       "step and to audit someone else's one-liner.",
       Register.SHELL,
       ("xargs", "sed -i", "#!/bin/bash", "awk '{print",
        "awk field separator", "command substitution"),
       (), spine="cert objectives (scripting)"),
    _t("tooling.powershell-scripting", "tooling",
       "PowerShell as both the administrative language of Windows and the "
       "offensive one: pipelines, objects, remoting, modules.",
       Register.SHELL,
       ("param(", "new-object", "get-childitem", "enter-pssession",
        "invoke-webrequest", "cmdletbinding parameter"),
       ("T1059.001",), spine="cert objectives + vendor documentation"),
    _t("tooling.python-tooling", "tooling",
       "Python as the glue: HTTP clients, sockets, argument parsing, and the "
       "small purpose-built tools an engagement needs.",
       Register.SYSTEM,
       ("asyncio", "argparse", "def main()", "import socket",
        "import requests", "socket connect script"),
       ("T1059.006",), spine="cert objectives (scripting)"),
    _t("tooling.exploitation-frameworks", "tooling",
       "The frameworks that package exploitation: module options, payload "
       "selection, session handling and post-exploitation modules.",
       Register.SHELL,
       ("msfconsole", "metasploit", "meterpreter", "set payload",
        "exploit/multi", "payload handler listener"),
       ("T1588.002",), spine="cert objectives"),
    _t("tooling.command-output-interpretation", "tooling",
       "Reading what a tool printed: the column layouts and formats that carry "
       "the answer, which an agent must parse before it can decide.",
       Register.SHELL,
       ("ps aux", "lsof -i", "tasklist", "ss -tulpn", "netstat -ano",
        "ipconfig /all"),
       (), spine="corpus SHELL register + man pages"),
    _t("tooling.agent-protocol", "tooling",
       "The machine-readable action protocol an autonomous operator emits, and "
       "the budgets and approvals that bound it.",
       Register.TRAJECTORY,
       ("\"action\":", "tool call", "tool_call", "step limit",
        "approval required", "operator approval gate"),
       (), spine="this runtime's own protocol"),
    _t("tooling.regex-and-parsing", "tooling",
       "Matching and extracting text reliably, including the failure modes that "
       "turn a parser into an outage.",
       Register.SYSTEM,
       ("grep -e", "lookahead", "re.compile", "backtracking",
        "capture group"),
       (), spine="cert objectives + regex references"),

    # -- vulnmgmt ---------------------------------------------------------
    _t("vulnmgmt.vulnerability-records", "vulnmgmt",
       "The identifier-and-metadata form a vulnerability takes in public "
       "databases: affected ranges, product identifiers, references.",
       Register.ADVISORY,
       ("cpe match", "cve identifier", "vulnerable range",
        "affected versions", "vulnerability record"),
       (), spine="NVD / CVE"),
    _t("vulnmgmt.severity-scoring", "vulnmgmt",
       "Scoring systems as strings and as arguments: vector components, base "
       "versus environmental scores, and what they omit.",
       Register.ADVISORY,
       ("cvss v3", "cvss vector", "base metric", "environmental score",
        "attack vector network"),
       (), spine="CVSS specification"),
    _t("vulnmgmt.weakness-classification", "vulnmgmt",
       "The defect taxonomy underneath individual vulnerabilities, which is what "
       "makes two CVEs the same bug class.",
       Register.ADVISORY,
       ("cwe-79", "cwe-89", "cwe identifier", "common weakness",
        "weakness relationship parent"),
       (), spine="CWE"),
    _t("vulnmgmt.exploitation-status", "vulnmgmt",
       "Whether anyone is actually exploiting it: exploitation catalogues, "
       "prediction scoring, and public proof-of-concept availability.",
       Register.ADVISORY,
       ("in the wild", "known exploited", "exploit available",
        "proof of concept exploit availability"),
       (), spine="CISA KEV + EPSS"),
    _t("vulnmgmt.advisory-reading", "vulnmgmt",
       "Extracting the operational answer from a vendor or ecosystem advisory: "
       "what is affected, what fixes it, what to do meanwhile.",
       Register.ADVISORY,
       ("workaround", "patched version", "security advisory",
        "affected packages", "advisory severity assignment"),
       (), spine="GHSA / vendor advisories"),
    _t("vulnmgmt.dependency-and-sbom", "vulnmgmt",
       "Knowing what is in a build and which of it is vulnerable, including "
       "dependencies nobody chose directly.",
       Register.ADVISORY,
       ("sbom", "cyclonedx", "package.json", "lockfile audit",
        "requirements.txt", "transitive dependency"),
       (), spine="CycloneDX / SPDX + ecosystem advisories"),

    # -- crypto -----------------------------------------------------------
    _t("crypto.tls-and-pki", "crypto",
       "Transport security as deployed: handshake and version negotiation, "
       "certificate validation, revocation and pinning.",
       Register.SYSTEM,
       ("ocsp", "x.509", "cipher suite", "tls handshake",
        "certificate chain"),
       ("T1573.002",), spine="RFC 8446 + ASVS V9"),
    _t("crypto.primitive-misuse", "crypto",
       "Correct primitives used wrongly: mode choice, reused nonces and IVs, "
       "weak randomness, keys shipped with the code.",
       Register.ADVISORY,
       ("ecb mode", "math/rand", "nonce reuse", "hardcoded key",
        "insecure random"),
       (), spine="OWASP ASVS V6 + CWE"),
    _t("crypto.password-storage", "crypto",
       "Storing authentication secrets so that a database breach is not an "
       "account breach: work factors, salting, and migration.",
       Register.ADVISORY,
       ("bcrypt", "pbkdf2", "scrypt", "argon2", "password hashing"),
       (), spine="OWASP ASVS V2 + NIST SP 800-63B"),
    _t("crypto.protocol-attacks", "crypto",
       "Attacks on how a protocol uses cryptography rather than on the cipher: "
       "oracles, downgrades, replays and construction flaws.",
       Register.ADVERSARY,
       ("beast attack", "padding oracle", "downgrade attack",
        "length extension", "replay protection", "chosen ciphertext oracle"),
       ("T1689",), spine="RFC + academic protocol analysis"),
    _t("crypto.key-exchange-and-tunnels", "crypto",
       "The cryptography inside remote-access and VPN protocols: key agreement, "
       "group strength, and host identity.",
       Register.SYSTEM,
       ("wireguard", "ike phase", "key exchange", "diffie-hellman",
        "forward secrecy"),
       (), spine="RFC 7296 + RFC 4253"),
)


# ---------------------------------------------------------------------------
# Calibration evidence
# ---------------------------------------------------------------------------

#: Candidate terms that were **measured and thrown out**, with the document
#: frequency that disqualified them, out of the 208,346 documents in
#: ``clean-v7``. Kept in the module rather than deleted in an editor, because
#: "we calibrated the terms" is a claim and this is the evidence.
#:
#: Three passes over the generation produced these numbers. The first measured
#: the taxonomy's first-draft terms plus a list of deliberately broad probes;
#: the second measured a 2,696-candidate pool (first-draft terms, the field's
#: own short forms, and sub-phrases derived from the terms the first pass
#: measured at zero); the third measured, for every surviving term above 300
#: documents, how much of its frequency comes from a single source. Numbers
#: from the first pass predate the plural tolerance in :func:`term_pattern`
#: and are therefore floors, not exact counts.
#:
#: The ceiling is **5% of documents (10,417)** for an ordinary term: the point
#: at which a hit stops distinguishing one topic's documents from the corpus at
#: large. Nothing about that number is natural law. It is the line this
#: taxonomy drew, and the frequencies are recorded so a later reader can draw a
#: different one without re-running anything.
#:
#: **Two of these rejections could not have been reasoned out.** "shodan" reads
#: like reconnaissance vocabulary and is nuclei template metadata 99% of the
#: time. "cvss base score" reads like severity-rating vocabulary and is the
#: same metadata block. Both would have scored a topic as covered on the
#: strength of one source's boilerplate.
REJECTED_TERMS: tuple[RejectedTerm, ...] = (
    # --- the broad probes: measured on purpose, to find the ceiling ---
    RejectedTerm("vulnerability", 36995,
                 "17.8% of documents: the word the whole corpus is about",
                 replaced_by="per-topic mechanics"),
    RejectedTerm("exploit", 27299,
                 "13.1%: a verb, a noun and a module directory name at once",
                 replaced_by="'rop chain', 'proof of concept exploit'"),
    RejectedTerm("persistence", 18663,
                 "9.0%: names a tactic, and every rule file carries the label",
                 replaced_by="'registry run key', 'ld.so.preload'"),
    RejectedTerm("injection", 13908,
                 "6.7%: a substring of a dozen distinct topics",
                 replaced_by="'sql injection', 'os command injection', "
                             "'process injection'"),
    RejectedTerm("severity", 75957,
                 "36.5%, the single broadest candidate measured: every advisory, "
                 "every detection rule and every scanner template has a field "
                 "called this",
                 replaced_by="'cvss vector', 'severity justification'"),
    RejectedTerm("affected", 73602,
                 "35.3%: advisory boilerplate",
                 replaced_by="'affected versions', 'affected packages'"),
    RejectedTerm("cve-", 71293,
                 "34.2%: matches an identifier family, not a subject. A topic "
                 "term has to describe what a document is about",
                 replaced_by="'cve identifier', 'vulnerable range'"),
    RejectedTerm("cvss", 59951,
                 "28.8%: the acronym is in every advisory and every template",
                 replaced_by="'cvss vector', 'cvss v3', 'attack vector network'"),
    RejectedTerm("cwe-", 41566,
                 "20.0%: identifier family again",
                 replaced_by="'cwe-79', 'cwe-89', 'common weakness enumeration'"),
    RejectedTerm("signature", 39417,
                 "18.9%: code signing, rule signatures, cryptographic signatures "
                 "and function signatures, indistinguishable",
                 replaced_by="'snort signature', 'code signing certificate abuse'"),
    RejectedTerm("suricata rule", 31111,
                 "14.9%, and 31,207 of those documents are the netrules source: "
                 "a term that measures one adapter's output, not a topic",
                 replaced_by="'snort signature', 'conn.log', 'netflow'"),
    RejectedTerm("yara rule", 10462,
                 "5.0%, at the ceiling, driven by the yara source itself",
                 replaced_by="'imphash', 'ssdeep', 'pe header'"),
    RejectedTerm("nuclei template", 13552,
                 "6.5%: the template corpus, not the practice of scanning",
                 replaced_by="'nessus', 'openvas', 'authenticated scan'"),
    RejectedTerm("remediation", 13260,
                 "6.4%: the advice paragraph of every advisory ever written",
                 replaced_by="'remediation recommendation', 'workaround'"),
    RejectedTerm("finding", 12127,
                 "5.8%, and ordinary English besides",
                 replaced_by="'findings section', 'executive summary'"),
    RejectedTerm("scope", 18787,
                 "9.0%: variable scope, policy scope, OAuth scope, engagement "
                 "scope",
                 replaced_by="'rules of engagement', 'out of scope'"),
    # --- measured, under the ceiling, and still rejected ---
    RejectedTerm("command and control", 5926,
                 "2.8%, under the ceiling, and still too shared: six topics had "
                 "claimed it. Kept only where it is the subject",
                 replaced_by="'beacon jitter', 'domain generation algorithm'"),
    RejectedTerm("buffer overflow", 3616,
                 "1.7%, concentrated in advisory text: it measured the ADVISORY "
                 "register rather than exploitation skill",
                 replaced_by="'stack overflow', 'nop sled', 'stack canary'"),
    RejectedTerm("privilege escalation", 3302,
                 "1.6%, and it names a tactic every host topic could claim",
                 replaced_by="'unquoted service path', 'suid', 'sudo -l'"),
    RejectedTerm("remote code execution", 4536,
                 "2.2%: a severity statement, not a technique",
                 replaced_by="'proof of concept exploit', per-vector terms"),
    RejectedTerm("powershell", 6169,
                 "3.0%: the language's name is in every Windows source",
                 replaced_by="'get-childitem', '-encodedcommand', 'param('"),
    RejectedTerm("payload", 6024,
                 "2.9%: protocol payloads, exploit payloads, JSON payloads",
                 replaced_by="'msfvenom', 'payload handler listener'"),
    # --- rejected after the per-source concentration read ---
    RejectedTerm("shodan", 5570,
                 "5,531 of 5,570 documents are nuclei template metadata fields; "
                 "it measures one adapter, not reconnaissance",
                 replaced_by="'censys', 'google dork', 'internet-wide scan index'"),
    RejectedTerm("cvss base score", 5927,
                 "5,925 of 5,927 are the same nuclei metadata block",
                 replaced_by="'cvss vector' (97% NVD, which is the right source)"),
    RejectedTerm("epss", 4350,
                 "4,346 of 4,350 are the score field in nuclei templates",
                 replaced_by="'known exploited', 'actively exploited in the wild'"),
    RejectedTerm("execve", 3278,
                 "2,772 of 3,278 are agent trajectory command lines, which is "
                 "the TRAJECTORY register rather than shellcode",
                 replaced_by="'\\x90', 'null-free', 'egghunter'"),
    RejectedTerm("spdx", 2258,
                 "1,665 of 2,258 are SPDX-License-Identifier headers in kernel "
                 "documentation, not software-inventory practice",
                 replaced_by="'sbom', 'cyclonedx', 'lockfile audit'"),
    RejectedTerm("false positive", 3013,
                 "1,950 of 3,013 are the false_positives field of Elastic "
                 "detection rules: rule metadata, not triage practice",
                 replaced_by="'rule tuning', 'alert fatigue'"),
    RejectedTerm("detection rule", 4052,
                 "1,752 of 4,052 are this runtime's own trajectory prose",
                 replaced_by="'eql sequence', 'tstats', 'index='"),
    # --- rejected on reading, never measured ---
    RejectedTerm("proof of", -1,
                 "not measured: a truncation fragment, not a phrase. Produced "
                 "mechanically from 'proof of exploitation' and kept out by "
                 "reading, which is the one check a frequency cannot do",
                 replaced_by="'proof of exploitation'"),
    RejectedTerm("as code", -1,
                 "not measured: truncation fragment of 'detection as code'",
                 replaced_by="'detection as code'"),
    RejectedTerm("do not require", -1,
                 "not measured: truncation fragment of an ATT&CK technique name",
                 replaced_by="'asreproast', 'preauth'"),
    RejectedTerm("gadget", 238,
                 "0.1%, so frequency said keep: rejected anyway because one word "
                 "covers ROP gadgets, JavaScript gadgets and hardware",
                 replaced_by="'rop gadget', 'gadget chain'"),
)

#: Rejections too numerous to list individually, by class, with counts from the
#: selection pass over the 2,696-candidate pool. These are the mechanical
#: filters; :data:`REJECTED_TERMS` holds the ones worth reading.
#:
#: The largest class is the one that surprised the author: 247 single words
#: produced by truncating a longer term. "field descriptor redirection" minus
#: its last word is "descriptor", which measured 1,345 documents of manual
#: pages and Go documentation and says nothing whatever about shell mechanics.
#: A one-word term now has to be vocabulary somebody chose.
REJECTION_CLASSES: tuple[tuple[str, int, str], ...] = (
    ("single word produced by truncating a longer term", 247,
     "kept only if the word was chosen deliberately, not derived"),
    ("subsumed by a shorter term in the same topic", 163,
     "every document matching 'stack buffer overflow' already matches "
     "'stack overflow', so the longer term adds nothing but apparent breadth"),
    ("ordinary English word per the system word list", 66,
     "'finding', 'scope', 'evidence', 'beacon', 'macro', 'radius', 'salt' — "
     "each discriminating in context and useless as a corpus-wide matcher"),
    ("shorter than four characters", 52, "'spn', 'ttp', 'rce' and the like"),
    ("below the discriminating-term floor", 26,
     "single tokens that are neither acronym-shaped nor identifier-shaped"),
    ("claimed by more than three topics", 0,
     "none survived this far; the earlier filters had already removed them"),
)

#: Granularity decisions: what was deliberately *not* split, and why. Recorded
#: because "we chose 191 topics" is only defensible if the collapses are
#: visible and arguable.
COLLAPSED: tuple[tuple[str, str], ...] = (
    ("ATT&CK sub-techniques",
     "Not leaf topics. 697 live technique ids collapse into 191 topics; a "
     "coverage report over sub-techniques would be mostly zeros and would "
     "measure MITRE's granularity rather than the corpus's."),
    ("macOS",
     "One topic inside nix rather than a domain. The corpus has little macOS "
     "text, and five macOS topics would all read 'thin' without saying more "
     "than one does."),
    ("Mobile and ICS ATT&CK",
     "No topics at all. Both matrices are in the corpus via the attack source, "
     "but neither is in scope for this model's engagement surface, and topics "
     "nobody intends to train would make coverage look worse than it is."),
    ("Collection, C2 and Exfiltration",
     "Three ATT&CK tactics in one domain (c2exfil). They share vocabulary and "
     "document population; split, each would have been measured on the same text."),
    ("Individual CVEs, actors and tools",
     "Not topics. 'APT29' and 'CVE-2024-3094' are instances; the taxonomy "
     "measures subject coverage, and instance coverage is the attack source's "
     "own job."),
    ("Per-cloud-provider topics",
     "AWS, Azure and GCP share nine cloud topics rather than having nine each. "
     "Provider-specific vocabulary lives in the terms, so a coverage report can "
     "still show that 'iam policy' hits and 'managed identity' does not."),
    ("Programming-language depth",
     "C, Go, Python and PowerShell have one topic each at most, under tooling "
     "or binexp. The corpus has large language sources, but language fluency is "
     "not a curriculum area for a security model — it is a register."),
)


# ---------------------------------------------------------------------------
# Lookups and matching
# ---------------------------------------------------------------------------

_BY_ID: dict[str, Topic] = {t.id: t for t in TOPICS}
_BY_DOMAIN: dict[str, tuple[Topic, ...]] = {
    d.id: tuple(t for t in TOPICS if t.domain == d.id) for d in DOMAINS
}
_DOMAIN_BY_ID: dict[str, Domain] = {d.id: d for d in DOMAINS}


def topic_ids() -> tuple[str, ...]:
    """Every topic id, in declaration order."""
    return tuple(t.id for t in TOPICS)


def domain_ids() -> tuple[str, ...]:
    """Every domain id, in declaration order."""
    return tuple(d.id for d in DOMAINS)


def by_id(topic_id: str) -> Topic:
    """The topic with this id. Raises :class:`KeyError` if there is none."""
    return _BY_ID[topic_id]


def domain(domain_id: str) -> Domain:
    """The domain with this id."""
    return _DOMAIN_BY_ID[domain_id]


def by_domain(domain_id: str) -> tuple[Topic, ...]:
    """Every topic in a domain, in declaration order."""
    if domain_id not in _DOMAIN_BY_ID:
        raise KeyError(domain_id)
    return _BY_DOMAIN[domain_id]


def by_register(register: Register) -> tuple[Topic, ...]:
    """Every topic whose documents are expected in this register."""
    return tuple(t for t in TOPICS if t.register is register)


def iter_topics() -> Iterator[Topic]:
    """Iterate topics in declaration order."""
    return iter(TOPICS)


def attack_index() -> dict[str, tuple[str, ...]]:
    """ATT&CK id to the topic ids that claim it.

    Many-to-many on purpose: ``T1190`` is claimed by nine web topics because it
    genuinely covers all of them, and that is the point being made about where
    ATT&CK is thin.
    """
    index: dict[str, list[str]] = {}
    for t in TOPICS:
        for aid in t.attack_ids:
            index.setdefault(aid, []).append(t.id)
    return {k: tuple(v) for k, v in sorted(index.items())}


def atlas_index() -> dict[str, tuple[str, ...]]:
    """ATLAS id to the topic ids that claim it."""
    index: dict[str, list[str]] = {}
    for t in TOPICS:
        for aid in t.atlas_ids:
            index.setdefault(aid, []).append(t.id)
    return {k: tuple(v) for k, v in sorted(index.items())}


_WORDISH = re.compile(r"[0-9A-Za-z_]")


@lru_cache(maxsize=4096)
def term_pattern(term: str) -> re.Pattern[str]:
    """Compile one matcher term.

    Three rules, each of which exists because of a way a naive implementation
    miscounts:

    * **Internal whitespace matches any whitespace run**, so a phrase that was
      line-wrapped in the source still matches. Without this, "resource-based
      constrained delegation" misses every document that wrapped it.
    * **Word boundaries only where the term ends in a word character.** A term
      like ``../../`` or ``$where`` has no boundary to assert, and asserting one
      makes it match nothing — silently, which is the bad kind of nothing.
    * **Case-insensitive**, because ``SeImpersonatePrivilege``,
      ``seimpersonateprivilege`` and ``SEIMPERSONATEPRIVILEGE`` are one term.
    """
    parts = [re.escape(piece) for piece in term.split()]
    body = r"\s+".join(parts)
    prefix = r"(?<![0-9A-Za-z_])" if _WORDISH.match(term[0]) else ""
    if not _WORDISH.match(term[-1]):
        suffix = ""
    elif term[-1].isalpha() and term[-1] != "s":
        # Optional plural. Measured, not assumed: the first calibration scan
        # reported 399 of 952 terms at zero document frequency, and part of
        # that was the matcher refusing "yara rules" for the term "yara rule"
        # -- the trailing boundary made the plural a non-match. A singular noun
        # phrase that never matches its own plural measures a grammar choice
        # rather than a topic.
        suffix = r"s?(?![0-9A-Za-z_])"
    else:
        suffix = r"(?![0-9A-Za-z_])"
    return re.compile(prefix + body + suffix, re.IGNORECASE)


@lru_cache(maxsize=1024)
def topic_pattern(topic_id: str) -> re.Pattern[str]:
    """One alternation over a topic's terms, for a fast "does it match at all".

    Longest term first so that a nested term does not shadow the longer phrase
    that contains it when a caller inspects the match text.
    """
    topic = _BY_ID[topic_id]
    terms = sorted(topic.terms, key=len, reverse=True)
    return re.compile(
        "|".join(term_pattern(t).pattern for t in terms), re.IGNORECASE
    )


def all_terms() -> tuple[str, ...]:
    """Every matcher term across every topic, deduplicated and sorted."""
    seen: set[str] = set()
    for t in TOPICS:
        seen.update(t.terms)
    return tuple(sorted(seen))


# ---------------------------------------------------------------------------
# Measured appendices
# ---------------------------------------------------------------------------

#: Measured document frequency of every live term, over the shipped generation
#: ``clean-v7`` (208,346 documents, 579,716,793 characters), counted with the
#: boundary and plural rules :func:`term_pattern` applies. The scan is a read
#: of the generation's JSONL ``text`` fields and nothing else.
#:
#: **This is the number a coverage report must divide by.** A topic whose terms
#: total 40 documents is not "4% covered" in any useful sense; it is a topic
#: the corpus barely contains, and reporting a percentage of a percentage hides
#: that. Quote the counts.
#:
#: A zero here is a *finding*, not a bug: the term is spelled the way the field
#: spells it and the corpus has none of it. :data:`MEASURED_GAPS` lists the
#: topics where every term is zero.
TERM_DOC_FREQ: dict[str, int] = {
    "\"action\":": 186,
    "\"alg\":\"none\"": 5,
    "#!/bin/bash": 424,
    "$(id)": 11,
    "$where": 13,
    "%p%p%p": 0,
    "-m 1000": 2,
    ".aws/credentials": 58,
    ".bash_history": 67,
    ".bashrc": 109,
    ".env file": 23,
    ".git/config": 29,
    ".lnk": 175,
    ".php.jpg": 5,
    "/etc/passwd": 1345,
    "/etc/shadow": 217,
    "/var/run/docker.sock": 28,
    "169.254.169.254": 182,
    "3-2-1 backup": 3,
    "4624": 258,
    "4688": 794,
    "7z a -p": 1,
    "800-181": 49,
    "800-53": 2409,
    "802.1x": 81,
    "; id": 64,
    "<!doctype": 213,
    "<!entity": 80,
    "<script>alert": 627,
    "\\x90": 26,
    "__proto__": 137,
    "abuse case": 7,
    "access token structure": 0,
    "access token theft": 1,
    "access-control-allow-credentials": 22,
    "access-control-allow-origin wildcard": 0,
    "accesschk": 20,
    "account lockout bypass": 0,
    "account lockout threshold": 9,
    "acl on vlan": 0,
    "activity log": 297,
    "adcs": 134,
    "address sanitizer": 9,
    "admin share": 181,
    "adminsdholder": 18,
    "adsi search": 0,
    "adversarial attack": 2,
    "adversarial example": 2,
    "adversarial perturbation": 0,
    "adversary emulation": 19,
    "adversary tradecraft": 4,
    "advisory severity assignment": 0,
    "aes-256 payload": 0,
    "affected packages": 252,
    "affected versions": 1348,
    "agent action": 2,
    "agent guardrail": 0,
    "ai red teaming": 1,
    "ai safety control": 2,
    "aircrack-ng": 16,
    "airodump-ng": 7,
    "alert fatigue": 9,
    "alert triage workflow": 0,
    "alg none": 0,
    "amcache": 3,
    "amsi bypass": 22,
    "amsibypass": 7,
    "anomaly detection": 191,
    "anonymous ftp": 53,
    "anonymous login": 34,
    "anti-analysis check": 5,
    "apparmor": 168,
    "applocker": 154,
    "approval required": 3,
    "apt group": 46,
    "archive before exfil": 0,
    "archive collected data": 146,
    "argon2": 11,
    "argparse": 108,
    "argument injection": 109,
    "arp cache": 58,
    "arp spoofing": 25,
    "as-rep": 47,
    "aslr": 213,
    "asn lookup": 2,
    "aspx shell upload": 0,
    "asreproast": 23,
    "assessment methodology": 2,
    "assume role": 23,
    "asyncio": 70,
    "at.exe": 43,
    "atomic red team": 61,
    "atomic test": 1881,
    "attack surface reduction rule": 25,
    "attack technique coverage mapping": 0,
    "attack tree": 2,
    "attack vector network": 1,
    "audit log": 1214,
    "audit trail of testing": 0,
    "audit.log": 126,
    "auditctl": 298,
    "auditd": 3764,
    "auth.log entry": 0,
    "authenticated scan": 0,
    "authorisation": 401,
    "authorization check": 394,
    "authorized_keys": 169,
    "auto-elevate binary": 0,
    "autoroute": 2,
    "awk '{print": 103,
    "awk field separator": 0,
    "axfr": 27,
    "azure function": 34,
    "backdoor attack": 0,
    "backdoor trigger in model": 0,
    "backtick execution": 1,
    "backtracking": 120,
    "backup isolation": 0,
    "badge cloning": 0,
    "banner grabbing": 8,
    "base image vulnerability": 0,
    "base metric": 1,
    "base64 encoded": 398,
    "batch query attack": 0,
    "bcrypt": 77,
    "beacon interval": 5,
    "beacon jitter": 0,
    "beacon timing": 0,
    "beaconing detection": 3,
    "bearer token": 176,
    "beast attack": 4,
    "bgp.he.net": 0,
    "billion laughs": 26,
    "ble advertisement": 2,
    "blob container public access": 0,
    "blob storage": 53,
    "bluetooth": 419,
    "bootkit": 45,
    "breach credential dump": 3,
    "bring your own vulnerable driver": 8,
    "broken access control": 245,
    "browser exploit": 5,
    "brute force": 732,
    "bucket policy": 19,
    "bug bounty": 83,
    "business impact": 72,
    "business logic": 106,
    "byovd": 14,
    "c$ share": 5,
    "c2 channel": 1067,
    "c2 profile": 32,
    "cache poisoning": 153,
    "cached domain credentials": 32,
    "cachedump": 15,
    "caldera": 28,
    "cap_sys_admin": 72,
    "capabilities drop": 0,
    "captive portal": 29,
    "capture group": 45,
    "ccache": 82,
    "censys": 72,
    "certificate chain": 155,
    "certificate template": 105,
    "certificate transparency": 16,
    "certipy": 57,
    "chain of custody": 7,
    "china chopper": 45,
    "chmod 777": 271,
    "chosen ciphertext oracle": 0,
    "chunk metadata corruption": 0,
    "ci pipeline": 19,
    "cipher suite": 195,
    "cl.te": 6,
    "clear-eventlog": 19,
    "cleartext password in script": 0,
    "clickjacking": 65,
    "cloud function": 26,
    "cloudtrail": 756,
    "cmdletbinding parameter": 0,
    "cms version disclosure": 0,
    "cname record": 45,
    "cobalt strike": 589,
    "codesign verification": 0,
    "command and control channel": 87,
    "command obfuscation": 104,
    "command substitution": 43,
    "common weakness": 24,
    "community string": 69,
    "compensating control": 26,
    "computer misuse legislation": 0,
    "condition: selection": 1630,
    "conditional access": 201,
    "config extraction": 1,
    "configuration baseline": 99,
    "configuration drift": 12,
    "conn.log": 29,
    "consent.exe": 17,
    "constrained delegation": 77,
    "constrained language mode": 24,
    "constructor.prototype": 17,
    "container escape": 56,
    "containment eradication recovery": 0,
    "content-security-policy frame-ancestors": 0,
    "control assessment procedure": 0,
    "control flow graph recovery": 0,
    "control mapping": 3,
    "control plane audit event": 0,
    "coordinated disclosure": 29,
    "copy to share": 0,
    "corpus minimization": 0,
    "correlation window": 159,
    "cors": 235,
    "coupon abuse": 0,
    "coverage-guided": 4,
    "cpe match": 0,
    "crackmapexec": 50,
    "createremotethread": 69,
    "credential capture": 27,
    "credential capture page": 0,
    "credential dumping": 346,
    "credential file": 76,
    "credential guard": 74,
    "credential harvester": 10,
    "credential hygiene": 16,
    "credential prompt spoofing": 0,
    "credential reuse across hosts": 0,
    "credential stuffing": 79,
    "credential stuffing list": 0,
    "cron job writable": 0,
    "crontab": 2656,
    "cross-site request forgery": 1302,
    "cross-site scripting": 6853,
    "crossdomain.xml": 13,
    "csrf": 1862,
    "curl -t": 6,
    "cve identifier": 53,
    "cve-2021-4034": 10,
    "cvss v3": 50,
    "cvss vector": 711,
    "cwe identifier": 1,
    "cwe-79": 5415,
    "cwe-89": 2392,
    "cyclonedx": 31,
    "d3fend": 138,
    "data exfil": 55,
    "data flow diagram": 1,
    "data poisoning": 7,
    "database link abuse": 0,
    "dcsync": 98,
    "dead drop": 54,
    "deauth": 30,
    "debugger detection": 23,
    "decompiler": 21,
    "def main()": 89,
    "default credentials": 265,
    "dep bypass rop chain": 0,
    "detection engineering": 17,
    "detection validation run": 0,
    "device code": 57,
    "dhcp": 456,
    "diamond model": 0,
    "diamond ticket": 9,
    "diffie-hellman": 150,
    "digital artifact ontology": 0,
    "direct kernel object manipulation": 0,
    "direct syscall": 7,
    "directory traversal": 1415,
    "dirsearch": 26,
    "dirty pipe": 2,
    "dirtycow": 6,
    "disable defender": 26,
    "disable etw provider": 0,
    "disable security tool": 29,
    "disassembly listing": 6,
    "distillation attack": 1,
    "dkim": 76,
    "dkom": 9,
    "dll hijacking": 83,
    "dmarc": 30,
    "dns brute force": 0,
    "dns tunneling": 35,
    "dns tunnelling": 2,
    "dnscat": 8,
    "dnsrecon": 6,
    "docker build": 81,
    "docker socket mount": 0,
    "dockerfile": 149,
    "dom clobbering": 11,
    "domain fronting": 25,
    "domain generation": 65,
    "domain trust": 124,
    "double extension": 34,
    "double free": 158,
    "downgrade attack": 87,
    "dpapi masterkey": 0,
    "drive-by": 149,
    "drsuapi": 21,
    "dsquery": 48,
    "dynamic port forward": 2,
    "eap-tls": 27,
    "eaphammer": 0,
    "ebpf": 111,
    "ecb mode": 17,
    "egghunter": 18,
    "egress filtering": 19,
    "elasticsearch query": 0,
    "em4100": 2,
    "encoded command line": 0,
    "encrypted c2": 33,
    "engagement letter": 0,
    "enter-pssession": 64,
    "entity expansion": 77,
    "environmental score": 0,
    "eql sequence": 4,
    "esc1": 27,
    "etcd": 182,
    "etw bypass": 0,
    "evasion attack on classifier": 0,
    "event correlation": 46,
    "event id": 377,
    "eventvwr": 53,
    "evidence capture during test": 0,
    "evil twin": 24,
    "evilginx": 45,
    "evilginx2": 24,
    "excessive agency": 14,
    "execution role": 21,
    "executive summary": 82,
    "exfil over dns": 0,
    "exfiltration over c2 channel": 1000,
    "exfiltration over web service": 104,
    "exploit available": 2,
    "exploit kit": 1138,
    "exploit-db local": 0,
    "exploit/multi": 603,
    "exposed git directory": 0,
    "expression language injection": 29,
    "fallback channel": 69,
    "false positive rate": 53,
    "falsepositives": 3141,
    "fast flux": 20,
    "ffuf": 16,
    "file capability cap_setuid": 0,
    "file upload": 1176,
    "file:// scheme": 5,
    "findings section": 5,
    "firewall ruleset": 2,
    "fodhelper": 21,
    "forced browsing": 20,
    "forest trust": 52,
    "forged ticket": 10,
    "format specifier abuse": 0,
    "format string": 435,
    "forward secrecy": 53,
    "frame busting": 4,
    "freemarker": 40,
    "from header spoofing": 0,
    "fsutil usn": 7,
    "function app": 59,
    "function calling": 16,
    "fuzz target": 0,
    "fuzzy hash similarity": 0,
    "gadget chain": 45,
    "gatt": 5,
    "genericall": 48,
    "get-childitem": 516,
    "getasynckeystate": 14,
    "getfacl": 6,
    "getnpusers": 4,
    "gets()": 7,
    "getuserspns": 14,
    "ghidra": 9,
    "git history": 21,
    "github actions": 123,
    "gitleaks": 198,
    "globbing": 88,
    "gnuradio": 0,
    "gobuster": 17,
    "golden image hardening": 0,
    "golden ticket": 64,
    "google dork": 4,
    "google hacking database": 0,
    "gopher://": 13,
    "gophish": 6,
    "gpo modification": 10,
    "gpupdate": 27,
    "graphql": 217,
    "grep -e": 139,
    "group policy": 683,
    "grpc": 138,
    "gtfobins": 1729,
    "guardduty": 95,
    "guest access to share": 0,
    "hackrf": 4,
    "half-open scan": 0,
    "hardcoded credential": 24,
    "hardcoded key": 22,
    "hashcat": 60,
    "hashicorp vault": 53,
    "haveibeenpwned": 6,
    "hcitool": 4,
    "hcxdumptool": 0,
    "heap overflow": 139,
    "helpdesk impersonation": 0,
    "high integrity": 38,
    "history -c": 16,
    "hkcu\\software\\microsoft\\windows\\currentversion\\run": 45,
    "hostapd": 10,
    "hostpath": 85,
    "hs256": 46,
    "html smuggling": 18,
    "httponly": 148,
    "huggingface model": 0,
    "hypothesis-driven": 0,
    "iam policy": 79,
    "icacls": 81,
    "icmp tunnel": 0,
    "icon spoofing": 0,
    "id_rsa": 83,
    "iis module": 14,
    "ike phase": 36,
    "image file execution options": 59,
    "image layer": 23,
    "image scanning": 12,
    "imap folder enumeration": 0,
    "imds": 44,
    "imdsv2": 36,
    "immediate scheduled task via policy": 0,
    "immunity debugger": 2,
    "immutable attribute chattr": 0,
    "immutable backup": 6,
    "impact rating": 1,
    "imphash": 259,
    "import hash": 67,
    "import requests": 84,
    "import socket": 95,
    "import table": 9,
    "in the wild": 300,
    "in-scope": 17,
    "incident response": 1055,
    "incident severity classification": 0,
    "index=": 133,
    "indirect injection": 9,
    "information_schema": 122,
    "injected code in memory": 1,
    "input capture": 116,
    "input sanitisation for prompts": 0,
    "insecure deserialization": 124,
    "insecure random": 7,
    "instance metadata": 132,
    "instance profile": 40,
    "instruction override in content": 0,
    "integer overflow": 1214,
    "internal service reachable from": 0,
    "internet-wide scan index": 0,
    "introspection query": 8,
    "invoke-command": 224,
    "invoke-obfuscation": 66,
    "invoke-webrequest": 411,
    "ip range": 88,
    "ipconfig /all": 48,
    "ipmi cipher zero": 0,
    "ipmitool": 5,
    "isdebuggerpresent": 19,
    "iso 27001": 4,
    "iso attachment": 1,
    "iso14443": 2,
    "ja3 fingerprint": 0,
    "ja3s": 12,
    "jailbreak": 32,
    "jarm": 29,
    "java deserialization": 80,
    "jenkins": 1063,
    "jinja2": 49,
    "john the ripper": 30,
    "joomla": 640,
    "journalctl": 42,
    "juicypotato": 9,
    "just-in-time": 91,
    "jwks": 43,
    "kaslr": 33,
    "kerberoast": 47,
    "kerberos ticket injection": 1,
    "kerbrute": 9,
    "kernel callback removal": 0,
    "kernel exploit": 6,
    "kernel heap spray": 0,
    "kernel module": 373,
    "kernel structure scan": 0,
    "kernel version": 173,
    "kernel32": 293,
    "key exchange": 354,
    "key management service": 83,
    "key rotation": 60,
    "keylogger": 297,
    "keystroke logging": 8,
    "kill chain": 9,
    "klist": 38,
    "knowledge statement": 0,
    "known exploited": 1793,
    "known_hosts": 53,
    "krbtgt": 135,
    "krbtgt hash": 10,
    "kubectl": 794,
    "kubelet": 471,
    "kubernetes": 2355,
    "launchctl": 121,
    "launchd": 3477,
    "launchdaemon": 42,
    "ld_preload": 64,
    "ldapsearch": 42,
    "length extension": 9,
    "libfuzzer": 4,
    "ligolo": 10,
    "likelihood and impact": 36,
    "linkedin": 174,
    "linpeas": 50,
    "llm01": 10,
    "llmnr": 63,
    "lnk file": 117,
    "lnk file payload": 0,
    "local data staging": 162,
    "local file inclusion": 1021,
    "lock pick": 1,
    "lockfile audit": 0,
    "lockout policy": 37,
    "log2timeline": 12,
    "login attempt throttling": 0,
    "login brute force": 10,
    "logsource": 3174,
    "lolbas": 587,
    "lolbin": 352,
    "lookahead": 31,
    "lookalike domain": 7,
    "lsa protection": 19,
    "lsa secrets": 77,
    "lsadump": 51,
    "lsass": 555,
    "lsof -i": 6,
    "m365 audit": 5,
    "mactime": 1,
    "magic byte check": 0,
    "maldoc": 215,
    "malfind": 1,
    "malicious extension": 52,
    "malloc": 482,
    "malware analysis": 179,
    "managed identity": 106,
    "management interface": 603,
    "mark-of-the-web": 30,
    "masquerading": 410,
    "mass assignment": 48,
    "masscan": 32,
    "match legitimate name": 27,
    "math/rand": 23,
    "membership inference": 5,
    "memory dump": 114,
    "metadata token header": 0,
    "metadata.google.internal": 18,
    "metasploit": 755,
    "meterpreter": 538,
    "mfa bypass": 15,
    "mfa fatigue": 11,
    "mfa registration abuse": 0,
    "mft record": 9,
    "microsegmentation": 12,
    "mifare": 14,
    "mimikatz": 441,
    "mitm": 279,
    "mitm6": 11,
    "mitre engage": 1,
    "model artifact": 6,
    "model extraction": 2,
    "model inversion": 1,
    "model stealing": 0,
    "mona.py": 0,
    "mongodb": 262,
    "msds-keycredentiallink": 22,
    "msfconsole": 1420,
    "msfvenom": 32,
    "mshta": 319,
    "mssql": 250,
    "mstsc": 49,
    "multipart/form-data": 512,
    "mysql": 1118,
    "named pipe impersonation": 8,
    "nbtscan": 22,
    "nessus": 194,
    "net group": 58,
    "net share": 29,
    "netbios name service": 17,
    "netblock": 5,
    "netflow": 85,
    "netsh advfirewall": 49,
    "netsh portproxy": 3,
    "netstat -ano": 15,
    "network level authentication": 16,
    "network route through implant": 0,
    "network segmentation": 284,
    "new-object": 649,
    "nice framework": 12,
    "nist csf": 2,
    "nltest": 85,
    "nmap": 1021,
    "nmap scripting engine": 11,
    "nonce reuse": 7,
    "nop sled": 18,
    "nopasswd": 2709,
    "nosql injection": 33,
    "nosqli": 6,
    "nse script": 623,
    "nslookup": 142,
    "nt hash authentication": 0,
    "ntdll": 164,
    "ntds.dit": 122,
    "ntfs metadata": 7,
    "ntlm hash": 53,
    "ntlm relay": 54,
    "ntlmrelayx": 70,
    "ntlmv1 downgrade": 0,
    "null byte truncation": 0,
    "null pointer dereference": 757,
    "null session": 30,
    "null-free": 0,
    "oauth consent": 22,
    "oauth token": 97,
    "objdump": 20,
    "object reference": 201,
    "ocsp": 123,
    "off-by-one": 88,
    "offline backup": 36,
    "oidc federation": 0,
    "oidc trust policy": 0,
    "onerror=": 320,
    "onesixtyone": 0,
    "ook modulation": 1,
    "open redirect": 567,
    "open relay": 11,
    "open source intelligence": 2,
    "open source security testing methodology": 0,
    "openapi": 103,
    "openvas": 20,
    "operator approval gate": 0,
    "operator injection": 7,
    "orm query injection": 0,
    "os fingerprinting": 30,
    "osascript": 223,
    "osquery": 701,
    "out of scope": 279,
    "out-of-bounds": 1263,
    "output filtering for model responses": 0,
    "overpass-the-hash": 17,
    "package.json": 133,
    "padding oracle": 26,
    "pairing": 175,
    "param(": 496,
    "parameter expansion": 20,
    "parent-child process": 56,
    "pass-the-hash": 99,
    "pass-the-ticket": 44,
    "password hashing": 45,
    "password reset token": 34,
    "password spraying": 160,
    "patch management": 128,
    "patched version": 969,
    "path traversal": 1938,
    "pattern_offset": 2,
    "payload handler listener": 0,
    "pbkdf2": 75,
    "pcap": 152,
    "pe header": 451,
    "penetration testing execution standard": 0,
    "permitrootlogin": 23,
    "petitpotam": 35,
    "phishing email": 157,
    "phishing page": 40,
    "phishing simulation": 9,
    "phpsessid": 131,
    "physical security": 93,
    "pickle file": 32,
    "pivot host": 1,
    "pkinit": 39,
    "plaintext credentials": 66,
    "plink": 56,
    "plist": 3613,
    "pmkid": 12,
    "port 3389": 67,
    "port 445": 288,
    "position independent": 17,
    "post-exploitation": 351,
    "post-incident review": 25,
    "postgresql": 942,
    "postmessage": 42,
    "postmortem": 37,
    "potato attack": 0,
    "powerview": 124,
    "preauth": 88,
    "prefetch": 67,
    "preflight request": 4,
    "presigned": 16,
    "pretexting": 11,
    "price manipulation": 1,
    "printerbug": 22,
    "printf(": 511,
    "privilege boundary": 17,
    "privileged access": 290,
    "privileged container": 68,
    "proc filesystem memory read": 0,
    "process hollowing": 84,
    "process injection": 299,
    "prompt injection": 128,
    "proof of concept": 627,
    "proof of concept exploit availability": 0,
    "protected users": 53,
    "prototype pollution": 277,
    "proxmark": 0,
    "proxy model": 2,
    "proxychains": 18,
    "ps aux": 40,
    "psexec": 266,
    "pslist": 26,
    "ptes": 34,
    "ptr record": 39,
    "ptunnel": 6,
    "public read access": 6,
    "pull_request_target": 13,
    "purple team": 4,
    "pwnkit": 4,
    "pypykatz": 13,
    "pyramid of pain": 2,
    "qualys": 110,
    "race condition": 636,
    "radare2": 204,
    "radius server": 53,
    "rag poisoning": 4,
    "rainbow table": 21,
    "rar a -hp": 1,
    "rbcd": 39,
    "rc.local": 55,
    "rc4 key": 47,
    "rce via parameter": 0,
    "rdap": 26,
    "rdp certificate warning": 0,
    "rdp hijack": 0,
    "re.compile": 75,
    "recovery time objective": 19,
    "referer check": 4,
    "reflected xss": 590,
    "reflective dll": 21,
    "refresh token": 153,
    "registrant contact": 58,
    "registrar abuse contact": 24,
    "registry credential": 20,
    "regsvr32 scriptlet": 0,
    "remediation recommendation": 2,
    "remote desktop protocol": 287,
    "remote file inclusion": 612,
    "remote scheduled task": 7,
    "replay of request": 0,
    "replay protection": 94,
    "replication rights abuse": 0,
    "report phishing button": 0,
    "report suspicious email": 2,
    "report template": 9,
    "reproduction steps": 70,
    "request smuggling": 115,
    "requirements.txt": 58,
    "responsible disclosure": 49,
    "rest api": 564,
    "restore procedure": 3,
    "restricted admin mode": 37,
    "ret2libc": 0,
    "return-oriented programming": 15,
    "reverse dns lookup": 41,
    "reverse ip lookup": 1,
    "rfid": 29,
    "right-to-left override": 28,
    "ring 0": 18,
    "rip overwrite": 0,
    "risk rating": 1,
    "rockyou": 4,
    "rogue access point": 8,
    "rogue ap": 8,
    "rootkit": 365,
    "rop chain": 22,
    "rop gadget": 8,
    "rs256": 32,
    "rsync": 112,
    "rsyslog": 81,
    "rtl-sdr": 4,
    "rubber ducky": 9,
    "rubeus": 111,
    "rule condition": 7,
    "rule tuning": 1,
    "rules of engagement": 8,
    "run key": 369,
    "rundll32": 631,
    "rustscan": 9,
    "s3 bucket": 210,
    "s4u2self": 31,
    "safe harbor": 2,
    "safe harbour clause": 0,
    "safeseh": 2,
    "safetensors": 6,
    "sam hive": 11,
    "same-origin policy": 29,
    "sandbox detection": 19,
    "sandbox evasion": 97,
    "sandbox report": 1,
    "sbom": 61,
    "scanner plugin": 8,
    "schtasks": 237,
    "schtasks /s": 0,
    "screen -x": 1,
    "script block logging": 194,
    "scrypt": 19,
    "sddl": 86,
    "search engine": 112,
    "seccomp": 141,
    "secret injection at runtime": 0,
    "secret scanning": 23,
    "secrets management": 52,
    "secretsdump": 58,
    "security advisory": 319,
    "security awareness": 88,
    "security descriptor": 292,
    "security event log channel": 0,
    "sed -i": 147,
    "sedebugprivilege": 75,
    "seh overwrite": 3,
    "seimpersonateprivilege": 48,
    "sekurlsa": 43,
    "selinux": 255,
    "serialized object payload": 0,
    "server software component": 106,
    "server-sent events endpoint": 0,
    "server-side request forgery": 787,
    "server-side template injection": 109,
    "serverless": 95,
    "service account token": 126,
    "service binary replacement": 0,
    "service file": 101,
    "service principal": 316,
    "service principal name": 123,
    "session cookie": 554,
    "session fixation": 102,
    "session hijacking": 720,
    "session id": 434,
    "session token entropy": 0,
    "set -e": 406,
    "set payload": 254,
    "set-cookie": 261,
    "setfacl": 21,
    "setuid root": 27,
    "setwindowshookex": 17,
    "severity justification": 3,
    "shadow copy": 104,
    "shadow credentials": 38,
    "sharpgpoabuse": 15,
    "sharphound": 33,
    "shellbags": 2,
    "shellcode": 606,
    "shimcache": 6,
    "showmount": 18,
    "sidhistory": 26,
    "sigma field mapping": 0,
    "sigma rule": 260,
    "sigmac": 1,
    "sign-in log": 109,
    "signed binary": 163,
    "signing required": 4,
    "silver ticket": 44,
    "sim swap": 6,
    "sleep evasion": 0,
    "sleep interval": 5,
    "sleep mask": 1,
    "sleuthkit": 8,
    "smap": 12,
    "smb share permission": 0,
    "smb signing": 28,
    "smbclient": 46,
    "smbexec": 38,
    "smbv1": 72,
    "smep": 12,
    "smishing": 7,
    "smtp": 920,
    "snmpwalk": 15,
    "snort signature": 24,
    "social engineering call": 2,
    "socket connect script": 0,
    "socket.io": 37,
    "socks proxy pivot": 0,
    "software defined radio": 14,
    "software packing": 145,
    "spearphishing": 459,
    "spf record": 11,
    "splunk": 3974,
    "spring4shell": 18,
    "sql injection": 7447,
    "sqli": 1025,
    "srop": 3,
    "srv record enumeration": 0,
    "ss -tulpn": 0,
    "ssdeep": 124,
    "ssdt": 15,
    "ssh -l": 17,
    "ssh private key harvest": 0,
    "ssh-keygen": 44,
    "sshd_config": 225,
    "sshuttle": 5,
    "ssrf": 1139,
    "ssti": 161,
    "stack canary": 5,
    "stack counting": 1,
    "stack overflow": 278,
    "stackdriver": 8,
    "staging directory": 19,
    "startup folder": 389,
    "state-changing request": 13,
    "static analysis of sample": 0,
    "stats by command": 0,
    "step limit": 2,
    "sticky bit": 56,
    "stig": 8610,
    "stop-service": 52,
    "stored xss": 1014,
    "stp root bridge": 0,
    "stride category": 0,
    "struts": 236,
    "sub-ghz": 26,
    "subdomain takeover": 22,
    "subfinder": 7,
    "subshell": 42,
    "sudoers": 201,
    "summary section": 2,
    "supply chain compromise": 155,
    "syn scan": 11,
    "syn-ack": 191,
    "syscall": 1171,
    "sysctl": 347,
    "sysdig": 73,
    "syslog facility": 57,
    "sysmon": 5645,
    "system prompt": 55,
    "systemctl": 675,
    "systemd sandboxing option": 0,
    "systemd timer": 37,
    "systemd unit": 74,
    "sysvol": 90,
    "tailgating": 3,
    "tamper protection": 15,
    "tasklist": 146,
    "tcache": 24,
    "te.cl": 7,
    "template engine sandbox escape": 0,
    "tenant investigation": 0,
    "terminal multiplexer": 7,
    "testing window": 5,
    "tftp": 236,
    "tgs-rep hash": 0,
    "theharvester": 3,
    "threat actor group": 6,
    "threat hunting": 60,
    "threat model": 164,
    "ticket cache file": 1,
    "tier 0": 14,
    "tiered administration model": 0,
    "time-based blind": 62,
    "timeline": 520,
    "timestamp analysis": 0,
    "timestomp": 100,
    "tls fingerprint": 6,
    "tls handshake": 176,
    "tmux attach": 0,
    "toctou": 149,
    "token impersonation": 64,
    "tool abuse": 41,
    "tool call": 68,
    "tool_call": 4,
    "traceroute": 132,
    "transitive dependency": 11,
    "trap signal handler": 0,
    "trufflehog": 47,
    "trust boundary": 135,
    "trust relationship": 150,
    "tscon": 11,
    "tstats": 732,
    "ttps": 210,
    "tunnel through compromised host": 0,
    "txt record": 57,
    "typosquatting": 29,
    "uac bypass": 126,
    "ui redress attack": 4,
    "unconstrained delegation": 31,
    "unhooking": 7,
    "unified audit log": 24,
    "uninitialized": 468,
    "union select": 622,
    "unpacking": 105,
    "unquoted service path": 49,
    "unserialize": 86,
    "unsigned driver": 18,
    "untrusted model": 13,
    "upload directory": 37,
    "upload to pastebin": 0,
    "usb drop": 1,
    "use-after-free": 810,
    "user reported message": 0,
    "user training": 100,
    "userland hook bypass": 0,
    "username enumeration": 32,
    "usnjrnl": 6,
    "validation test": 43,
    "varargs": 5,
    "vaultcmd": 12,
    "version detection": 48,
    "virtual host discovery": 0,
    "vishing": 17,
    "vlan": 325,
    "volatility plugin": 2,
    "vulnerability record": 2,
    "vulnerability scanner": 124,
    "vulnerable range": 7,
    "watering hole": 49,
    "wdac": 47,
    "wdigest": 53,
    "weakness relationship parent": 0,
    "web service as c2": 0,
    "web shell": 540,
    "web.config": 59,
    "webshell": 753,
    "websocket": 366,
    "wevtutil": 102,
    "whois lookup": 5,
    "whois record": 2,
    "wiegand": 5,
    "wifiphisher": 0,
    "windbg": 48,
    "winlogbeat": 342,
    "winpeas": 47,
    "winrs": 14,
    "wireguard": 53,
    "wmi remote process create": 0,
    "wmic": 337,
    "wmiexec": 59,
    "wordlist": 109,
    "wordlist rule": 0,
    "wordpress": 6880,
    "work role": 2,
    "workaround": 1023,
    "world-writable": 120,
    "wpa enterprise": 1,
    "wpa2": 42,
    "wpscan": 1357,
    "writedacl": 33,
    "writeowner right": 0,
    "writeprocessmemory": 76,
    "ws://": 33,
    "x-forwarded-host": 44,
    "x-frame-options": 50,
    "x.509": 405,
    "xargs": 232,
    "xml external entity": 382,
    "xor encoded": 13,
    "xp_cmdshell": 79,
    "xsrf": 38,
    "ysoserial": 97,
    "zero trust": 60,
    "zone transfer": 78,
    "zoomeye": 70,
    "|| whoami": 0,
}

#: Topics where **every** matcher term measured zero in ``clean-v7``. These are
#: the taxonomy's own answer to "what is this corpus missing", available before
#: any model is trained or any benchmark is run.
#:
#: Read them as a list of candidate acquisitions, not as a list of failures:
#: several are areas the project may deliberately never cover (physical entry,
#: workforce frameworks), and a few are areas a purple-team model plainly
#: should cover.
MEASURED_GAPS: tuple[str, ...] = (
    # Empty, and empty as a *result*: after the terms were rebuilt from the
    # field's own surface forms, every one of the 192 topics has at least one
    # term that occurs in clean-v7. The gaps in this corpus are therefore
    # differences of degree, not of presence, and degree is what
    # TERM_DOC_FREQ measures -- adversarial examples total 4 documents across
    # every term, beaconing 14, fuzzing 17, report writing 100, against 50,220
    # for the web-application domain. An entry appearing here later would mean
    # a topic went silent, which is a stronger claim and worth a line of its
    # own in a coverage report.
)


#: Terms whose frequency is concentrated in **one source**: term ->
#: (source, documents from that source, documents in total). Measured over
#: every live term above 300 documents; a term absent from this mapping is
#: either spread across sources or too small for the question to matter.
#:
#: This is not a list of bad terms. "falsepositives" is 99% the sigma source
#: and that is exactly right -- Sigma rules *are* this corpus's Sigma
#: coverage. It is a list of places where a coverage number is really a
#: statement about one adapter, and the next agent should say so rather than
#: claim the model knows a topic. Where the concentration meant the term was
#: simply wrong, the term was removed instead and is in REJECTED_TERMS.
SOURCE_CONCENTRATION: dict[str, tuple[str, int, int]] = {
    "stig": ("govguidance", 8578, 8610),
    "cwe-79": ("nvd", 5162, 5415),
    "wordpress": ("nvd", 4495, 6880),
    "launchd": ("trajectories", 3240, 3477),
    "splunk": ("splunk", 3239, 3974),
    "plist": ("trajectories", 3156, 3613),
    "logsource": ("sigma", 3144, 3174),
    "falsepositives": ("sigma", 3122, 3141),
    "auditd": ("trajectories", 2772, 3764),
    "nopasswd": ("trajectories", 2672, 2709),
    "crontab": ("trajectories", 2490, 2656),
    "800-53": ("govguidance", 2353, 2409),
    "cwe-89": ("nvd", 2286, 2392),
    "atomic test": ("atomic", 1862, 1881),
    "known exploited": ("cisa", 1791, 1793),
    "condition: selection": ("sigma", 1620, 1630),
    "msfconsole": ("metasploit", 1413, 1420),
    "gtfobins": ("trajectories", 1116, 1729),
    "affected versions": ("ghsa", 1070, 1348),
    "exploit kit": ("netrules", 1046, 1138),
    "out-of-bounds": ("nvd", 962, 1263),
    "cross-site request forgery": ("nvd", 912, 1302),
    "c2 channel": ("netrules", 751, 1067),
    "exfiltration over c2 channel": ("netrules", 751, 1000),
    "jenkins": ("ghsa", 748, 1063),
    "nmap": ("nselua", 742, 1021),
    "tstats": ("splunk", 718, 732),
    "cvss vector": ("nvd", 691, 711),
    "nse script": ("nselua", 615, 623),
    "use-after-free": ("nvd", 603, 810),
    "exploit/multi": ("metasploit", 588, 603),
    "4688": ("splunk", 575, 794),
    "null pointer dereference": ("nvd", 572, 757),
    "union select": ("netrules", 553, 622),
    "<script>alert": ("nuclei", 514, 627),
    "remote file inclusion": ("nvd", 463, 612),
    "meterpreter": ("metasploit", 438, 538),
    "pe header": ("yara", 430, 451),
    "set -e": ("shellscripts", 393, 406),
    "param(": ("powershell", 356, 496),
    "authorisation": ("trajectories", 336, 401),
    "winlogbeat": ("elastic", 336, 342),
    "kubelet": ("containers", 332, 471),
    "#!/bin/bash": ("shellscripts", 328, 424),
    "invoke-webrequest": ("atomic", 316, 411),
    "startup folder": ("attackactors", 263, 389),
    "run key": ("attackactors", 260, 369),
    "lolbin": ("lolbas", 222, 352),
    "security advisory": ("ghsa", 192, 319),
}

#: Total documents in the generation the terms were calibrated against. Kept
#: beside the frequencies so a later reader cannot mistake a count for a share.
CALIBRATION_DOCS = 208346
CALIBRATION_GENERATION = "clean-v7"
