"""Government hardening guidance — the requirement, its check, its fix. PROSE/BLUE.

PROSE is the register this corpus is starved of: 1.8% observed against a 9%
target, which is a worse shortfall proportionally than any register except
shell. It is also the register that is hardest to fill *honestly*, because most
security writing on the open web is either someone's blog or somebody's
copyrighted book, and this project has already disabled one finished adapter
over an unlicensed upstream (see :mod:`._internal_unlicensed`). US Government
works are the exception: not merely permissive but outside copyright altogether
under 17 USC 105, and written by the institutions whose vocabulary the rest of
the corpus keeps citing. Sigma rules map to ATT&CK; CISA's SCuBA baselines cite
``CM-7``; every DISA STIG rule carries a CCI identifier that resolves to an SP
800-53 control. Those control identifiers already appear all over this corpus.
Until now, nothing in it said what they *mean*.

**Two upstreams, joined.**

*DISA STIGs.* Each STIG rule is a requirement in one sentence, a discussion of
why it matters in a paragraph, a **check procedure** and a **fix procedure**.
That pairing is this project's whole thesis expressed by a different
institution: :mod:`whetstone.verbs` insists a ``harden.*`` verb declares what
proves it worked, and a STIG rule has said exactly that, for thirty years, in
XCCDF. Nothing else in the corpus has this shape. Atomic Red Team pairs a
technique with a command but has no notion of verifying a *state*; Sigma
verifies behaviour but prescribes no fix; OWASP's cheat sheets explain without
ever naming a check you could run. The STIG says "this must be true", "here is
the command that shows whether it is", "here is the command that makes it so".

*NIST OSCAL catalogues.* SP 800-53 Rev 5 (with its 800-53A assessment
procedures), SP 800-171 Rev 3, SP 800-172 Rev 3, the SSDF (SP 800-218) and the
Cybersecurity Framework 2.0 — the control text itself, as JSON rather than as a
PDF nobody can parse. This is where ``AU-6`` stops being an opaque token and
becomes *Audit Record Review, Analysis, and Reporting* followed by three
paragraphs about what that obliges you to do.

**The join is the point.** DISA publishes a CCI list mapping every Control
Correlation Identifier to the SP 800-53 control it derives from, and this
adapter fetches it and resolves it. So a STIG rule does not print a bare
``CCI-000366``; it prints::

    CCI: CCI-000366 Implement the security configuration settings.
         (NIST SP 800-53 Rev 5 CM-6 b — Configuration Settings)

Identifier, definition, target identifier and target *name*, in one line, with
the full text of CM-6 elsewhere in the same source. Measured on the current
lists: 3,849 CCI-to-Rev-5 references resolve and **zero** fail to, so this is a
complete join rather than a lucky sample.

---

**Register: PROSE, and that was measured rather than assumed.** These documents
carry commands, and a source that carries commands is tempting to file under
SHELL, where the corpus is even hungrier. It would be wrong. Classifying the
lines of every check and fix procedure in the RHEL 9 STIG — 452 rules — puts
**11.6%** of that text in command shape and the rest in sentences. What a STIG
rule looks like on the page is English under labelled headings with a command
quoted inside it, and that is the prose register. The commands are a bonus for
SHELL exposure, not a claim this source makes.

**Side: BLUE, and this source moves the offence ratio the wrong way.** Worth
saying plainly rather than burying: the corpus is at 30% red against a ~60%
target, and every document here is defensive. Government hardening guidance is
written by defenders for defenders and ends in a list of things to go and fix;
calling it NEUTRAL to protect a ratio would be a lie about what it is. The
justification for adding it anyway is that PROSE is the binding constraint on
the register balancer, and a register the balancer cannot fill costs the corpus
far more than a few points of side ratio.

---

**Trap 1: the STIG description is escaped XML that is not XML.** Every
``<Rule><description>`` is a single text node holding an escaped blob::

    &lt;VulnDiscussion&gt;Unnecessary service packages must not…&lt;/VulnDiscussion&gt;
    &lt;FalsePositives&gt;&lt;/FalsePositives&gt;&lt;Documentable&gt;false&lt;/Documentable&gt;…

The obvious move — unescape it, wrap it in a root element, hand it back to the
parser — is wrong, and the Application Security and Development STIG is where
it breaks. Four of its rules quote SAML inside the discussion, so after
unescaping the blob contains ``<Subject>``, ``<SubjectConfirmation>``,
``<Conditions>`` and ``<OneTimeUse>`` at the same syntactic level as
``<VulnDiscussion>``. A parser cannot tell DISA's field wrapper from the
author's payload; it would either fail on the unbalanced fragment or silently
swallow the payload as markup. So the known field names are extracted by name,
one narrow pattern each, and *everything else that looks like a tag is left as
the literal text it is* — the same argument :mod:`.capec` makes about the
``<embed src=...>`` inside its XSS example.

The corollary is that nothing here calls ``html.unescape`` over a body. One
double-escaped ``&lt;`` survives, in one rule, catalogue-wide. Resolving it
would mean running an unescaper across text that is full of query strings and
shell, and mauling ``?a=1&globalVar=2`` to save one character is a bad trade.

**Trap 2: prefix matching pulls in the wrong product.** Family selection
resolves a curated list against the live directory index, and
``U_Google_Android_13`` is a prefix of ``U_Google_Android_13_BYOAD`` — a
different STIG for a different deployment model. Matching is therefore on the
family *exactly*, after stripping the version suffix, never on ``startswith``.

**Trap 3: two version schemes, and they interleave.** DISA moved from
``V2R4`` to date-stamped ``Y26M07`` part way through, and three families carry
both (``U_Google_Android_13``, ``U_IBM_HMC``, ``U_Tanium_7-x_TanOS``). Sorting
the strings puts ``V2R4`` after ``Y23M04`` and picks a release three years
stale. The comparator therefore ranks any ``Y``-form above any ``V``-form,
which is sound because the ``Y`` names are the newer convention — verified
against all three mixed families, where the ``Y`` release is in every case the
later publication.

**Trap 4: one zip can hold several benchmarks.** ``U_Cisco_IOS_Router`` ships
an NDM benchmark and an RTR benchmark in one archive, on independent version
numbers. Taking "the" XCCDF file would have dropped half of it, so every
``*Manual-xccdf.xml`` member is extracted and each becomes its own benchmark.

**Trap 5: percent-encoding in the index.** Two hrefs carry ``%20``
(``U_Splunk_Enterprise_8-x_for%20Linux``). Hrefs are used verbatim to build the
URL and are never unquoted — unquoting and re-quoting is how a fetch starts
404ing. The curated list names the underscore twin, which is the maintained one.

**Trap 6: near-duplicate rules across products.** The same requirement appears
word for word in the NDM benchmarks of five different switch vendors, and
including the rule identifier in the document text means the build's own
fingerprint dedup can never see it — the ids differ, so the texts differ. A
body fingerprint over title-plus-discussion-plus-check-plus-fix, with the
identifiers excluded, is kept here and repeats are held back and counted.

**Trap 7: OSCAL is one schema and five dialects.** The NIST half is the same
format five times and agrees with itself about almost nothing that matters to a
renderer. Every one of these was found by reading the output rather than the
schema:

* *The label, the title and the id are sometimes all the same string.* CSF
  subcategories and SSDF tasks title themselves ``PO.1.2``, so a heading built
  as "label then title" read ``PO.1.2 PO.1.2`` and the ``Name:`` line named
  nothing. SP 800-171 is the other way round, labelling a requirement
  ``Separation of Duties (03.01.04)`` whose title is inside its own label.
* *Withdrawn controls still carry their old text.* 182 SP 800-53 Rev 5
  controls, 91 CSF subcategories, 33 SP 800-171 and 12 SP 800-172
  requirements are withdrawn, and nothing in the control body says so — the
  flag is a ``status`` prop. Rendered unmarked, this source would have taught
  retired CSF 1.1 identifiers like ``PR.AC-01`` as current CSF 2.0 content.
  They are kept, because a withdrawn identifier still turns up in old
  assessment reports, but each is marked and points at what replaced it. One
  that points nowhere is a tombstone and is dropped.
* *The relation names disagree by punctuation and the hrefs by a ``#``.* SP
  800-53 writes ``incorporated-into`` and links ``#ac-6``; the CSF writes
  ``incorporated_into`` and links the bare ``GV.OC``. Matching one spelling
  and requiring the fragment marker produced empty withdrawal notices, which
  then failed the body check and silently dropped 91 real documents.
* *A withdrawn enhancement can forward to a statement item, not a control.*
  ``ac-2_smt.k`` is "item k of AC-2's statement" and resolves against no
  control index; printed raw it reads ``AC-2_SMT.K``, an identifier nobody
  writes.
* *SP 800-172 files its adversary-effects model under* ``name="statement"``,
  distinguished from the actual requirement only by ``class``. Selecting on
  the name welded "(includes preempt) Ensure that the threat event does not
  have an impact" onto the end of every enhanced requirement. It is now its
  own section — and a good one: Preclude / Impede / Limit / Expose / Redirect,
  each with the impact on the adversary and the result to expect, which is the
  only NIST prose in this source written about the attacker.

One thing that is *not* corrected: NIST's own prose sometimes carries a space
before its punctuation around a parameter, so a statement reads "Report
findings to [Assignment: organization-defined personnel or roles] ; and". That
space is in the upstream JSON, in 139 of 3,515 parameter references. It is the
publisher's text, and inventing a punctuation-tidying pass over a corpus full
of shell and query strings to save 139 characters is the wrong trade.

---

**Licensing, read from the upstreams' own files rather than from a badge.**

*NIST OSCAL content* — ``LICENSE.md`` in ``usnistgov/oscal-content`` states
"This project is in the worldwide public domain … As a work of the United
States government, this project is in the public domain within the United
States. Additionally, we waive copyright and related rights in the work
worldwide through the CC0 1.0 Universal public domain dedication." That is a
belt-and-braces grant: 17 USC 105 domestically, CC0 everywhere else. The file
is fetched and cached verbatim beside the catalogues it covers. Note that
GitHub's own licence detection returns ``NOASSERTION`` for this repository —
which is precisely why the file is read instead of the API field.

*DISA STIGs* — there is no LICENSE file to read, so three things were checked
instead. The XCCDF carries a ``<notice id="terms-of-use">`` element and it is
**empty**: DISA attaches no terms to the data. The package's own Overview
document, section "STIG Distribution", describes unrestricted public
distribution via ``public.cyber.mil`` for anyone without a CAC, and asserts no
copyright anywhere in the document; what it does assert is a liability
disclaimer, reproduced in :data:`_LICENSE`. And the content is marked
UNCLASSIFIED and "Developed by DISA for the DOD" — a work prepared by officers
and employees of the United States Government as part of their official duties,
which 17 USC 105 excludes from copyright protection.

Two honest caveats are written into the licence string rather than glossed.
17 USC 105 is a statement about copyright *in the United States*; the CC0
waiver that NIST adds is not something DISA has said. And third-party material
is real here: the STIG packages contain a DoD/DISA logo JPEG and several PDFs
whose figures this project has not cleared. **Only the XCCDF XML is ever
extracted.** The logo and every PDF are left inside the archive, which is then
deleted. That is the concrete answer to "some NIST pages carry third-party
copyrighted figures": do not take the pictures.

**Held back, and counted out loud.** ``Documentable`` is ``false`` on every
rule in every STIG, and its nine sibling fields — ``FalsePositives``,
``Mitigations``, ``ThirdPartyTools`` and the rest — are empty on every rule of
all 135 benchmarks measured. The renderer still asks for them, so the day DISA
starts filling one in it arrives for free; :func:`_section` drops a heading
with nothing under it, so today they cost nothing. The per-rule ``<reference>`` block
is DISA's asset-management boilerplate ("DPMS Target …") repeated once per rule
and is dropped. On the NIST side the SP 800-53A ``assessment-objective`` parts
are dropped: they are the control statement rewritten in the passive voice, and
the measurement says so — median 0.70 sequence similarity against the statement
they assess, 64% of controls above 0.6. Keeping both would teach the model to
paraphrase itself in a corpus already small enough to memorise. The
``assessment-method`` parts survive, because EXAMINE/INTERVIEW/TEST against a
named list of artefacts is the *verification* half and is the NIST analogue of
the STIG check procedure — which is the whole reason these two upstreams share
a source.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Generator, Iterator

from ..net import NetworkError, download, fetch
from ..source import (Document, Register, Side, SourceError, SourceSpec,
                      fingerprint, normalise)

# ---------------------------------------------------------------------------
# where things live
# ---------------------------------------------------------------------------

#: The OSCAL content repository as a codeload tarball: one 12 MB request, no
#: git binary, no history, and nothing a later ``git pull`` can mutate under a
#: reproducible build. Same reasoning as :mod:`.sigma`.
_OSCAL_TARBALL = "https://codeload.github.com/usnistgov/oscal-content/tar.gz/refs/heads/main"
_OSCAL_HOME = "https://github.com/usnistgov/oscal-content"
_OSCAL_LICENSE_MEMBER = "LICENSE.md"

#: DISA's download host, serving a plain Apache-style directory index. This is
#: the only stable machine-readable route to the STIG library: ``cyber.mil``
#: itself is now a Salesforce Experience Cloud site whose STIG document library
#: is assembled entirely in JavaScript and contains not one ``.zip`` href.
_STIG_INDEX = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
_CCI_ZIP = _STIG_INDEX + "CCI_List.zip"

_NIST_DIR = "nist"
_STIG_DIR = "stig"
_CCI_FILE = "cci_list.xml"
_INDEX_FILE = "stig_index.html"

#: Written last, so its presence means every stage finished. An interrupted
#: fetch therefore re-fetches instead of being mistaken for a complete cache —
#: which is how a corpus silently loses half a register.
_MARKER = ".fetched.json"

#: NIST publication, version directory, and the label this source files its
#: documents under. Matched as path components against the tarball rather than
#: as a full path, because NIST's own file naming is not self-consistent:
#: ``NIST_SP-800-53_rev5_catalog.json`` has a hyphen after ``SP`` and
#: ``NIST_SP800-171_rev3_catalog.json`` does not. Globbing the directory and
#: taking the ``_catalog.json`` in it survives that; constructing the filename
#: does not.
#:
#: Rev 4 of SP 800-53 is deliberately absent even though the repository carries
#: it. It is a near-duplicate of Rev 5 — same families, same control names,
#: heavily overlapping text — and duplicated text in a corpus this size is
#: worse than absent text. The ``*-baseline_profile`` and
#: ``*-resolved-profile_catalog`` files are absent for the same reason squared:
#: a resolved profile is the Rev 5 control prose *copied out again* filtered to
#: one impact level, so taking LOW, MODERATE and HIGH would put three more
#: copies of the same catalogue in the corpus.
_CATALOGS: tuple[tuple[str, str, str, str], ...] = (
    ("SP800-53", "rev5", "SP800-53r5", "NIST SP 800-53 Rev 5"),
    ("SP800-171", "rev3", "SP800-171r3", "NIST SP 800-171 Rev 3"),
    ("SP800-172", "rev3", "SP800-172r3", "NIST SP 800-172 Rev 3"),
    ("SP800-218", "ver1", "SP800-218", "NIST SP 800-218 (SSDF) v1.1"),
    ("CSF", "v2.0", "CSF2.0", "NIST Cybersecurity Framework 2.0"),
)

#: The STIG families to take, named exactly as the index names them minus the
#: version suffix. This is a selection, not a filter on a whole-library fetch,
#: and the selection is the design decision: the index carries 268 families and
#: 606 archives, of which a large majority are appliance firmware and mobile
#: vendor skins whose rules are near-verbatim copies of one another.
#:
#: What is chosen is *surface-form diversity* — the register argument applied to
#: a source rather than a corpus. A Linux STIG is ``systemctl`` and ``grep`` and
#: file modes; a Windows STIG is registry paths and ``Get-`` cmdlets and Group
#: Policy paths; a Cisco STIG is IOS configuration lines; a database STIG is
#: SQL; Kubernetes is YAML and ``kubectl``. Those five look nothing alike and
#: every one of them is a shape the agent will be asked to read.
#:
#: What is deliberately *not* chosen is the second member of a clone pair.
#: Oracle Linux 9, AlmaLinux 9, Rocky and TOSS are rebuilds of RHEL 9 and their
#: STIGs are rebuilds of the RHEL 9 STIG; Windows Server 2019 sits between 2016
#: and 2022; the Office 2016 family ships eleven per-application STIGs that
#: differ by the product name. One of each is here, the rest are not.
_FAMILIES: tuple[str, ...] = (
    # Linux and Unix
    "U_RHEL_8",
    "U_RHEL_9",
    "U_CAN_Ubuntu_22-04_LTS",
    "U_CAN_Ubuntu_24-04_LTS",
    "U_SLES_15",
    "U_Amazon_Linux_2023",
    "U_IBM_AIX_7-x",
    "U_SOL_11_x86",
    # Windows
    "U_MS_Windows_11",
    "U_MS_Windows_Server_2022",
    "U_MS_Windows_Server_2025",
    "U_MS_Windows_Defender_Firewall",
    "U_MS_Defender_Antivirus",
    "U_MS_Defender_Endpoint",
    "U_Active_Directory_Domain",
    "U_Active_Directory_Forest",
    "U_MS_Windows_PAW",
    "U_MS_Windows_Server_DNS",
    "U_MS_IIS_10-0",
    # Apple and mobile
    "U_Apple_macOS_15",
    "U_Apple_iOS-iPadOS_18",
    "U_Google_Android_15",
    # Network infrastructure
    "U_Cisco_IOS_Router",
    "U_Cisco_IOS_Switch",
    "U_Cisco_NX-OS_Switch",
    "U_Cisco_ASA",
    "U_Cisco_ISE",
    "U_Juniper_Router",
    "U_Juniper_SRX_SG",
    "U_Juniper_EX_Switches",
    "U_PAN",
    "U_F5_BIG-IP_TMOS",
    "U_FN_FortiGate_Firewall",
    "U_Arista_MLS_EOS_4-X",
    "U_HPE_Aruba_Networking_AOS",
    "U_Network_Infrastructure_Policy",
    "U_Network_WLAN",
    # Web and application servers
    "U_Apache_Server_2-4_Unix",
    "U_Apache_Server_2-4_Windows",
    "U_Apache_Tomcat_Application_Server_9",
    "U_F5_NGINX",
    "U_IBM_WebSphere_Liberty_Server",
    # Secure development: the only STIG written about code rather than config.
    "U_ASD",
    # Databases
    "U_MS_SQL_Server_2022",
    "U_Oracle_Database_19c",
    "U_Oracle_MySQL_8-0",
    "U_CD_Postgres_16",
    "U_MongoDB_Enterprise_Advanced_7-x",
    "U_MariaDB_Enterprise_10-x",
    "U_Redis_Enterprise_6-x",
    # Containers, cloud, virtualisation, identity
    "U_Kubernetes",
    "U_RGS_RKE2",
    "U_RH_OpenShift_Container_Platform_4-x",
    "U_Docker_Enterprise_2-x_Linux-Unix",
    "U_VMW_vSphere_8-0",
    "U_VMW_NSX_4-x",
    "U_MS_Entra_ID",
    "U_Okta_IDaaS",
    # Browsers and endpoint applications
    "U_Google_Chrome",
    "U_MOZ_Firefox",
    "U_MS_Edge",
    "U_MS_Office_365_ProPlus",
    # Operations, logging, DNS, mainframe
    "U_Splunk_Enterprise_8-x_for_Linux",
    "U_Tanium_7-x",
    "U_BIND_9-x",
    "U_Infoblox_NIOS_9-x",
    "U_IBM_zOS",
)

# ---------------------------------------------------------------------------
# ceilings
# ---------------------------------------------------------------------------

#: One archive member may not be read into memory unbounded. NUL bytes compress
#: at roughly 1000:1, so an 8 GiB member leaves an archive looking entirely
#: ordinary on the wire and then asks for 8 GiB of RAM — a MemoryError that
#: kills the build, or an OOM kill that picks the training run instead. The
#: largest XCCDF in the selection is under 1.5 MB and the CCI list is 3.2 MB.
_MAX_MEMBER_BYTES = 64 * 1024 * 1024

#: ``zipfile`` does not bound the reader it hands back the way ``tarfile``
#: does, so the declared size is checked *and* the read is bounded. See
#: :func:`_extract_zip_members`.
_MAX_ZIP_BYTES = 128 * 1024 * 1024
_MAX_TARBALL_BYTES = 128 * 1024 * 1024
_MAX_INDEX_BYTES = 8 * 1024 * 1024

#: Floors. A fetch that lands under one of these has met an upstream layout
#: change, not a quiet day, and must say so rather than yield a fragment.
_MIN_FAMILIES = 30
_MIN_CATALOGS = 4
_MIN_INDEX_ZIPS = 200

#: Below this a rendered document is a header with nothing under it.
_MIN_CHARS = 200

_ZIP_TIMEOUT = 300
_INDEX_TIMEOUT = 120

# ---------------------------------------------------------------------------
# patterns
# ---------------------------------------------------------------------------

#: ``U_RHEL_9_V2R4_STIG.zip`` / ``U_Cisco_IOS_Router_Y26M07_STIG.zip``. The
#: family is whatever precedes the version, and it is compared for *equality*
#: against the curated list — see trap 2 in the module docstring.
_STIG_ZIP = re.compile(
    r"^(?P<family>.+?)_(?:V(?P<major>\d+)R(?P<minor>\d+)"
    r"|Y(?P<year>\d{2})M(?P<month>\d{2}))_STIG\.zip$"
)

#: Anything an href must look like before it is pasted onto the index URL. The
#: index is a third party's HTML and its hrefs are data: a name with a slash,
#: a scheme or a ``..`` in it is not a file in this directory and must never
#: reach :func:`~training.corpus.net.download`.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._%()+-]+\.zip$")

#: The escaped fields DISA packs into ``<Rule><description>``. Extracted by
#: name, non-greedily, one at a time — never by re-parsing the blob. See trap 1.
_STIG_FIELDS: tuple[tuple[str, str], ...] = (
    ("VulnDiscussion", "Discussion"),
    ("FalsePositives", "False positives"),
    ("FalseNegatives", "False negatives"),
    ("Mitigations", "Mitigations"),
    ("SeverityOverrideGuidance", "Severity override guidance"),
    ("PotentialImpacts", "Potential impacts"),
    ("ThirdPartyTools", "Third-party tools"),
    ("MitigationControl", "Mitigation control"),
    ("Responsibility", "Responsibility"),
    ("IAControls", "IA controls"),
)

#: ``Documentable`` is not in the list above on purpose. It is a boolean flag,
#: it reads ``false`` on every rule of every STIG measured, and rendering it
#: would put one identical line on thirty thousand documents.
_STIG_DROPPED_FIELD = "Documentable"

_FIELD_PATTERNS = {
    name: re.compile(rf"<{name}>(.*?)</{name}>", re.DOTALL)
    for name, _ in (*_STIG_FIELDS, (_STIG_DROPPED_FIELD, ""))
}

#: ``CM-2 (2)`` and ``CM-6 b`` as DISA writes them in the CCI list, mapped onto
#: the OSCAL control id (``cm-2.2``, ``cm-6``). The trailing statement letter is
#: not part of a control id; the parenthesised number is the enhancement.
_CCI_INDEX = re.compile(r"^([A-Za-z]{2})-(\d+)\s*(?:\((\d+)\))?")

#: A group id short enough, and clean enough, to be a family code a reader
#: recognises. Anything longer is OSCAL's internal key — see :meth:`_Catalog._walk_group`.
_FAMILY_CODE = re.compile(r"^[A-Za-z]{2}(?:\.[A-Za-z]{2})?$")

#: OSCAL's parameter placeholder. NIST's published rendering of an unfilled
#: parameter is ``[Assignment: organization-defined frequency]``, and that
#: bracketed form is how SP 800-53 reads on the page — which makes it the wild
#: form, and the one the model should meet.
_INSERT = re.compile(r"\{\{\s*insert:\s*param,\s*([^}\s]+)\s*\}\}")


# ---------------------------------------------------------------------------
# fetch: NIST
# ---------------------------------------------------------------------------

def _fetch_nist(cache_dir: Path) -> dict[str, str]:
    """Unpack the five OSCAL catalogues and the repository's LICENSE.

    Returns ``{label: version}`` for the marker file. Idempotent: a populated
    ``nist/`` directory short-circuits without touching the network, because
    the build runs often and this is 12 MB over the wire.
    """
    target = cache_dir / _NIST_DIR
    wanted = {label for _, _, label, _ in _CATALOGS}
    if target.is_dir() and wanted <= {p.stem for p in target.glob("*.json")}:
        return _catalog_versions(target)

    staging = cache_dir / ".nist.staging"
    archive = cache_dir / ".oscal-content.tar.gz"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    try:
        try:
            download(_OSCAL_TARBALL, archive, timeout=_ZIP_TIMEOUT,
                     max_bytes=_MAX_TARBALL_BYTES)
        except NetworkError as exc:
            raise SourceError(
                f"govguidance: could not fetch {_OSCAL_TARBALL}: {exc}"
            ) from exc

        found = _extract_tar_members(archive, staging)
        missing = wanted - set(found)
        if len(found) < _MIN_CATALOGS:
            raise SourceError(
                f"govguidance: only {len(found)} of {len(_CATALOGS)} NIST "
                f"catalogues found in {_OSCAL_TARBALL} (missing "
                f"{sorted(missing)}). usnistgov/oscal-content has moved its "
                "directory layout — fix the adapter rather than training on a "
                "fragment of the register this source exists for."
            )
        if missing:
            print(f"   govguidance: NIST catalogue(s) not in the tarball: "
                  f"{', '.join(sorted(missing))}")

        shutil.rmtree(target, ignore_errors=True)
        staging.replace(target)
    finally:
        archive.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)
    return _catalog_versions(target)


def _extract_tar_members(archive: Path, staging: Path) -> dict[str, Path]:
    """Copy the wanted catalogues and the LICENSE out of the tarball.

    Members are selected and written by hand rather than via ``extractall``.
    An archive member is attacker-controlled data in principle — absolute
    paths, ``..`` segments and symlinks are all expressible in tar — and the
    cheap defence is never to hand the archive's own names to the filesystem.
    Only regular files are written, and only ever under a basename this module
    chose.
    """
    found: dict[str, Path] = {}
    try:
        with tarfile.open(archive, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                relative = "/".join(parts[1:])   # drop "oscal-content-main/"
                label = _wanted_catalog(relative)
                if label is None and relative != _OSCAL_LICENSE_MEMBER:
                    continue
                if member.size > _MAX_MEMBER_BYTES:
                    print(f"   govguidance: skipped {relative} — declares "
                          f"{member.size:,} bytes, over the member ceiling")
                    continue
                stream = tar.extractfile(member)
                if stream is None:
                    continue
                name = f"{label}.json" if label else "LICENSE.oscal-content.md"
                out = staging / name
                with stream, out.open("wb") as handle:
                    shutil.copyfileobj(stream, handle, length=1 << 20)
                if label:
                    found[label] = out
    except (tarfile.TarError, OSError) as exc:
        raise SourceError(
            f"govguidance: could not unpack {archive}: {exc}") from exc
    return found


def _wanted_catalog(relative: str) -> str | None:
    """The label for a tarball path, or ``None`` if it is not one we take.

    Matched on path *components* — publication and version directory — with the
    filename checked only for the ``_catalog.json`` suffix. NIST's filenames are
    inconsistent across publications (see :data:`_CATALOGS`); their directory
    layout is not.
    """
    parts = relative.split("/")
    if len(parts) != 5 or parts[0] != "nist.gov" or parts[3] != "json":
        return None
    publication, version, name = parts[1], parts[2], parts[4]
    if not name.endswith("_catalog.json") or "-min" in name:
        return None
    # A resolved baseline profile is the same control prose filtered to one
    # impact level. Three of them would be three more copies of the catalogue.
    if "baseline" in name or "resolved-profile" in name:
        return None
    for pub, ver, label, _ in _CATALOGS:
        if publication == pub and version == ver:
            return label
    return None


def _catalog_versions(target: Path) -> dict[str, str]:
    """``{label: catalogue version}``, best effort, for the marker file."""
    versions: dict[str, str] = {}
    for _, _, label, _ in _CATALOGS:
        path = target / f"{label}.json"
        if not path.is_file():
            continue
        try:
            with path.open(encoding="utf-8") as handle:
                metadata = json.load(handle)["catalog"]["metadata"]
            versions[label] = str(metadata.get("version", ""))
        except (OSError, ValueError, KeyError):
            versions[label] = "?"
    return versions


# ---------------------------------------------------------------------------
# fetch: DISA
# ---------------------------------------------------------------------------

class _IndexParser(HTMLParser):
    """Collect ``a/@href`` from DISA's directory index.

    ``html.parser`` from the stdlib rather than a regex, for the ordinary
    reason: the index is generated HTML today and could be generated
    differently tomorrow, and a parser degrades to "found nothing" where a
    regex degrades to "found something that is not a filename".
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag != "a":
            return
        for name, value in attrs:
            if name == "href" and value:
                self.hrefs.append(value)


def _stig_index(cache_dir: Path) -> list[str]:
    """Every ``*.zip`` href in the STIG download directory, as written.

    Hrefs are returned verbatim, percent-encoding and all. Unquoting them here
    and re-quoting them at download time is how two families (the ``%20``
    Splunk twins) start 404ing; the curated list names the underscore form and
    the encoded ones simply never match.
    """
    try:
        body = fetch(_STIG_INDEX, timeout=_INDEX_TIMEOUT,
                     max_bytes=_MAX_INDEX_BYTES)
    except NetworkError as exc:
        raise SourceError(
            f"govguidance: could not fetch the STIG index {_STIG_INDEX}: {exc}"
        ) from exc

    text = body.decode("utf-8", "replace")
    (cache_dir / _INDEX_FILE).write_text(text, encoding="utf-8")

    parser = _IndexParser()
    parser.feed(text)
    names = [href for href in parser.hrefs if _SAFE_NAME.match(href)]
    if len(names) < _MIN_INDEX_ZIPS:
        raise SourceError(
            f"govguidance: {_STIG_INDEX} listed only {len(names)} archives "
            f"(expected >= {_MIN_INDEX_ZIPS}). DISA has changed the download "
            "host's layout, or something other than the index answered."
        )
    return names


def _version_rank(match: re.Match[str]) -> tuple[int, int, int]:
    """Order two DISA version schemes against each other.

    ``Y26M07`` outranks every ``V#R#`` because the date-stamped names are the
    newer convention — DISA migrated to them in 2024, so a family carrying both
    has its ``Y`` release as the later publication. Verified against all three
    families that carry both schemes; string sorting gets every one of them
    wrong, picking a release up to three years stale.
    """
    if match.group("year") is not None:
        return (1, int(match.group("year")), int(match.group("month")))
    return (0, int(match.group("major")), int(match.group("minor")))


def _latest_per_family(names: list[str]) -> dict[str, str]:
    """``{family: newest zip name}``, restricted to the curated families.

    Equality on the family, never ``startswith``: ``U_Google_Android_13`` is a
    prefix of ``U_Google_Android_13_BYOAD``, which is a different STIG for a
    different deployment model.
    """
    wanted = set(_FAMILIES)
    best: dict[str, tuple[tuple[int, int, int], str]] = {}
    for name in names:
        match = _STIG_ZIP.match(name)
        if match is None:
            continue
        family = match.group("family")
        if family not in wanted:
            continue
        rank = _version_rank(match)
        if family not in best or rank > best[family][0]:
            best[family] = (rank, name)
    return {family: name for family, (_, name) in best.items()}


def _fetch_stigs(cache_dir: Path) -> dict[str, str]:
    """Download the newest archive per family; keep only its XCCDF members.

    Resumable per family: each family records the archive it was built from in
    a sidecar, so a re-run re-downloads only the families whose newest release
    has changed. That matters because this stage is ~70 requests.
    """
    target = cache_dir / _STIG_DIR
    target.mkdir(parents=True, exist_ok=True)
    resolved = _latest_per_family(_stig_index(cache_dir))

    unresolved = sorted(set(_FAMILIES) - set(resolved))
    if unresolved:
        print(f"   govguidance: {len(unresolved)} STIG famil(ies) are no "
              f"longer in the index: {', '.join(unresolved)}")

    built: dict[str, str] = {}
    failed: list[str] = []
    for family in _FAMILIES:
        archive_name = resolved.get(family)
        if archive_name is None:
            continue
        family_dir = target / family
        sidecar = target / f"{family}.json"
        if _already_built(sidecar, family_dir, archive_name):
            built[family] = archive_name
            continue
        try:
            benchmarks = _fetch_one_stig(family, archive_name, family_dir)
        except SourceError as exc:
            failed.append(f"{family} ({exc})")
            continue
        sidecar.write_text(
            json.dumps({"archive": archive_name, "benchmarks": benchmarks,
                        "url": _STIG_INDEX + archive_name}, indent=2),
            encoding="utf-8",
        )
        built[family] = archive_name

    if failed:
        print(f"   govguidance: {len(failed)} STIG famil(ies) failed: "
              f"{'; '.join(failed)}")
    if len(built) < _MIN_FAMILIES:
        raise SourceError(
            f"govguidance: only {len(built)} of {len(_FAMILIES)} STIG families "
            f"were fetched (floor {_MIN_FAMILIES}). Either the download host "
            "changed layout or the network refused most of the run; training "
            "on the remainder would silently under-fill the prose register."
        )
    return built


def _already_built(sidecar: Path, family_dir: Path, archive_name: str) -> bool:
    """True when this family's cache was built from this exact archive."""
    if not family_dir.is_dir():
        return False
    try:
        with sidecar.open(encoding="utf-8") as handle:
            return json.load(handle).get("archive") == archive_name
    except (OSError, ValueError):
        return False


def _fetch_one_stig(family: str, archive_name: str, family_dir: Path) -> list[str]:
    """Download one STIG archive and extract every XCCDF benchmark in it.

    The archive is deleted afterwards, and that is a licensing decision as much
    as a disk one: STIG packages carry a DoD/DISA logo JPEG and several PDFs
    whose figures this project has not cleared. Only the XML is kept.
    """
    url = _STIG_INDEX + archive_name
    staging = family_dir.parent / f".{family}.zip"
    unpacked = family_dir.parent / f".{family}.staging"
    shutil.rmtree(unpacked, ignore_errors=True)
    try:
        try:
            download(url, staging, timeout=_ZIP_TIMEOUT,
                     max_bytes=_MAX_ZIP_BYTES)
        except NetworkError as exc:
            raise SourceError(f"download failed: {exc}") from exc

        unpacked.mkdir(parents=True, exist_ok=True)
        names = _extract_zip_members(
            staging, unpacked,
            keep=lambda n: n.lower().endswith("manual-xccdf.xml"),
        )
        if not names:
            raise SourceError(f"no Manual-xccdf.xml member in {archive_name}")

        shutil.rmtree(family_dir, ignore_errors=True)
        unpacked.replace(family_dir)
        return sorted(names)
    finally:
        staging.unlink(missing_ok=True)
        shutil.rmtree(unpacked, ignore_errors=True)


def _extract_zip_members(archive: Path, staging: Path, *,
                         keep: Callable[[str], bool]) -> list[str]:
    """Write the members ``keep`` accepts into ``staging``, by basename only.

    Two differences from the tar path, both deliberate. ``ZipInfo.file_size`` is
    a *claim* by the archive and ``zipfile`` does not bound the reader it hands
    back the way ``tarfile`` does, so the declared size is refused first **and**
    the streaming read is bounded second — a zip can declare 4 KB and deliver
    gigabytes. And only the member's basename is used, never its path, so a
    member named ``../../etc/authorized_keys`` cannot address anything.
    """
    written: list[str] = []
    try:
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir() or not keep(info.filename):
                    continue
                name = Path(info.filename).name
                if not name or name in (".", ".."):
                    continue
                if info.file_size > _MAX_MEMBER_BYTES:
                    print(f"   govguidance: skipped {info.filename} — declares "
                          f"{info.file_size:,} bytes, over the member ceiling")
                    continue
                out = staging / name
                total = 0
                with zf.open(info) as stream, out.open("wb") as handle:
                    while chunk := stream.read(1 << 20):
                        total += len(chunk)
                        if total > _MAX_MEMBER_BYTES:
                            break
                        handle.write(chunk)
                if total > _MAX_MEMBER_BYTES:
                    out.unlink(missing_ok=True)
                    print(f"   govguidance: {info.filename} ran past the "
                          "member ceiling mid-stream and was discarded")
                    continue
                written.append(name)
    except (zipfile.BadZipFile, OSError) as exc:
        raise SourceError(f"could not unpack {archive.name}: {exc}") from exc
    return written


def _fetch_cci(cache_dir: Path) -> int:
    """Download DISA's CCI list; return the number of items in it.

    This is the file that turns ``CCI-000366`` on a STIG rule into the SP
    800-53 control it derives from, which is the join this source is built
    around. A failure here is not fatal — the STIG rules still render, minus
    the mapping — but it is reported rather than swallowed.
    """
    target = cache_dir / _CCI_FILE
    if target.is_file() and target.stat().st_size > 100_000:
        return _count_cci(target)

    staging = cache_dir / ".cci.zip"
    unpacked = cache_dir / ".cci.staging"
    shutil.rmtree(unpacked, ignore_errors=True)
    try:
        download(_CCI_ZIP, staging, timeout=_ZIP_TIMEOUT,
                 max_bytes=_MAX_ZIP_BYTES)
        unpacked.mkdir(parents=True, exist_ok=True)
        names = _extract_zip_members(
            staging, unpacked,
            keep=lambda n: n.lower().endswith("cci_list.xml"),
        )
        if not names:
            raise SourceError(f"no CCI_List.xml member in {_CCI_ZIP}")
        os.replace(unpacked / names[0], target)
    except (NetworkError, SourceError, OSError) as exc:
        print(f"   govguidance: CCI list unavailable ({exc}); STIG rules will "
              "carry their CCI ids without the SP 800-53 control they map to")
        return 0
    finally:
        staging.unlink(missing_ok=True)
        shutil.rmtree(unpacked, ignore_errors=True)
    return _count_cci(target)


def _count_cci(path: Path) -> int:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return 0
    ns = _namespace(root)
    return len(root.findall(f"{ns}cci_items/{ns}cci_item"))


# ---------------------------------------------------------------------------
# fetch: the whole thing
# ---------------------------------------------------------------------------

def _fetch(cache_dir: Path) -> Path:
    """Populate ``cache_dir`` and return it.

    The completion marker is written **last**, after every stage has finished,
    so an interrupted fetch re-fetches rather than being mistaken for a
    complete cache. Each stage is independently resumable underneath that, so
    an interruption costs the family it was in the middle of and nothing more.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file() and (cache_dir / _NIST_DIR).is_dir() \
            and (cache_dir / _STIG_DIR).is_dir():
        return cache_dir

    catalogs = _fetch_nist(cache_dir)
    cci_items = _fetch_cci(cache_dir)
    families = _fetch_stigs(cache_dir)
    _write_license(cache_dir)

    marker.write_text(
        json.dumps(
            {
                "oscal_url": _OSCAL_TARBALL,
                "oscal_catalogs": catalogs,
                "stig_index": _STIG_INDEX,
                "stig_families": families,
                "cci_items": cci_items,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "license": _LICENSE,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _write_license(cache_dir: Path) -> None:
    """Record the licence reasoning into the cache, beside what it covers.

    ``LICENSE.oscal-content.md`` is already there — it came out of the tarball
    verbatim, which is the point: NIST's own words, not a paraphrase. What this
    adds is the DISA half, which has no LICENSE file to copy and therefore has
    to carry its reasoning instead. Best effort; a build must not fail because
    a sidecar note could not be written.
    """
    try:
        (cache_dir / "LICENSE.stig.txt").write_text(_LICENSE, encoding="utf-8")
    except OSError:
        return


def _resolve(path: Path) -> Path:
    """Accept the cache directory, and prove it was actually populated."""
    if not path.is_dir():
        raise SourceError(f"govguidance: {path} is not a directory")
    if not (path / _NIST_DIR).is_dir() and not (path / _STIG_DIR).is_dir():
        raise SourceError(
            f"govguidance: {path} holds neither {_NIST_DIR}/ nor {_STIG_DIR}/ "
            "— run the source's fetch() first"
        )
    return path


# ---------------------------------------------------------------------------
# XML helpers
# ---------------------------------------------------------------------------

def _namespace(root: ET.Element) -> str:
    """The document's namespace in ``{uri}`` form, read off the root element.

    Hardcoding ``xccdf/1.1`` would mean an XCCDF 1.2 benchmark yielding zero
    rules: every ``find`` would miss and the source would report success with
    nothing in it. Reading it here makes that event either work or fail the
    root-name check, both of which beat silence.
    """
    tag = root.tag
    return tag[: tag.index("}") + 1] if tag.startswith("{") else ""


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _field(description: str, name: str) -> str:
    """One escaped field out of a STIG rule description, or ``""``.

    Non-greedy, and by name. What it deliberately does *not* do is treat the
    description as markup: everything between the named tags is returned as the
    literal text it is, which is what keeps the SAML fragments inside the
    Application Security STIG's discussions intact. See trap 1.
    """
    match = _FIELD_PATTERNS[name].search(description)
    return match.group(1).strip() if match else ""


# ---------------------------------------------------------------------------
# the CCI join
# ---------------------------------------------------------------------------

class _CciIndex:
    """CCI identifier -> its definition and the SP 800-53 Rev 5 control.

    Built once and consulted per rule. The Rev 5 reference is preferred and the
    older revisions are ignored: a rule that cites ``CM-6 b`` under Rev 3 and
    ``CM-6 b`` under Rev 5 would otherwise print the same mapping four times.
    """

    _REV5 = "NIST SP 800-53 Revision 5"

    def __init__(self, path: Path | None) -> None:
        self.definitions: dict[str, str] = {}
        self.controls: dict[str, list[str]] = {}
        if path is None or not path.is_file():
            return
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError):
            return
        ns = _namespace(root)
        for item in root.findall(f"{ns}cci_items/{ns}cci_item"):
            cci = (item.get("id") or "").strip()
            if not cci:
                continue
            definition = (item.findtext(f"{ns}definition") or "").strip()
            if definition:
                self.definitions[cci] = definition
            indexes = [
                (ref.get("index") or "").strip()
                for ref in item.findall(f"{ns}references/{ns}reference")
                if (ref.get("title") or "").strip() == self._REV5
            ]
            if indexes:
                self.controls[cci] = indexes

    def line(self, cci: str, titles: dict[str, str]) -> str:
        """One rendered ``CCI:`` line, with as much of the join as resolves.

        ``titles`` is the SP 800-53 Rev 5 control-id-to-name map built from the
        catalogue in this same source, which is what puts the control's *name*
        next to its identifier — the shape the tokenizer measurement rewarded.
        """
        parts = [cci]
        definition = self.definitions.get(cci)
        if definition:
            parts.append(definition)
        mapped = []
        for index in self.controls.get(cci, []):
            title = titles.get(_oscal_id(index) or "", "")
            mapped.append(f"{index} — {title}" if title else index)
        if mapped:
            parts.append(f"(NIST SP 800-53 Rev 5 {'; '.join(mapped)})")
        return " ".join(parts)


def _oscal_id(index: str) -> str | None:
    """``CM-2 (2)`` -> ``cm-2.2``; ``CM-6 b`` -> ``cm-6``.

    The trailing letter in ``CM-6 b`` points at a statement item inside the
    control, not at a separate control, so it is dropped for the lookup while
    staying in the rendered text — the reader wants to know it was ``b``.
    """
    match = _CCI_INDEX.match(index.strip())
    if match is None:
        return None
    family, number, enhancement = match.groups()
    out = f"{family.lower()}-{int(number)}"
    return f"{out}.{int(enhancement)}" if enhancement else out


# ---------------------------------------------------------------------------
# NIST OSCAL rendering
# ---------------------------------------------------------------------------

class _Catalog:
    """One parsed OSCAL catalogue plus the indexes rendering needs."""

    def __init__(self, path: Path, label: str, pretty: str) -> None:
        try:
            with path.open(encoding="utf-8") as handle:
                catalog = json.load(handle)["catalog"]
        except (OSError, ValueError, KeyError) as exc:
            raise SourceError(
                f"govguidance: {path} is not an OSCAL catalogue: {exc}") from exc

        self.label = label
        self.pretty = pretty
        self.metadata = catalog.get("metadata", {})
        self.version = str(self.metadata.get("version", ""))

        #: control -> the family it sits in, so a document can say "AU Audit
        #: and Accountability" rather than leaving the reader to infer it.
        self.family: dict[str, str] = {}
        self.controls: list[dict] = []
        for group in catalog.get("groups", []):
            self._walk_group(group, "")
        for control in catalog.get("controls", []):
            self._walk_control(control, "")

        self.titles: dict[str, str] = {
            c["id"]: str(c.get("title", "")) for c in self.controls
        }
        #: Precomputed rather than searched per reference. A control cites ~15
        #: related controls and there are 1,196 of them, so resolving a label
        #: by scanning the control list is 21 million comparisons per build —
        #: measurably slow for a lookup that is a dictionary.
        self.labels: dict[str, str] = {
            c["id"]: (_label(c) or str(c["id"]).upper()) for c in self.controls
        }
        self.params: dict[str, dict] = {
            p["id"]: p
            for c in self.controls for p in c.get("params", []) if "id" in p
        }
        self.resources: dict[str, str] = {}
        for resource in catalog.get("back-matter", {}).get("resources", []):
            uuid = str(resource.get("uuid", ""))
            if uuid:
                self.resources[uuid] = _render_resource(resource)

    def _walk_group(self, group: dict, parent: str) -> None:
        # The group id is worth printing when it is the family code a reader
        # would recognise — "AU", "GV", "PO" — and is noise when it is OSCAL's
        # internal key. SP 800-171 groups are ``SP_800_171_03.01`` and SP
        # 800-172's are ``SP_800_172_3_0_0_3.1``, which put a random-looking
        # token in front of "Access Control" on every one of their documents.
        group_id = str(group.get("id", "")).strip()
        prefix = group_id.upper() if _FAMILY_CODE.match(group_id) else ""
        name = f"{prefix} {group.get('title', '')}".strip() or parent
        for control in group.get("controls", []):
            self._walk_control(control, name)
        for child in group.get("groups", []):
            self._walk_group(child, name)

    def named(self, control_id: str) -> str:
        """``AC-2 Account Management`` — the identifier beside what it denotes.

        Two shapes have to survive this. The CSF titles every subcategory with
        its own id, so a naive "label then title" prints ``PR.AA-01 PR.AA-01``;
        it is said once. And SP 800-53 forwards a withdrawn enhancement at a
        *part* rather than a control — ``ac-2_smt.k``, meaning item k of AC-2's
        statement — which resolves against neither index and used to print the
        raw OSCAL key, ``AC-2_SMT.K``, as though that were an identifier
        anybody writes.
        """
        base, sep, item = control_id.partition("_smt")
        if sep and base in self.titles:
            where = f" (statement {item.lstrip('.')})" if item.strip(". ") else ""
            return f"{self.named(base)}{where}"
        label = self.labels.get(control_id, control_id.upper())
        title = self.titles.get(control_id, "")
        return label if (not title or title in label) else f"{label} {title}"

    def _walk_control(self, control: dict, family: str) -> None:
        if "id" not in control:
            return
        self.family[control["id"]] = family
        self.controls.append(control)
        for child in control.get("controls", []):
            self._walk_control(child, family)


def _render_resource(resource: dict) -> str:
    """A back-matter reference as one line: citation, then the link."""
    bits: list[str] = []
    citation = (resource.get("citation") or {}).get("text", "")
    bits.append(str(citation).strip() or str(resource.get("title", "")).strip())
    for link in resource.get("rlinks", []):
        href = str(link.get("href", "")).strip()
        if href.startswith("http"):
            bits.append(href)
            break
    return " ".join(b for b in bits if b)


def _label(node: dict, cls: str | None = None) -> str:
    """The ``label`` prop of an OSCAL node, optionally of a given class.

    OSCAL stores a control's human identifier as a prop rather than a field,
    and a control carries several: ``AC-1``, the zero-padded ``AC-01``, and the
    SP 800-53A variant. The unclassed one is how the world writes it.
    """
    for prop in node.get("props", []):
        if prop.get("name") == "label" and prop.get("class") == cls:
            return str(prop.get("value", ""))
    return ""


def _param_text(param: dict) -> str:
    """One parameter rendered the way SP 800-53 prints it on the page.

    ``[Assignment: organization-defined frequency]`` and
    ``[Selection (one-or-more): organization-level; system-level]`` are not an
    invention here — they are NIST's own rendering of an unfilled parameter,
    which makes them the wild form and therefore the one worth learning. 148 of
    the 1,600 labels already begin with "organization", so the prefix is added
    only when it is not already there rather than producing
    "organization-defined organization-defined personnel or roles".
    """
    if "select" in param:
        select = param["select"]
        how = str(select.get("how-many", "")).strip()
        choices = "; ".join(str(c) for c in select.get("choice", []))
        head = f"Selection ({how})" if how else "Selection"
        return f"[{head}: {choices}]"
    if values := param.get("values"):
        return "[" + "; ".join(str(v) for v in values) + "]"
    # SP 800-171 and 800-172 carry a ``usage`` field that already reads as the
    # assignment ("organization-defined account and/or account type") where
    # ``label`` is only the noun ("account and/or account types"). Preferring it
    # keeps those two catalogues reading like their published text; SP 800-53
    # has no ``usage`` and falls through to the label.
    label = str(param.get("usage", "")).strip() or str(param.get("label", "")).strip()
    if not label:
        return f"[Assignment: {param.get('id', 'organization-defined value')}]"
    if label.lower().startswith("organization"):
        return f"[Assignment: {label}]"
    return f"[Assignment: organization-defined {label}]"


def _resolve_inserts(prose: str, catalog: _Catalog) -> str:
    """Replace every ``{{ insert: param, X }}`` moustache with its rendering.

    Left alone, the control text reads "Review and analyze system audit records
    {{ insert: param, au-06_odp.01 }} for indications of …", which is a
    template, not a sentence, and would teach the model a token sequence that
    exists nowhere outside OSCAL's own JSON. All 1,600 references in SP 800-53
    Rev 5 resolve against the catalogue's own parameter index, measured; an
    unresolvable one keeps its moustache rather than vanishing, so a future
    upstream change is visible in the text instead of silent.
    """
    def replace(match: re.Match[str]) -> str:
        param = catalog.params.get(match.group(1))
        return _param_text(param) if param else match.group(0)

    return _INSERT.sub(replace, prose)


def _render_parts(parts: list[dict], catalog: _Catalog, names: tuple[str, ...],
                  depth: int = 0,
                  reject: frozenset[str] = frozenset()) -> list[str]:
    """Render the named part kinds as indented, labelled lines.

    Indentation carries the statement's structure — ``a.`` above ``1.`` above
    ``(a)`` — and :func:`~training.corpus.source.normalise` preserves it. That
    is the contract this whole corpus is built on and the reason nothing here
    tidies horizontal whitespace.

    ``reject`` drops a part **and its whole subtree** by ``class``. It exists
    because SP 800-172 files its adversary-effects model under
    ``name="statement"`` with ``class="adversary_effect"``, so selecting on the
    name alone welded "(includes preempt) Ensure that the threat event does not
    have an impact" onto the end of every requirement as though it were part of
    the requirement. The subtree has to go with it: the children underneath are
    plain ``item`` parts and would otherwise survive their own parent.
    """
    lines: list[str] = []
    for part in parts or []:
        if str(part.get("class", "")) in reject:
            continue
        if part.get("name") not in names:
            continue
        pad = "  " * depth
        label = _label(part) or _label(part, "sp800-53a")
        prose = _resolve_inserts(str(part.get("prose", "")), catalog).strip()
        if label and prose:
            lines.append(f"{pad}{label} {prose}")
        elif label:
            lines.append(f"{pad}{label}")
        elif prose:
            lines.append(f"{pad}{prose}")
        lines += _render_parts(part.get("parts", []), catalog, names,
                               depth + 1, reject)
    return lines


def _named_parts(parts: list[dict], name: str) -> Iterator[dict]:
    for part in parts or []:
        if part.get("name") == name:
            yield part
        yield from _named_parts(part.get("parts", []), name)


def _section(title: str, body: list[str]) -> list[str]:
    """A titled section, or nothing at all when there is nothing to put in it.

    The blank filter is not belt-and-braces: several call sites pass a
    single-element list built from a field that is sometimes the empty string,
    and a list holding one empty string is still a truthy list. Without this a
    control with no guidance emits a bare ``## Discussion`` header with the next
    header directly under it, which teaches that a heading can be followed by
    nothing.
    """
    kept = [line for line in body if line.strip()]
    return ["", f"## {title}", "", *kept] if kept else []


def _render_control(catalog: _Catalog, control: dict) -> tuple[str, int]:
    """One control as a document. Returns (text, held-back characters).

    The identifier appears three times over: leading the document, on its own
    labelled line, and as the OSCAL id. That is the same three-position
    exposure :mod:`.attack` and :mod:`.capec` argue for, and it is the shape
    that moved an identifier sample from -45% to +13% against gpt2. What it
    must not become is the *same string* three times: the five catalogues
    disagree about what a label is, and in the CSF and the SSDF the id, the
    label and the title are all ``PO.1.2``. Naively concatenated that produced
    a heading reading "PO.1.2 PO.1.2" and a ``Name:`` line that named nothing.
    """
    control_id = str(control["id"])
    label = _label(control) or control_id.upper()
    title = str(control.get("title", ""))
    # SP 800-171 labels its controls "Separation of Duties (03.01.04)" and
    # titles them "Separation of Duties", so the title is inside the label.
    # CSF and SSDF make all three identical. Either way, say it once.
    heading = label if (not title or title in label) else f"{label} {title}"
    lines = [
        f"{catalog.pretty} {heading}".strip(),
        "",
        f"Publication: {catalog.pretty} (OSCAL version {catalog.version})",
        f"Control: {label}",
    ]
    if title and title != label:
        lines.append(f"Name: {title}")
    lines.append(f"OSCAL id: {control_id}")
    if family := catalog.family.get(control_id):
        lines.append(f"Family: {family}")
    # The SP 800-53A label is zero-padded ("AC-01" against "AC-1") and is the
    # form assessment tooling writes. Emitted only when it differs, so the
    # ordinary control does not carry the same string twice.
    assessment_label = _label(control, "sp800-53a")
    if assessment_label and assessment_label != label:
        lines.append(f"Assessment label: {assessment_label}")

    # 182 of SP 800-53 Rev 5's controls are withdrawn, and so are 91 CSF
    # subcategories, 33 SP 800-171 requirements and 12 SP 800-172 ones. They
    # still carry their old statement text, so rendering them unmarked would
    # teach retired CSF 1.1 subcategory ids as current CSF 2.0 content — the
    # model would confidently cite PR.AC-01, which no longer exists.
    withdrawn = _status(control) == "withdrawn"
    if withdrawn:
        lines.append("Status: withdrawn")

    parts = control.get("parts", [])
    lines += _section("Control", _render_parts(
        parts, catalog, ("statement", "item"), reject=_ADVERSARY_EFFECT))
    lines += _section("Discussion", _render_parts(parts, catalog, ("guidance",)))
    lines += _section("Implementation examples",
                      _render_parts(parts, catalog, ("example",)))
    lines += _section("Adversary effects", _render_effects(parts, catalog))

    lines += _section("Organization-defined parameters", [
        f"- {_label(param, 'sp800-53a') or param.get('id', '')}: "
        f"{_param_text(param)}"
        + (f" — {guide}" if (guide := _guideline(param)) else "")
        for param in control.get("params", [])
    ])

    lines += _section("Assessment methods", _render_methods(parts))

    lines += _section("Related controls", [
        f"- {catalog.named(ref)}"
        for ref in _links(control, "related")
        if catalog.titles.get(ref)
    ])

    # The SSDF and the CSF express their whole value as cross-framework
    # mappings — an SSDF task points at the BSA framework, at OWASP, at SP
    # 800-53 control ids — and OSCAL hangs them off the link's ``text`` rather
    # than off a part. Without this section those two catalogues render as a
    # sentence and nothing else.
    lines += _section("Framework mappings", [
        f"- {catalog.resources[uuid]}: {text}"
        for uuid, text in _links_with_text(control, "external_reference")
        if catalog.resources.get(uuid) and text
    ])

    lines += _section("Requires", [
        f"- {catalog.named(ref)}"
        for ref in _links(control, "required")
        if catalog.titles.get(ref)
    ])

    # A withdrawn requirement earns its place by saying what replaced it — the
    # same argument :mod:`.capec` makes for keeping a deprecated pattern that
    # forwards somewhere. A withdrawn control that forwards nowhere is a
    # tombstone and is held back by the caller.
    successors = _links(control, "incorporated_into", "moved_to", "addressed_by")
    lines += _section("Withdrawn",
                      [f"- Superseded by {catalog.named(ref)}"
                       for ref in successors])

    lines += _section("References", [
        f"- {catalog.resources[uuid]}"
        for uuid in _links(control, "reference")
        if catalog.resources.get(uuid)
    ])

    held = sum(
        len(str(part.get("prose", "")))
        for part in _named_parts(parts, "assessment-objective")
    )
    return "\n".join(lines), held


#: SP 800-172 hangs its adversary-effects model off a part named ``statement``.
#: Named here so the rejection in the Control section and the selection in the
#: Adversary effects section cannot drift apart.
_ADVERSARY_EFFECT = frozenset({"adversary_effect"})

#: The class prefixes SP 800-172 uses inside an adversary-effect block. ``I-``
#: is the impact on the adversary, ``ER-`` the expected result.
_EFFECT_ROLE = (("I-", "Impact"), ("ER-", "Expected result"))


def _status(control: dict) -> str:
    """The ``status`` prop of a control, lowercased, or the empty string."""
    for prop in control.get("props", []):
        if prop.get("name") == "status":
            return str(prop.get("value", "")).strip().lower()
    return ""


def _render_effects(parts: list[dict], catalog: _Catalog) -> list[str]:
    """SP 800-172's Preclude / Impede / Limit / Expose / Redirect model.

    This is the one piece of NIST prose in this source that talks about the
    adversary rather than about the organisation — what an enhanced
    requirement *does to an attacker*, and what result you should expect if it
    works. It is filed under a part name that collides with the requirement
    statement (see :func:`_render_parts`), which is the only reason it needs a
    renderer of its own rather than a heading.
    """
    lines: list[str] = []
    for block in parts or []:
        if str(block.get("class", "")) not in _ADVERSARY_EFFECT:
            continue
        for effect in block.get("parts", []):
            name = str(effect.get("class", "")).split("-")[0]
            body = " ".join(
                line.strip()
                for line in str(effect.get("prose", "")).split("\n")
                if line.strip()
            )
            lines.append(f"- {name}: {body}" if name else f"- {body}")
            for detail in effect.get("parts", []):
                cls = str(detail.get("class", ""))
                role = next((label for prefix, label in _EFFECT_ROLE
                             if cls.startswith(prefix)), "")
                prose = str(detail.get("prose", "")).strip()
                lines.append(f"  - {role}: {prose}" if role else f"  - {prose}")
    return lines


def _guideline(param: dict) -> str:
    for guideline in param.get("guidelines", []):
        prose = str(guideline.get("prose", "")).strip()
        if prose:
            return prose
    return ""


def _links(control: dict, *rels: str) -> list[str]:
    """Targets of a control's links of one or more relations."""
    return [target for target, _ in _links_with_text(control, *rels)]


def _links_with_text(control: dict, *rels: str) -> list[tuple[str, str]]:
    """``(target, text)`` for the named relations. The text is a mapping.

    An SSDF task's link to the BSA framework carries no prose at all; what it
    carries is ``"text": "SM1.1, SM1.4, SM2.2, ..."`` — the identifiers in the
    other framework that this task corresponds to. Dropping the text would
    throw away the entire mapping and keep only a bibliography entry.

    Two normalisations, both of which cost a whole section of every withdrawn
    control when they are missing. The five catalogues **disagree about
    punctuation in relation names** — SP 800-53 writes ``incorporated-into``
    and ``moved-to``, everything else writes ``incorporated_into`` and
    ``moved_to`` — so underscores and hyphens are folded together. And they
    disagree about whether an internal href is a fragment: SP 800-53's are
    ``#ac-6``, the CSF's are the bare ``GV.OC``. Matching only ``#`` left every
    CSF withdrawal notice empty, which then failed the body check and dropped
    91 real documents on the floor without a word.
    """
    wanted = {rel.replace("_", "-") for rel in rels}
    out: list[tuple[str, str]] = []
    for link in control.get("links", []):
        if str(link.get("rel", "")).replace("_", "-") not in wanted:
            continue
        href = str(link.get("href", ""))
        target = href[1:] if href.startswith("#") else href
        if target:
            out.append((target, str(link.get("text", "")).strip()))
    return out


def _render_methods(parts: list[dict]) -> list[str]:
    """EXAMINE / INTERVIEW / TEST, each with the artefacts it applies to.

    This is the NIST analogue of a STIG check procedure — "how would an
    assessor know" — which is why it survives when the assessment *objectives*
    beside it do not. The objects are joined onto one line because they are a
    list of nouns, and a bullet each would triple the line count for no gain.
    """
    lines: list[str] = []
    for part in _named_parts(parts, "assessment-method"):
        method = ""
        for prop in part.get("props", []):
            if prop.get("name") == "method":
                method = str(prop.get("value", ""))
        objects: list[str] = []
        for child in _named_parts(part.get("parts", []), "assessment-objects"):
            objects += [
                line.strip()
                for line in str(child.get("prose", "")).split("\n")
                if line.strip()
            ]
        if method and objects:
            lines.append(f"- {method}: {'; '.join(objects)}")
        elif method:
            lines.append(f"- {method}")
    return lines


# ---------------------------------------------------------------------------
# STIG rendering
# ---------------------------------------------------------------------------

class _Benchmark:
    """One parsed XCCDF benchmark: its metadata and its rules."""

    _ROOT = "Benchmark"

    def __init__(self, path: Path) -> None:
        try:
            self.root = ET.parse(path).getroot()
        except (ET.ParseError, OSError) as exc:
            raise SourceError(
                f"govguidance: cannot read benchmark {path}: {exc}") from exc
        if _local(self.root.tag) != self._ROOT:
            raise SourceError(
                f"govguidance: {path} has root <{_local(self.root.tag)}>, "
                f"expected <{self._ROOT}>"
            )
        self.ns = _namespace(self.root)
        self.title = (self.root.findtext(f"{self.ns}title") or "").strip()
        self.version = (self.root.findtext(f"{self.ns}version") or "").strip()
        self.release = ""
        for plain in self.root.findall(f"{self.ns}plain-text"):
            if plain.get("id") == "release-info" and plain.text:
                self.release = plain.text.strip()
        status = self.root.find(f"{self.ns}status")
        self.status_date = status.get("date", "") if status is not None else ""
        self.groups = self.root.findall(f"{self.ns}Group")


def _render_rule(bench: _Benchmark, group: ET.Element, rule: ET.Element,
                 cci: _CciIndex, titles: dict[str, str]) -> str:
    """One STIG rule: the identifiers, the discussion, the check, the fix."""
    ns = bench.ns
    group_id = (group.get("id") or "").strip()
    rule_id = (rule.get("id") or "").strip()
    stig_id = (rule.findtext(f"{ns}version") or "").strip()
    title = (rule.findtext(f"{ns}title") or "").strip()
    srg = (group.findtext(f"{ns}title") or "").strip()

    lines = [
        f"{group_id} {title}".strip(),
        "",
        f"STIG: {bench.title}",
    ]
    if bench.version or bench.release:
        lines.append(f"Version: {bench.version}    {bench.release}".rstrip())
    lines += [
        f"Group ID: {group_id}",
        f"Rule ID: {rule_id}",
    ]
    if stig_id:
        lines.append(f"STIG ID: {stig_id}")
    if srg:
        lines.append(f"SRG: {srg}")
    if severity := (rule.get("severity") or "").strip():
        lines.append(f"Severity: {severity}")

    legacy: list[str] = []
    for ident in rule.findall(f"{ns}ident"):
        system = (ident.get("system") or "").lower()
        value = (ident.text or "").strip()
        if not value:
            continue
        if "cci" in system:
            lines.append(f"CCI: {cci.line(value, titles)}")
        else:
            legacy.append(value)
    if legacy:
        lines.append(f"Legacy IDs: {', '.join(legacy)}")

    description = rule.findtext(f"{ns}description") or ""
    for field, heading in _STIG_FIELDS:
        lines += _section(heading, [_field(description, field)])

    lines += _section("Check", [
        (check.findtext(f"{ns}check-content") or "").strip()
        for check in rule.findall(f"{ns}check")
    ])
    lines += _section("Fix", [
        (fixtext.text or "").strip()
        for fixtext in rule.findall(f"{ns}fixtext")
    ])
    return "\n".join(lines)


def _rule_body(bench: _Benchmark, rule: ET.Element) -> str:
    """The identifier-free body of a rule, for cross-product dedup.

    The build's own fingerprint dedup cannot catch a rule that five vendors
    publish verbatim, because this adapter puts the rule's identifiers in the
    text and those differ. Fingerprinting the *body* — title, discussion,
    check, fix — is what actually answers "is this the same requirement".
    """
    ns = bench.ns
    description = rule.findtext(f"{ns}description") or ""
    pieces = [
        (rule.findtext(f"{ns}title") or ""),
        _field(description, "VulnDiscussion"),
        *((check.findtext(f"{ns}check-content") or "")
          for check in rule.findall(f"{ns}check")),
        *((fixtext.text or "") for fixtext in rule.findall(f"{ns}fixtext")),
    ]
    return fingerprint("\n".join(pieces))


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------

def _documents(path: Path) -> Iterator[Document]:
    """Yield the NIST controls, then the STIG rules, in a stable order."""
    root = _resolve(path)
    titles, held_objectives = yield from _nist_documents(root)
    yield from _stig_documents(root, titles)
    if held_objectives:
        print(f"   govguidance: held back {held_objectives:,} chars of SP "
              "800-53A assessment objectives — the control statement rewritten "
              "in the passive voice (median 0.70 similarity to the statement "
              "it assesses, 64% of controls above 0.6)")


def _nist_documents(
    root: Path,
) -> Generator[Document, None, tuple[dict[str, str], int]]:
    """One document per control, across the five catalogues.

    Declared as a ``Generator`` with a return type rather than an ``Iterator``
    because it genuinely has one: ``yield from`` in :func:`_documents` collects
    ``(titles, held)``. ``titles`` is the SP 800-53 Rev 5 control-name map that
    the STIG half needs to put a control's *name* beside the CCI that points at
    it, and ``held`` is the assessment-objective character count for the log.
    """
    titles: dict[str, str] = {}
    held = 0
    headerless = 0
    tombstones = 0
    withdrawn = 0
    nist_dir = root / _NIST_DIR
    for _, _, label, pretty in _CATALOGS:
        path = nist_dir / f"{label}.json"
        if not path.is_file() or path.is_symlink():
            continue
        catalog = _Catalog(path, label, pretty)
        if label == "SP800-53r5":
            titles = dict(catalog.titles)
        for control in catalog.controls:
            text, objective_chars = _render_control(catalog, control)
            held += objective_chars
            text = normalise(text)
            # A header with no section under it is a control that carries no
            # statement, no guidance and no forwarding pointer. The length
            # floor alone does not catch them, because the header is itself
            # 200-odd characters, so the body is checked for as well.
            if len(text) < _MIN_CHARS or "\n## " not in text:
                headerless += 1
                continue
            # A withdrawn control that names its successor is a real fact about
            # a real identifier that still appears in old assessment reports,
            # and :mod:`.capec` keeps exactly that. One that forwards nowhere
            # is a tombstone.
            if _status(control) == "withdrawn" and "\n## Withdrawn" not in text:
                tombstones += 1
                continue
            withdrawn += _status(control) == "withdrawn"
            yield Document(
                text=text,
                source="govguidance",
                register=Register.PROSE,
                side=Side.BLUE,
                ident=f"{label}/{control['id']}",
            )
    if headerless or tombstones:
        print(f"   govguidance: held back {headerless} NIST control(s) with no "
              f"body and {tombstones} withdrawn one(s) naming no successor")
    if withdrawn:
        print(f"   govguidance: {withdrawn} withdrawn NIST control(s) kept, "
              "each marked 'Status: withdrawn' and pointing at what replaced it")
    return titles, held


def _stig_documents(root: Path, titles: dict[str, str]) -> Iterator[Document]:
    """One document per STIG rule, deduplicated across products."""
    stig_dir = root / _STIG_DIR
    if not stig_dir.is_dir():
        return
    cci = _CciIndex(root / _CCI_FILE)

    seen: set[str] = set()
    duplicates = 0
    benchmarks = 0
    rules = 0

    for family, benchmark_path in _benchmark_files(stig_dir):
        try:
            bench = _Benchmark(benchmark_path)
        except SourceError as exc:
            print(f"   govguidance: {exc}")
            continue
        benchmarks += 1
        for group in bench.groups:
            rule = group.find(f"{bench.ns}Rule")
            if rule is None:
                continue
            body = _rule_body(bench, rule)
            if body in seen:
                duplicates += 1
                continue
            seen.add(body)
            text = normalise(_render_rule(bench, group, rule, cci, titles))
            if len(text) < _MIN_CHARS:
                continue
            rules += 1
            yield Document(
                text=text,
                source="govguidance",
                register=Register.PROSE,
                side=Side.BLUE,
                ident=f"{family}/{(group.get('id') or '').strip()}",
            )

    print(f"   govguidance: {rules:,} STIG rules from {benchmarks} benchmarks; "
          f"held back {duplicates:,} rule(s) whose requirement, check and fix "
          "are word-for-word a rule already emitted by another product")
    print(f"   govguidance: dropped the per-rule DPMS <reference> block and the "
          f"always-'false' {_STIG_DROPPED_FIELD} flag from every rule — one "
          "identical line per rule is memorisation, not volume")


def _benchmark_files(stig_dir: Path) -> list[tuple[str, Path]]:
    """Every cached XCCDF, as ``(family, path)``, in a stable order.

    ``os.walk(followlinks=False)`` rather than ``rglob``: a source in this
    package once followed a symlink into the corpus cache and pulled 180 MB of
    corpus back in as training data. ``followlinks=False`` covers the descent
    and not the leaf, so the file itself is checked too — ``Path.is_file()``
    follows a link, and a benchmark-shaped name pointing at something else
    would otherwise be opened and parsed on every build.
    """
    out: list[tuple[str, Path]] = []
    for dirpath, dirnames, filenames in os.walk(stig_dir, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames
                             if not (here / d).is_symlink())
        family = here.name if here != stig_dir else ""
        for name in sorted(filenames):
            if not name.lower().endswith(".xml"):
                continue
            candidate = here / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            out.append((family or candidate.stem, candidate))
    return sorted(out, key=lambda pair: (pair[0], pair[1].name))


# ---------------------------------------------------------------------------
# licence
# ---------------------------------------------------------------------------

_LICENSE = (
    "Public domain (US Government works, 17 USC 105), from two upstreams, each "
    "read from its own files rather than from a badge. "
    "(1) NIST OSCAL content: LICENSE.md in usnistgov/oscal-content states "
    "\"This project is in the worldwide public domain. As a work of the United "
    "States government, this project is in the public domain within the United "
    "States. Additionally, we waive copyright and related rights in the work "
    "worldwide through the CC0 1.0 Universal public domain dedication.\" "
    "GitHub's licence detection reports NOASSERTION for that repository, which "
    "is why the file itself is fetched and cached (LICENSE.oscal-content.md). "
    "(2) DISA STIGs: no LICENSE file exists, so three things were checked "
    "instead. The XCCDF carries <notice id=\"terms-of-use\"> and it is empty — "
    "DISA attaches no terms to the data. Each package's Overview document, "
    "section 'STIG Distribution', describes unrestricted public distribution "
    "via public.cyber.mil and asserts no copyright; what it does assert is "
    "\"DISA accepts no liability for the consequences of applying specific "
    "configuration settings made on the basis of the SRGs/STIGs.\" And the "
    "content is marked UNCLASSIFIED and \"Developed by DISA for the DOD\", a "
    "work prepared by US Government employees in the course of official "
    "duties. CAVEATS, stated rather than glossed: 17 USC 105 removes copyright "
    "within the United States and is not a worldwide waiver (NIST adds CC0; "
    "DISA has not); and the STIG packages contain a DoD/DISA logo JPEG and "
    "several PDFs whose figures are not cleared here, so ONLY the XCCDF XML is "
    "ever extracted and the archive is deleted. Sources: "
    "https://github.com/usnistgov/oscal-content/blob/main/LICENSE.md and "
    "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"
)


SPEC = SourceSpec(
    name="govguidance",
    license=_LICENSE,
    url=_OSCAL_HOME + " and " + _STIG_INDEX,
    register=Register.PROSE,
    side=Side.BLUE,
    fetch=_fetch,
    documents=_documents,
    #: The five NIST catalogues alone carry ~1,720 controls, and the curated
    #: STIG selection ~17,000 rules after cross-product dedup. The floor sits
    #: far below that on purpose: it is not a target, it is the line under
    #: which something has broken. Anything at or below it means the DISA
    #: index stopped resolving and the source has quietly become NIST-only,
    #: which is exactly the failure the floor exists to make loud.
    expect_min_docs=6000,
    #: This source is ~70 HTTPS downloads on a cold cache — the OSCAL tarball,
    #: the CCI list, and one archive per STIG family. Warm, it is a local
    #: parse and finishes in seconds. The build-wide budget is sized for the
    #: median adapter, so this one states its own rather than dragging the
    #: global number around behind it.
    timeout=3600,
    notes=(
        "Two US Government upstreams joined on the CCI list: NIST OSCAL "
        "catalogues (SP 800-53r5 with its 800-53A assessment procedures, "
        "800-171r3, 800-172r3, the SSDF and CSF 2.0) and a curated 67-family "
        "selection of DISA STIGs. Every STIG rule renders as requirement, "
        "discussion, check procedure and fix procedure, with its CCI resolved "
        "to the SP 800-53 control id AND name whose full text is elsewhere in "
        "this same source. Held back: SP 800-53A assessment objectives (the "
        "control statement in the passive voice), the always-empty STIG "
        "description fields, the per-rule DPMS reference boilerplate, and any "
        "rule whose body another product already published verbatim. Only the "
        "XCCDF XML is taken out of a STIG package; the PDFs and the DISA logo "
        "stay in the archive, which is then deleted."
    ),
)
