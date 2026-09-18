"""Windows security internals — the SYSTEM register, Windows side.

This project ships a Windows adapter with thirty verbs, and enterprise purple
teaming happens on Windows. The corpus did not reflect that. Its only Windows
content was :mod:`~training.corpus.sources.psdocs` — PowerShell cmdlet
reference, labelled SHELL — while Linux got the kernel's whole
``Documentation/`` tree at roughly a third of the build. A model fed that
corpus can reason about ``/proc``, capabilities, cgroups and seccomp, and can
recite ``Get-CimInstance`` syntax. It has no model of *how Windows decides
anything*. Asked why a process could open LSASS, it has nothing to think with.

What was missing is the security model itself, and the striking thing about
listing it is that every item is simultaneously a red technique and the blue
detection for that technique — it sits exactly on this project's seam:

* access tokens, SIDs, privileges and account rights (``SeDebugPrivilege``,
  ``SeImpersonatePrivilege``, ``SeBackupPrivilege``, ``S-1-5-18``),
* security descriptors, DACLs, SACLs, ACEs and SDDL strings,
* LSA, credential storage and the authentication packages — NTLM, Kerberos,
  SSPI, service principal names, and why unconstrained delegation matters,
* the registry as persistence: hives, Run keys, service keys, WMI permanent
  event subscriptions (``__EventFilter`` / ``__FilterToConsumerBinding``),
* the Event Log — channels, providers, XPath selectors, and the audit
  subcategories that decide whether 4624/4625/4688/4697/7045 are written at
  all,
* Sysmon's schema and real Sysmon rule configuration,
* AMSI, ETW, code integrity and the protections around anti-malware services.

None of that is prose *about* Windows security. It is the platform's own
reference text, and the surface form — ``HKLM\\SYSTEM\\CurrentControlSet\\
Services``, ``(A;OICI;GA;;;BA)``, ``TokenElevationTypeFull`` — is the signal a
BPE actually learns.

**Selection is the whole design of this adapter, and it is two-tier.** These
repositories are enormous and mostly about deployment, licensing, MDM policy
and product portals. Pulled in whole they would bury the corpus in text that
teaches nothing and crowd out the sources this one was added to sit beside. So
each upstream declares two kinds of tree — with one upstream declaring neither,
for a reason given further down:

*Dense* trees are on-topic **by location** and are taken entire. ``desktop-src/
SecAuthZ`` is the access-control model; ``desktop-src/WES`` is the Event Log
API. A page there about ``EvtQuery`` is Windows Event Log reference whether or
not it ever says "attacker", and a keyword test run over it does real damage.
Measured on the cache: a content gate would discard 93% of the characters in
``WES``, 96% of ``Memory``, 85% of ``SysInfo``, 82% of ``ETW`` — and 55% of
``SecAuthZ``, which is the token/SID/ACL model itself, the most on-topic tree
in this source. Those are not irrelevant pages. They are pages written in the
vocabulary of an API rather than the vocabulary of a threat, and location knows
that where a word list cannot.

*Gated* trees are mixed — genuinely valuable pages sitting next to deployment
guides — and each page must earn its place by content. The gate counts hits in
six term families (access control, authentication, auditing and logging,
persistence surfaces, defensive mechanisms, threat language) and keeps a page
that touches three families, or two families with at least eight hits, or any
one family fifteen times. The last clause exists because of ``reg add``: that
page scores seventeen hits and every one of them is a registry term, which is
precisely the surface form wanted, and a families-only rule threw it away.
Measured: ``administration/windows-commands`` 851 pages to 92 — ``icacls``,
``auditpol``, ``secedit``, ``klist``, ``wevtutil``, ``wecutil``, ``wmic``,
``whoami``, ``takeown``, ``reg add``, ``net user``, ``schtasks``,
``manage-bde`` in, ``robocopy``, ``diskraid``, ``winnt32`` out — ``identity/``
from 6.1 MB to 3.4 MB, ``TaskSchd`` to 16% of its characters, which is the COM
property-stub reference falling away and the task-persistence documentation
staying.

Some trees were considered and left out entirely, which is also selection:
``desktop-src/SecCrypto`` and ``SecCNG`` are 3.9 MB of CryptoAPI, CAPICOM and
certificate-enrollment COM reference — cryptography, not the security model
either team reasons about — and ``desktop-src/Rpc`` is 1.3 MB of MIDL and
runtime plumbing. Taking them would have made this source half again as large
and no more Windows-security-literate.

Two hand-made rulings sit on top of the gate, because a keyword test cannot
make either of them:

**One page is named explicitly.** ``desktop-src/Debug/pe-format.md`` is the PE
file format specification, 335 KB of the structure that every loader, packer,
injector, signature and Authenticode check on the platform is about. It scores
two families and four hits, because a format specification talks about
``IMAGE_OPTIONAL_HEADER`` and not about adversaries. It is named in
:data:`_ALWAYS` rather than pretending the filter found it. The same gate also
keeps the nine ``system-error-codes-*`` tables, which was not the intent and is
kept anyway: ``ERROR_ACCESS_DENIED``, ``ERROR_LOGON_FAILURE``,
``ERROR_PRIVILEGE_NOT_HELD`` are what Windows actually prints back at an
operator, and reading command output is half this model's job.

**One page is thrown out by shape rather than topic.** ``identity/ad-ds/deploy/
Schema-Updates.md`` is 1.38 MB — a third of the entire AD DS tree in one file —
and it passes the gate comfortably. It is an LDIF dump: ``dn: CN=…`` /
``changetype: add`` repeated across 43,661 lines of which only 33% are
distinct. That is a database export wearing a documentation extension, and the
same objection that keeps ``perltoc.1`` out of the manpages source applies. So
a large document whose distinct-line ratio falls under a half is refused.
Calibration, from the checkout: the error-code tables are 99% distinct, the
audit-policy reference 70%, a merged Sysmon config 74%, and this file 33%. The
threshold is not near anything real.

**One upstream was refused on licensing.** ``SwiftOnSecurity/sysmon-config`` is
the best-known Sysmon configuration in existence and it carries **no licence at
all** — no ``LICENSE`` file, no statement in its README, nothing the GitHub
licence endpoint recognises. :mod:`training.corpus.source` refuses a blank
licence for a reason, and "everyone uses it" is not provenance. It is left out.
``olafhartong/sysmon-modular`` is MIT and covers the same ground.

**One upstream no longer exists.** ``MicrosoftDocs/windows-itpro-docs`` — which
held ``windows/security/threat-protection/auditing/event-4624.md`` and the rest
of the per-event-id audit reference, the single most valuable Windows text for
a blue-team model — is no longer public: the clone fails with *repository not
found*, and what search returns is other people's forks. Training on a stranger's
fork of a repository whose upstream has been withdrawn is exactly the provenance
problem the licence rule exists to prevent, so it is not done here.

Event ids still arrive, from the places that survived. "Appendix L: Events to
Monitor" and the advanced audit policy reference under ``identity/ad-ds``
account for 489 event-id mentions between them; Sentinel's Windows security
event-id reference enumerates 128 ids by collection set; ``auditpol``,
``wevtutil`` and ``wecutil`` document the policy and the channels; Sysmon's own
page gives its whole event table. What that does not reproduce is *depth* on
any single id: ``4624`` appears seven times here and not seventy, because the
page that described it field by field is the page that went away. Sigma,
Elastic and Splunk carry the DETECTION register's event-id density in this
corpus; this source carries the model underneath it. If that repository ever
returns, it belongs here.

**Rendering, and three refusals to clean.** These files are Markdown, and the
``win32`` half is machine-converted MSDN carrying real HTML inside it —
``<span id="…"></span>`` anchors, ``<dl><dt>`` wrappers in table cells and
26,441 ``<br/>`` tags, 131,731 tags in all. Those go, matched by an allow-list
of tag *names* that also requires whitespace before any attribute, so
``<p.zabel@example.com>`` cannot be eaten as a ``<p>`` tag — the bug that
deleted 73 maintainer e-mail addresses from another source in this package.
Bare ``<a>`` appears in zero pages of the cache; the bare tags that do appear
(``<p>`` 1,643, ``<code>`` 219, ``<em>`` 74, ``<b>`` in seven pages, ``<i>`` in
five) are all real markup, checked by reading them.

The backslash unescaping is not cosmetic. MSDN conversion wrote every
identifier with escaped underscores — ``SE\\_DEBUG\\_NAME``,
``AMSI\\_ATTRIBUTE``, ``TOKEN\\_ADJUST\\_PRIVILEGES`` — 41,795 times in the
selection. Left alone, this source would teach the model that Windows security
constants contain backslashes, corrupting the exact vocabulary it was added to
supply. Only ``\\_``, ``\\[`` and ``\\]`` are unescaped, which is 74% of the
66,973 escapes and the safe 74%. It is not perfectly safe: 12 of those
41,795 sit inside a path-shaped token — ``C:\\inetpub\\wwwroot\\_wmcs`` —
where the backslash is a separator and undoing it welds two path
components together. Twelve is the price of the other 41,783, and it is the
right way round. The exclusions below are the cases where the count came out
the other way:

* ``\\<`` and ``\\>`` are **left alone**, all 1,758 of them, because
  ``\\Device\\HarddiskVolume3\\<Folder>`` is a device path where the backslash
  is a path separator and unescaping would silently delete it.
* ``\\|`` is left alone: it is an escaped pipe inside a table, and unescaping
  it would tear the row apart.
* ``\\\\`` is left alone: nearly every one is inside a C string in a fenced
  block, which nothing here touches anyway.

And "Applies to" is not stripped the way it first looks as though it should be.
The banner form (``**Applies to:** Windows Server 2022``) belonged to the
withdrawn ITPro repository. In these three, the phrase occurs 154 times and
every one is content — ``Applies to: properties, methods, parameters`` in the
WMI qualifier reference, ``(Applies to enterprise CAs)`` inside a certificate
table. So the rule here matches only the banner *shape*: bold or blockquote
marked, alone on its line. It fires zero times today and is kept as a guard
that cannot do harm, which is the only kind of unfiring rule worth keeping.

**Fenced code is never touched.** Every rewrite above runs on prose segments
only; a ``:::`` directive, a Markdown link or an HTML-looking token inside a
``cmd``, ``powershell``, ``xml`` or ``C`` block is code, and the block is copied
through byte for byte. Tables are kept with their padding intact, because
:func:`~training.corpus.source.normalise` preserves horizontal whitespace and an
event-id table with its columns collapsed is a different document. Nothing here
runs a frequency filter over lines either: :mod:`training.corpus.boilerplate`
owns that, at corpus scale, and its alpha-ratio test — which had to be fixed
once because counting spaces as letters made packet diagrams look like prose —
is what keeps ``|-------|:------|`` separator rows and padded table cells out of
its sights.

**Licences, checked rather than claimed.** ``fetch`` reads each upstream's
licence file and refuses to proceed if the expected text is not in it, so a
relicensing upstream fails the build instead of quietly falsifying
:data:`SPEC`. The files are copied into the cache beside the text they cover.
Nothing is redistributed: the adapter ships, the corpus does not.

**Two transports, one rule about them.** The eighteen Defender pages go
through :func:`training.corpus.net.download`, which is the project's only
builder of TLS contexts and refuses to build one that does not verify. The four
cloned upstreams do not: ``git`` opens those sockets, not :mod:`urllib`, and
calling ``ssl_context()`` to feel consistent would be theatre. What that module
stands for is enforced where it can actually be broken here instead — ``fetch``
refuses to run at all if ``GIT_SSL_NO_VERIFY`` is set in the environment, and no
``http.sslVerify`` override is ever passed. ``net.USER_AGENT`` goes out as git's
user agent too, so the corpus identifies itself the same way on both.

**Provenance is recorded, not pinned.** :mod:`~training.corpus.sources.kerneldocs`
pins ``v7.2`` because the kernel ships tags. None of these repositories ships a
release tag of any kind; there is nothing to pin to. So the default branch is
cloned and the resolved ``HEAD`` of each cloned upstream is written into the
cache marker, which at least makes two builds comparable after the fact. The
Defender pages have no revision at all — raw content is served per branch — and
the marker records an empty one rather than inventing something.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .. import net
from ..net import USER_AGENT
from ..source import (
    Document, Register, Side, SourceError, SourceSpec, fingerprint, normalise,
)


@dataclass(frozen=True, slots=True)
class _Upstream:
    """One repository, and which parts of it are corpus.

    ``dense`` trees are taken whole; ``gated`` trees are filtered page by page
    by :func:`_relevant`; ``exclude`` wins over both. An empty ``dense`` means
    everything not excluded is dense, which is right for an upstream that is
    already nothing but the wanted material — the Sysmon rule fragments — and
    for one that is fetched a named page at a time and so has no tree to sort.
    """

    name: str
    url: str
    #: Licence file(s) copied into the cache as evidence. The first is the one
    #: :func:`_check_licence` reads.
    licence_files: tuple[str, ...]
    #: Case-folded text that must appear near the top of ``licence_files[0]``.
    licence_proof: str
    #: File extension this upstream contributes. Everything else is pruned at
    #: fetch time: the sparse checkouts together weigh several hundred
    #: megabytes and 41 MB of that is text.
    suffix: str
    dense: tuple[str, ...] = ()
    gated: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    #: Individual paths kept whatever the gate says. See :data:`_ALWAYS`.
    always: tuple[str, ...] = ()
    #: Floor on a rendered document. The default is sized for Markdown pages,
    #: where anything shorter is a stub; a Sysmon rule fragment is a complete
    #: document at 150 characters and needs its own, lower floor.
    min_chars: int = 0
    #: Partial, sparse clone. False for repositories small enough that the
    #: extra machinery buys nothing.
    sparse: bool = True
    #: Individually named pages, fetched over HTTPS instead of cloned. An
    #: upstream with ``pages`` is never cloned at all; see :data:`_UPSTREAMS`
    #: for the one case where that is the right answer.
    pages: tuple[str, ...] = ()
    #: Raw-content prefix the pages hang off, branch included.
    raw: str = ""
    #: Keep files sitting directly at the repository root. False for
    #: sysmon-modular, whose root holds the merged composite configs.
    root_files: bool = True
    #: Floor on files of ``suffix`` reaching the cache. An upstream that
    #: reorganises its tree fails here rather than contributing a fragment.
    min_files: int = 1


#: The one page the content gate cannot recognise and the corpus must not lose.
#: See the module docstring: a file-format specification scores almost nothing
#: on security vocabulary and is the most security-relevant document in its
#: tree.
_ALWAYS = ("desktop-src/Debug/pe-format.md",)


_UPSTREAMS: tuple[_Upstream, ...] = (
    _Upstream(
        name="win32",
        url="https://github.com/MicrosoftDocs/win32.git",
        licence_files=("LICENSE", "LICENSE-CODE"),
        licence_proof="attribution 4.0 international",
        suffix=".md",
        # Dense: the Windows security model as the platform documents it to
        # itself. SecAuthZ is tokens/SIDs/privileges/ACLs/SDDL, SecAuthN is
        # LSA/NTLM/Kerberos/SSPI/credential providers, SecGloss is the
        # definition of every term the other two use, WES/WEC/EventLog/ETW/
        # tracelogging are the logging substrate a detection is written
        # against, and ProcThread/Memory/ToolHelp/psapi/Dlls are the process
        # and image surfaces injection and hijacking live on.
        dense=(
            "desktop-src/AMSI",
            "desktop-src/SecAuthZ",
            "desktop-src/SecAuthN",
            "desktop-src/SecBP",
            "desktop-src/SecGloss",
            "desktop-src/SecMgmt",
            "desktop-src/ETW",
            "desktop-src/EventLog",
            "desktop-src/WES",
            "desktop-src/WEC",
            "desktop-src/Services",
            "desktop-src/ProcThread",
            "desktop-src/Memory",
            "desktop-src/ToolHelp",
            "desktop-src/psapi",
            "desktop-src/Dlls",
            "desktop-src/SysInfo",
            "desktop-src/NetMgmt",
            "desktop-src/tracelogging",
            "desktop-src/trusted-execution",
        ),
        # Gated: real security content diluted by COM plumbing. WmiSdk holds
        # the permanent event subscription classes and several hundred pages of
        # IWbem* interface reference; TaskSchd holds scheduled-task persistence
        # and several hundred property stubs; Debug holds the error-code tables
        # and a symbol-server manual; SecProv holds the BitLocker and TPM WMI
        # classes and their per-method boilerplate.
        gated=(
            "desktop-src/WmiSdk",
            "desktop-src/TaskSchd",
            "desktop-src/Debug",
            "desktop-src/SecProv",
        ),
        always=_ALWAYS,
        # 3,529 pages reach the cache from these trees. A floor at 40% of
        # that catches a renamed tree, not upstream editing.
        min_files=1400,
    ),
    _Upstream(
        name="windowsserverdocs",
        url="https://github.com/MicrosoftDocs/windowsserverdocs.git",
        licence_files=("LICENSE", "LICENSE-CODE"),
        licence_proof="attribution 4.0 international",
        suffix=".md",
        # Dense: WindowsServerDocs/security is Kerberos, Windows
        # authentication, credential protection (Credential Guard, LSA
        # protection, Protected Users), UAC and the service hardening pages.
        # 102 files, no filler.
        dense=("WindowsServerDocs/security",),
        # Gated: identity/ is the Active Directory documentation — the
        # security-best-practices appendices, the advanced audit policy
        # reference, LAPS, AD CS certificate templates, software restriction
        # policies — sitting beside forest deployment and upgrade guides.
        # windows-commands is the cmd.exe reference, which
        # training.corpus.sources.psdocs does not cover at all (it is
        # PowerShell) and which holds icacls, auditpol, secedit, klist,
        # wevtutil, wmic and takeown.
        gated=(
            "WindowsServerDocs/identity",
            "WindowsServerDocs/administration/windows-commands",
        ),
        min_files=900,
    ),
    _Upstream(
        name="sysinternals",
        url="https://github.com/MicrosoftDocs/sysinternals.git",
        licence_files=("LICENSE", "LICENSE-CODE"),
        licence_proof="attribution 4.0 international",
        suffix=".md",
        # Dense in full: 129 pages, ~1 MB, and every tool in it is a security
        # or forensics tool. sysmon.md alone is the complete Sysmon event
        # table and configuration schema — event ids, filter conditions,
        # RuleGroup semantics — which is the single most useful page here.
        # AccessChk, Autoruns, Handle, LogonSessions, PsExec, Sigcheck and
        # Streams document the same artefacts from the operator's side.
        dense=("sysinternals",),
        min_files=80,
    ),
    _Upstream(
        name="sysmon-modular",
        url="https://github.com/olafhartong/sysmon-modular.git",
        licence_files=("license.md",),
        licence_proof="permission is hereby granted, free of charge",
        suffix=".xml",
        # Whole repository, minus the two directories that are not rules and
        # minus every root-level file. The root holds sysmonconfig.xml and its
        # four siblings: merged composites built by concatenating the modular
        # fragments. Keeping both would be ~890 KB of text that is already
        # present line for line in the fragments, and source.py is explicit
        # that duplication in a small corpus is worse than absence because the
        # model memorises it.
        exclude=("attack_matrix", "config_lists"),
        sparse=False,
        root_files=False,
        # 25 fragments sit between 120 and 300 characters — a single
        # ``<RegistryEvent onmatch="include">`` rule with two conditions and
        # its technique annotation — and every one of them is a whole,
        # well-formed configuration document. The Markdown floor would throw
        # them away for being short, which is a judgement about stub pages and
        # does not transfer.
        min_chars=120,
        min_files=300,
    ),
    _Upstream(
        name="defender-docs",
        url="https://github.com/MicrosoftDocs/defender-docs",
        raw="https://raw.githubusercontent.com/MicrosoftDocs/defender-docs/public/",
        licence_files=("LICENSE",),
        # Not CC BY 4.0. Microsoft published this repository under MIT for
        # both prose and code — LICENSE reads "MIT License / Copyright (c)
        # Microsoft Corporation" where its sibling repositories carry the
        # Creative Commons text. Read out of the file rather than assumed from
        # the other three.
        licence_proof="mit license",
        suffix=".md",
        # **Eighteen named pages, and no tree at all.** This is the one
        # upstream where the two-tier design fails outright, and it fails in an
        # instructive way: the content gate cannot filter Defender
        # documentation, because Defender product documentation is *made of*
        # the gate's vocabulary. A page about licensing tiers says "threat",
        # "attack surface reduction" and "malicious" a dozen times and sails
        # through. Measured: sentinel/, defender-endpoint/ and defender-xdr/
        # are 1,329 pages and 16 MB, most of it portal walkthroughs and
        # onboarding, and gating them would roughly double this source with
        # text that is about a product rather than about Windows.
        #
        # What is wanted from here is narrow and specific: the log *schemas*.
        # The ASIM normalisation schemas give the field names and EventType
        # values for process, registry, file, authentication, network,
        # user-management and audit events; the advanced-hunting tables give
        # the Defender column names an analyst actually queries
        # (InitiatingProcessCommandLine, ProcessTokenElevation, RegistryKey);
        # the ASR and exploit-protection references give the mitigation names
        # and rule GUIDs; and windows-security-event-id-reference.md
        # enumerates the Security-channel event ids by collection set, which is
        # the nearest surviving relative of the per-event pages the withdrawn
        # ITPro repository used to hold.
        #
        # Eighteen files do not justify cloning a 2.8 GB repository — the
        # sparse checkout of just those three trees is 927 MB — so these come
        # over HTTPS through training.corpus.net, which is the one place in
        # this project that builds a verifying TLS context.
        pages=(
            "sentinel/windows-security-event-id-reference.md",
            "sentinel/normalization-schema-process-event.md",
            "sentinel/normalization-schema-registry-event.md",
            "sentinel/normalization-schema-file-event.md",
            "sentinel/normalization-schema-authentication.md",
            "sentinel/normalization-schema-network.md",
            "sentinel/normalization-schema-user-management.md",
            "sentinel/normalization-schema-audit.md",
            "defender-xdr/advanced-hunting-schema-tables.md",
            "defender-xdr/advanced-hunting-deviceprocessevents-table.md",
            "defender-xdr/advanced-hunting-devicelogonevents-table.md",
            "defender-xdr/advanced-hunting-deviceregistryevents-table.md",
            "defender-xdr/advanced-hunting-devicefileevents-table.md",
            "defender-xdr/advanced-hunting-deviceimageloadevents-table.md",
            "defender-xdr/advanced-hunting-devicenetworkevents-table.md",
            "defender-xdr/advanced-hunting-deviceevents-table.md",
            "defender-endpoint/attack-surface-reduction-rules-reference.md",
            "defender-endpoint/exploit-protection-reference.md",
        ),
        # Four of the eighteen may go missing before this is a problem worth
        # failing the build over: a docs repository renames individual pages
        # routinely and the missing ones are printed either way. Losing five is
        # a reorganisation, and then the named list needs revisiting rather
        # than quietly shrinking.
        min_files=14,
    ),
)


#: Written last, after every upstream has cloned, verified its licence and
#: cleared its file floor. Its presence — not the presence of the directories —
#: is what lets ``fetch`` skip the network, so an interrupted run re-clones
#: instead of yielding a partial corpus.
_MARKER = ".windocs-complete.json"

#: Bumped whenever a change alters *which files land in the cache* — the
#: upstream set, a tree list, the pruned suffix. Path and content selection
#: happen in ``documents()`` against the full cached tree, deliberately, so
#: tuning the gate never requires a refetch and the build can report what the
#: gate held back.
_CACHE_VERSION = 1

_GIT_TIMEOUT = 1800

#: Short of this a page is a redirect stub or a bare "## Requirements" table.
#: Higher than the 120 kerneldocs uses because these repositories are full of
#: generated COM property pages whose entire body is two table rows. An
#: upstream may lower it — see ``_Upstream.min_chars``.
_MIN_CHARS = 300

#: A document at least this large is checked for degenerate repetition. Below
#: it the test is meaningless — a short page legitimately repeats its own
#: structure — and running it anyway only risks false positives.
_DEGENERATE_CHARS = 100_000

#: …and is refused if fewer than this fraction of its non-blank lines are
#: distinct. Calibrated in the module docstring; the one file this catches sits
#: at 0.33 and the closest legitimate document at 0.70.
_DEGENERATE_UNIQUE = 0.50


# --------------------------------------------------------------------------
# The content gate
# --------------------------------------------------------------------------

#: Six families of Windows security vocabulary. A page must span families or
#: saturate one of them; a page that merely says "password" twice in a
#: deployment checklist does neither.
#:
#: The terms are deliberately specific. An early draft included bare ``service``
#: and ``registry``, which match essentially every page ever written about
#: Windows and turned the gate into a no-op.
_FAMILIES: dict[str, re.Pattern[str]] = {
    "authz": re.compile(
        r"access token|security descriptor|\bSDDL\b|\bDACL\b|\bSACL\b|\bACEs?\b"
        r"|access control list|\bACLs?\b|security identifier|\bSIDs?\b|S-1-5"
        r"|privileges?|impersonat|integrity level|user account control|\bUAC\b"
        r"|icacls|takeown|securable object|Se[A-Z][A-Za-z]+Privilege",
        re.I,
    ),
    "authn": re.compile(
        r"Kerberos|\bNTLM\b|\bLSASS?\b|credentials?|logon|authenticat|\bSSPI\b"
        r"|service principal name|\bSPNs?\b|ticket-granting|\bTGT\b|delegation"
        r"|Netlogon|passwords?|smart ?card|\bNTDS\b|\bDPAPI\b|pass-the-hash"
        r"|domain controller",
        re.I,
    ),
    "audit": re.compile(
        r"audit polic|auditpol|Security log|event log|Windows Event|subcategor"
        r"|\bETW\b|Event Tracing|Sysmon|event channel|event ID|EventID"
        r"|\b4[67][0-9][0-9]\b|\b70[0-9][0-9]\b",
        re.I,
    ),
    "persist": re.compile(
        r"HKEY_|HKLM|HKCU|registry key|registry value|registry subkey|Run key"
        r"|scheduled task|service control manager|\bWMI\b|__EventFilter"
        r"|__EventConsumer|autostart|startup folder|AppInit|search order",
        re.I,
    ),
    "defend": re.compile(
        r"\bAMSI\b|Defender|anti-?malware|code integrity|\bWDAC\b|AppLocker"
        r"|\bELAM\b|protected process|Credential Guard|LSA protection"
        r"|exploit protection|attack surface reduction|tamper protection"
        r"|driver signing|BitLocker|Secure Boot",
        re.I,
    ),
    "threat": re.compile(
        r"malware|malicious|attacker|exploit|privilege escalation"
        r"|lateral movement|compromis|threat|spoof|hijack|backdoor|ransomware"
        r"|unauthoriz",
        re.I,
    ),
}

#: Thresholds, in the order they are tried. See the module docstring for what
#: each one rescues; the third exists entirely because ``reg add`` is seventeen
#: registry terms and nothing else, and the first two threw it away.
_GATE_FAMILIES = 3
_GATE_PAIR_HITS = 8
_GATE_SOLO_HITS = 15


def _relevant(text: str) -> bool:
    """True if a page from a *gated* tree has earned its place."""
    hits = [len(pattern.findall(text)) for pattern in _FAMILIES.values()]
    families = sum(1 for count in hits if count)
    total = sum(hits)
    if families >= _GATE_FAMILIES:
        return True
    if families >= 2 and total >= _GATE_PAIR_HITS:
        return True
    return total >= _GATE_SOLO_HITS


def _degenerate(text: str) -> bool:
    """True for a large document that is a data dump wearing a ``.md`` suffix."""
    if len(text) < _DEGENERATE_CHARS:
        return False
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    if not lines:
        return True
    return len(set(lines)) / len(lines) < _DEGENERATE_UNIQUE


# --------------------------------------------------------------------------
# Markdown rendering
# --------------------------------------------------------------------------

#: The leading ``---`` block. Non-greedy, so it ends at its own closing fence
#: and not at a horizontal rule further down the page.
_FRONTMATTER = re.compile(r"\A---[ \t]*\n(?P<block>.*?)\n---[ \t]*\n", re.DOTALL)

#: ``title:`` inside that block, quotes optional. The only key read: everything
#: else in these headers is publishing machinery (``ms.topic``, ``ms.date``,
#: ``ms.assetid``, ``ms.author``, ``ms:mtpsurl``) repeated on every page in the
#: repository, and ``description`` is almost always the page's own first
#: sentence with the links taken out.
_FM_TITLE = re.compile(r"^title\s*:\s*(?P<title>.+?)\s*$", re.MULTILINE)

#: An opening code fence: three or more backticks or tildes, optional info
#: string. The closing fence must be at least as long and of the same character.
_FENCE = re.compile(r"\A(?P<marker>`{3,}|~{3,})(?P<info>[^`]*)$")

# HTML comments are cut by a scanner rather than by ``<!--.*?-->``, and the
# reason is the same disease that stopped this module the first time, in its
# milder polynomial form. ``re.sub`` restarts the pattern at every ``<!--`` in
# the text, and an opener that is never closed sends the lazy ``.*?`` all the
# way to the end of the document before it gives up; m unclosed openers
# therefore cost m x n. Measured: ``"<!--" * n`` takes 4x longer for every
# doubling of n — 2.6 s at n=16,000, and a page of commented-out markup is not
# an exotic thing for a documentation repository to ship. Nothing in today's
# cache is shaped like that, which is precisely why removing it is cheap now.
def _strip_comments(text: str) -> str:
    """Delete ``<!-- ... -->`` spans left to right in a single pass.

    Semantically identical to ``re.sub(r"<!--.*?-->", "", text)`` under
    ``DOTALL`` — leftmost match, shortest body, non-overlapping, and an opener
    with no closer left in the text along with everything after it — and
    verified equal to it over all 5,187 cached pages.

    It cannot be quadratic the way the regex is, because ``str.find`` only ever
    searches forward from a cursor that advances and never returns to a
    position it has passed. Once one opener has no closer, no later opener can
    have one either: a ``-->`` after the later opener would also be after the
    earlier one. So the scan stops there rather than re-deriving that fact for
    every remaining ``<!--``, which is exactly the work the regex repeats.
    """
    if "<!--" not in text:
        return text
    out: list[str] = []
    cursor = 0
    while True:
        start = text.find("<!--", cursor)
        if start < 0:
            break
        end = text.find("-->", start + 4)
        if end < 0:
            break
        out.append(text[cursor:start])
        cursor = end + 3
    out.append(text[cursor:])
    return "".join(out)


#: Learn's Markdown extensions, each of which is a rendering instruction rather
#: than text: ``:::image``/``:::row``/``:::moniker``/``:::zone`` triple-colon
#: blocks, transcluded files whose content is not in this repository, and the
#: ``[!div]``/``[!VIDEO]`` inline directives.
#:
#: The optional list marker is not decoration. Three pages write their
#: transclusions as numbered steps (``1.  [!INCLUDE [Initialize HGS](…)]``),
#: and because the link collapser runs first the directive arrives here as
#: ``1.  [!INCLUDE Initialize HGS]`` — a line that a start-anchored rule walks
#: straight past, leaving the marker in the prose.
_DIRECTIVE_LINE = re.compile(
    r"\A[ \t]*(?:(?:[-*+]|\d+\.)[ \t]+)?"
    r"(?::::|\[!INCLUDE\b|>?[ \t]*\[!(?:div|VIDEO|code)\b)"
)

#: The "Applies to" *banner*, which does not occur in these three repositories
#: and is kept as a guard that cannot misfire: it requires the line to be
#: nothing but a bold or blockquoted banner, so the 155 occurrences of the
#: phrase as content ("Applies to: properties, methods, parameters") are
#: untouched. See the module docstring.
_APPLIES_TO = re.compile(r"\A[ \t]*(?:>[ \t]*)?\*\*Applies to\b.*$", re.IGNORECASE)

#: ``> [!NOTE]`` and friends. The marker becomes a word so the note reads as
#: prose; the body of the note, which is content, is left alone.
_ALERT = re.compile(r"\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]", re.IGNORECASE)

#: A link target: parentheses may be backslash-escaped inside it, which MSDN
#: conversion does constantly (``hh832958\(v=vs.85\)``). Without the escape
#: alternative the match stops early and leaves a stray ``)`` in the text.
#:
#: **Both alternations below exclude the backslash from their character class,
#: and that is not tidiness.** Written as ``(?:\\.|[^\[\]])*`` the two branches
#: can both consume a backslash, so every backslash doubles the number of ways
#: the star can match the same text. On a Windows page — which is to say on a
#: page full of ``C:\Windows\System32`` — a link pattern that then fails to
#: find its closing ``)`` backtracks through all of them. The first draft of
#: this module did exactly that; it was not slow, it was exponential.
#:
#: That draft cost an overnight training run: it was left to build, spun at
#: 99.7% of a core for seven and a half hours, and never finished. The page it
#: died on is ``sysinternals/downloads/newsid.md`` and the mechanism is worth
#: writing down, because it is so ordinary. Line 175 is
#: ``**newsid /a \\[newname\\]**`` — a literal bracket, escaped, exactly as a
#: manual page should write it. The pattern starts a link there, walks the
#: remaining 6,139 characters looking for a ``](`` that the page does not
#: contain, and crosses 27 backslashes on the way: ``SECURITY\\SAM\\Domains``,
#: ``HKEY\_LOCAL\_MACHINE``, the ordinary furniture of a Windows document.
#: Each one is a branch point, so failing takes 2**27 paths. Measured on
#: synthetic input the old pattern costs 3x for every two backslashes added —
#: 0.15 s at 24, 13 s at 32 — and ``newsid.md`` has 27 with four more pages
#: behind it shaped the same way. Disjoint branches make the match linear
#: again: the same input is 20 microseconds and does not grow.
#: The same disjointness argument governs the third branch of :data:`_TARGET`.
#: One level of *unescaped* nested parentheses is allowed because MSDN-era
#: filenames carry them — ``(media/…/Dn783423.71a57ae1…(MSDN.10).jpg "title")``
#: — and a target pattern that stops at the first ``(`` leaves the whole image
#: link sitting in the text. The three branches still begin with disjoint
#: characters (``\``, anything-but, ``(``), so the star cannot match the same
#: span two ways and the linear behaviour is preserved.
_LINK_TEXT = r"(?:\\.|[^\[\]\\])*"
_TARGET = r"\((?:\\.|[^()\\]|\([^()]*\))*\)"

#: Images go entirely — alt text on these pages is a filename or a caption for
#: a screenshot nothing in the corpus can see.
_IMAGE = re.compile(r"!\[" + _LINK_TEXT + r"\]" + _TARGET)

#: ``[text](target)`` collapses to ``text``. The targets are doc-site routes —
#: ``/windows/win32/SecGloss/s-gly`` appears thousands of times and denotes a
#: glossary anchor, not a thing the model will ever need to produce.
#:
#: **The lookbehind is the second half of the backtracking fix.** Disjoint
#: branches made a single match attempt linear; they did not stop ``re.sub``
#: from *starting* an attempt at every ``[`` in the file, and ``\\.`` lets the
#: link text walk straight over an escaped bracket. On text made of ``\\[`` —
#: which is how these pages write a literal bracket — every one of the n
#: openers therefore scanned the whole remaining document: not exponential any
#: more, but still 4x for every doubling, 3.0 s at n=16,000. Requiring the
#: ``[`` to be unescaped removes those starts outright, and it is the more
#: faithful reading as well: an escaped bracket is deliberately *not* markup,
#: which is the whole argument for unescaping last in :func:`_clean_prose`.
#: With the lookbehind in place the text spans of successive attempts cannot
#: overlap — the star stops at the first unescaped ``[`` or ``]``, and the next
#: attempt begins no earlier than that — so the pass is linear by construction.
#: Output is unchanged on all 5,187 cached pages.
_LINK = re.compile(r"(?<!\\)\[(" + _LINK_TEXT + r")\]" + _TARGET)

_AUTOLINK = re.compile(r"<(https?://[^>\s]+)>")

#: HTML tag names that really are markup in these files. The ``(?:\s[^<>]*)?``
#: before the close is load-bearing: it requires whitespace before any
#: attribute, so ``<p.zabel@example.com>`` and ``<a>``-shaped metavariables
#: cannot match a tag name by accident. That exact false positive deleted
#: maintainer e-mail addresses and sysfs metavariables from another source in
#: this package, and the fix is recorded there at length.
#:
#: It was written ``(?:\s+[^<>]*?)?`` and that spelling was quadratic, for the
#: reason given on :data:`_LINK_TEXT`: whitespace is itself ``[^<>]``, so the
#: two quantifiers competed for the same characters and every way of splitting
#: a run of k spaces between them was a distinct path the engine had to try
#: before it could fail. A tag-shaped token followed by a long unbroken line —
#: ``"<a" + " " * n + "z" * n`` — cost 4x for every doubling of n and 5.5 s at
#: n=16,000. One whitespace character followed by a greedy ``[^<>]*`` accepts
#: exactly the same language, because ``\s`` is a subset of ``[^<>]`` and the
#: rest of the run is matched by the class either way, and it has only one
#: parse. Output is unchanged on all 5,187 cached pages.
_HTML_TAG = re.compile(
    r"</?(?:span|dl|dt|dd|br|p|b|i|u|strong|em|ul|ol|li|table|tr|td|th|thead"
    r"|tbody|a|div|code|pre|hr|img|sup|sub|nobr|center|font|h[1-6])"
    r"(?:\s[^<>]*)?/?>",
    re.IGNORECASE,
)

#: Markdown escapes that are safe to undo. ``\_`` alone is 41,795 occurrences
#: and the reason this exists; ``\<``, ``\>``, ``\|`` and ``\\`` are excluded by
#: measurement, each for its own reason, all of them recorded in the module
#: docstring.
_UNESCAPE = re.compile(r"\\([_\[\]])")

#: Entities, resolved to the character they denote rather than deleted, so
#: ``R&amp;D`` becomes ``R&D`` and not ``RD``. 3,509 entity-shaped tokens appear
#: in the selection, ``&quot;`` 2,269 of them.
#:
#: Resolution is **by name**, and unrecognised names are left exactly as
#: written, which is not caution for its own sake: nine of the distinct names
#: here are not entities at all but C address-of expressions from example code
#: — ``&insecbuff;``, ``&outsecbuff;``, ``&authident;``, ``&servercert;``. A
#: resolver that deleted whatever it could not name would quietly corrupt
#: working SSPI samples.
#:
#: The numeric branch refuses exactly one code point. ``&#124;`` is a pipe, and
#: 8 of its 15 occurrences sit inside a Markdown table cell
#: (``| /Operator:{Equal &#124; NotEqual &#124; Contains} |``) where it is
#: escaped *precisely so that it is not a column separator*. Resolving it would
#: split one cell into five. That is the same refusal as ``\|`` above, written
#: in a different notation.
_ENTITY = re.compile(r"&(?:#\d{1,5}|[a-zA-Z][a-zA-Z0-9]{1,9});")
_ENTITIES = {
    "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'",
    "&nbsp;": " ", "&ndash;": "-", "&mdash;": "-", "&hellip;": "...",
    "&rarr;": "->", "&larr;": "<-", "&times;": "x", "&copy;": "(c)",
    "&reg;": "(R)", "&trade;": "(TM)",
}


def _entity(match: re.Match[str]) -> str:
    token = match.group(0)
    known = _ENTITIES.get(token.lower())
    if known is not None:
        return known
    body = token[2:-1]
    if not body.isdigit():
        return token          # not an entity we know — leave the text alone
    code = int(body)
    if code == 0x7C:          # '|' — see the note on _ENTITY
        return token
    return chr(code) if 0 < code < 0x110000 else token


def _segments(text: str) -> list[tuple[bool, str]]:
    """Split into ``(is_code, chunk)`` pairs, fenced blocks marked as code.

    Rejoining the chunks with a newline reconstructs the input exactly, which
    is what lets the cleaners run on prose alone. An unterminated fence — there
    are a handful, mostly a stray ``` in a table cell — takes its tail with it
    as code, because copying suspect text through untouched is the failure this
    package prefers.
    """
    out: list[tuple[bool, str]] = []
    buffer: list[str] = []
    marker: str | None = None

    for line in text.split("\n"):
        stripped = line.strip()
        if marker is None:
            opening = _FENCE.match(stripped)
            if opening is not None:
                out.append((False, "\n".join(buffer)))
                buffer = [line]
                marker = opening.group("marker")
                continue
            buffer.append(line)
            continue
        buffer.append(line)
        if stripped.startswith(marker) and not stripped.strip(marker[0]):
            out.append((True, "\n".join(buffer)))
            buffer = []
            marker = None

    out.append((marker is not None, "\n".join(buffer)))
    return out


def _clean_prose(chunk: str) -> str:
    """Every rewrite in this module, applied to one non-code segment.

    **The unescaping goes last, and that ordering is load-bearing.** Escaped
    brackets are how these pages write a literal ``[`` in running text, and one
    of them is a WPP trace format string::

        set TRACE_FORMAT_PREFIX = \\[%9!d!\\]%8!04X!…%4!s!\\[%1!s!\\](%!COMPNAME!…)

    With the backslashes still in place, :data:`_LINK` and :data:`_IMAGE`
    correctly see no link there at all. Unescape first and the same text
    becomes ``[%1!s!](%!COMPNAME!…)`` — a perfectly well-formed image link as
    far as a regex is concerned — and the line the reader needed is deleted.
    Every escaped bracket in the source is a bracket that is deliberately *not*
    markup, so it must stay escaped until nothing is looking for markup any
    more.
    """
    chunk = _strip_comments(chunk)

    kept: list[str] = []
    for line in chunk.split("\n"):
        if _DIRECTIVE_LINE.match(line) or _APPLIES_TO.match(line):
            continue
        kept.append(line)
    chunk = "\n".join(kept)

    chunk = _ALERT.sub(lambda m: m.group(1).capitalize() + ":", chunk)
    chunk = _IMAGE.sub("", chunk)
    chunk = _LINK.sub(r"\1", chunk)
    chunk = _AUTOLINK.sub(r"\1", chunk)
    # A space, not an empty string: `<dt>A</dt><dt>B</dt>` must not weld into
    # `AB`, and trailing spaces are stripped per line by normalise() anyway.
    chunk = _HTML_TAG.sub(" ", chunk)
    if "&" in chunk:
        chunk = _ENTITY.sub(_entity, chunk)
    return _UNESCAPE.sub(r"\1", chunk)


def _render_markdown(raw: str) -> str:
    """Frontmatter off, prose cleaned, fenced code copied through verbatim."""
    text = raw.replace("\r\n", "\n").replace("\r", "\n")

    title = ""
    header = _FRONTMATTER.match(text)
    if header is not None:
        found = _FM_TITLE.search(header.group("block"))
        if found is not None:
            title = found.group("title").strip().strip("'\"").strip()
        text = text[header.end():]

    rendered = "\n".join(
        chunk if is_code else _clean_prose(chunk)
        for is_code, chunk in _segments(text)
    )

    # Recover the title only for a page that has none of its own. Two pages in
    # 5,187 need it today; the rule is here so that an upstream which stops
    # writing H1s produces titled documents rather than headless ones.
    if title and not re.search(r"^# ", rendered[:4000], re.MULTILINE):
        rendered = f"# {title}\n\n{rendered}"
    return normalise(rendered)


def _render_xml(raw: str) -> str:
    """Sysmon rule configuration, unchanged but for line endings.

    No cleaning at all, and the XML comments stay: ``<!--Thanks to Josh
    Frazier-->`` and the technique annotations beside the rules are the
    commentary that makes this upstream worth having. The attribute form is
    the point — ``<Image name="technique_id=T1036,technique_name=Masquerading"
    condition="begin with">C:\\PerfLogs\\</Image>`` puts an ATT&CK id next to
    its human name next to a real Windows path, which is exactly the
    id-beside-name shape the tokenizer measurement in
    :mod:`training.corpus.source` said the first corpus was missing.
    """
    return normalise(raw.replace("\r\n", "\n").replace("\r", "\n"))


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------

def _git(args: list[str], cwd: Path | None = None) -> str:
    """Run git, or raise :class:`SourceError` saying what failed.

    ``GIT_TERMINAL_PROMPT=0`` matters more than it looks. Without it a clone
    that meets an authentication challenge — a proxy, a rate limit answered
    with a 401 — sits on a credential prompt forever, and a corpus build that
    hangs silently is worse than one that fails.
    """
    exe = shutil.which("git")
    if exe is None:
        raise SourceError(
            "windocs: git is not on PATH. This source needs it: two of the "
            "five upstreams are hundreds of megabytes and only a partial, "
            "sparse clone keeps the download to the security trees."
        )
    argv = [exe, "-c", f"http.userAgent={USER_AGENT}", *args]
    try:
        done = subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True, text=True, check=False, timeout=_GIT_TIMEOUT,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                 "GIT_LFS_SKIP_SMUDGE": "1"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SourceError(f"windocs: git {args[0]} failed: {exc}") from None
    if done.returncode != 0:
        tail = "\n".join((done.stderr or done.stdout).strip().splitlines()[-3:])
        raise SourceError(f"windocs: git {args[0]} exited {done.returncode}: {tail}")
    return done.stdout


def _refuse_unverified_tls() -> None:
    """Refuse to fetch with certificate verification switched off.

    :mod:`training.corpus.net` never builds an unverifying context and says
    why, and the Defender pages go through it. The four cloned upstreams do
    not — git owns those sockets — so for them the same rule is enforced where
    it can actually be broken, which is an environment variable.
    """
    if os.environ.get("GIT_SSL_NO_VERIFY", "").strip():
        raise SourceError(
            "windocs: GIT_SSL_NO_VERIFY is set, so git would fetch this "
            "source's text over an unauthenticated channel. Unset it. A "
            "security project that downloads its own training data without "
            "verifying who sent it has a supply-chain problem."
        )


def _check_licence(upstream: _Upstream, tree: Path) -> str:
    """Read the declared licence file and prove it still says what SPEC claims."""
    path = tree / upstream.licence_files[0]
    if not path.is_file():
        raise SourceError(
            f"windocs: {upstream.name} has no {upstream.licence_files[0]} at "
            "its root. SPEC names a licence for it; without the file that "
            "claim is unverifiable, and source.py refuses unverifiable "
            "provenance for good reasons."
        )
    # utf-8-sig: windowsserverdocs ships its LICENSE with a byte-order mark,
    # and a U+FEFF glued to the front of "Attribution" would put one in the
    # provenance record and, on a stricter check than this one, would defeat
    # the comparison outright.
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if upstream.licence_proof not in text[:2000].casefold():
        raise SourceError(
            f"windocs: {upstream.name}'s {upstream.licence_files[0]} no longer "
            f"contains {upstream.licence_proof!r}. Upstream has relicensed, so "
            "the licence SPEC declares is now false. Correct the declaration "
            "before any of this text is used."
        )
    # First non-blank line, clipped: sysmon-modular's MIT text is one very long
    # paragraph and the whole of it in a JSON marker helps nobody.
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:120]
    return ""


def _prune(tree: Path, upstream: _Upstream) -> int:
    """Delete everything that is not text this source reads. Returns files kept.

    Pruning is by *suffix only*, never by the selection rules. Sparse checkout
    of ``windowsserverdocs`` weighs 194 MB of which 14 MB is Markdown, and none
    of the rest is ever opened; but which pages survive the content gate is a
    decision that should be retunable without a 250 MB refetch, so that
    decision stays in :func:`_documents` and the cache keeps every page.
    """
    keep_names = set(upstream.licence_files)
    kept = 0
    for dirpath, dirnames, filenames in os.walk(tree, topdown=False, followlinks=False):
        here = Path(dirpath)
        for name in filenames:
            path = here / name
            relative = path.relative_to(tree).as_posix()
            if relative in keep_names:
                continue
            if path.is_symlink() or not name.endswith(upstream.suffix):
                path.unlink(missing_ok=True)
                continue
            kept += 1
        for name in dirnames:
            directory = here / name
            if directory.is_symlink():
                directory.unlink(missing_ok=True)
                continue
            try:
                directory.rmdir()       # only succeeds when it is now empty
            except OSError:
                pass
    return kept


def _download_pages(upstream: _Upstream, staging: Path) -> str:
    """Fetch the named pages over verified TLS; return an empty revision.

    Every request goes through :func:`training.corpus.net.download`, which is
    the one place in this project that builds an SSL context and the one place
    that refuses to build a non-verifying one. Nothing about this path is
    hand-rolled.

    There is no commit sha to return: raw content is served per branch, not per
    revision, so the marker records the URL and the fetch time and says so
    rather than inventing provenance it does not have.
    """
    staging.mkdir(parents=True, exist_ok=True)
    missing: list[str] = []
    for relative in (*upstream.licence_files, *upstream.pages):
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            net.download(upstream.raw + relative, target, timeout=120)
        except net.NetworkError as exc:
            # A single renamed page is upstream editing, not breakage. The
            # file floor decides whether enough of them went missing to
            # matter, and either way the names are printed — a named list that
            # silently shrinks is worse than one that fails.
            missing.append(f"{relative} ({exc})")
    if missing:
        print(f"   windocs: {upstream.name} — {len(missing)} named page(s) "
              f"not found upstream:")
        for name in missing:
            print(f"     {name}")
    return ""


def _clone(upstream: _Upstream, staging: Path) -> str:
    """Clone the wanted trees into *staging*; return the resolved ``HEAD``.

    ``--filter=blob:none --sparse`` fetches commits and trees but no file
    contents, and the sparse-checkout that follows is what pulls blobs — only
    for the named directories. On ``win32`` that is 64 MB instead of the 422 MB
    the repository weighs, and the saving is larger still on
    ``windowsserverdocs``.
    """
    argv = ["clone", "--depth", "1", "--single-branch", "--no-tags"]
    if upstream.sparse:
        argv += ["--filter=blob:none", "--sparse"]
    argv += [upstream.url, str(staging)]
    _git(argv)

    if upstream.sparse:
        trees = [*upstream.dense, *upstream.gated]
        if not trees:
            raise SourceError(
                f"windocs: {upstream.name} asks for a sparse clone but names "
                "no trees; that would check out the repository root and "
                "nothing else."
            )
        _git(["sparse-checkout", "set", *trees], cwd=staging)

    head = _git(["rev-parse", "HEAD"], cwd=staging).strip()
    # The clone is never reused: fetch is marker-gated and a cold run starts
    # from scratch. Keeping .git would leave the partial-clone object store
    # sitting in the cache for nothing, so HEAD is read out first.
    shutil.rmtree(staging / ".git", ignore_errors=True)
    return head


def _populate(upstream: _Upstream, staging: Path) -> tuple[str, int, str]:
    """Fetch one upstream, prove its licence, prune it, enforce its floor.

    Returns ``(revision, files kept, licence headline)``. Whichever transport
    ran, the checks after it are the same ones, which is the point of having
    this function at all rather than two half-verified fetch paths.
    """
    revision = (_download_pages(upstream, staging) if upstream.pages
                else _clone(upstream, staging))
    headline = _check_licence(upstream, staging)

    kept = _prune(staging, upstream)
    if kept < upstream.min_files:
        raise SourceError(
            f"windocs: only {kept} {upstream.suffix} files reached the cache "
            f"from {upstream.url} (expected >= {upstream.min_files}). Either "
            "what this adapter names has been reorganised or the fetch was "
            "partial. Fix the adapter rather than training on a fragment of "
            "the Windows security model."
        )
    return revision, kept, headline


def _fetch(cache_dir: Path) -> Path:
    """Populate *cache_dir* with one directory per upstream; return it.

    Idempotent and network-free on re-run. Each upstream clones into a
    ``.part`` sibling and is moved into place only after its licence check and
    file floor have both passed, so an interrupted fetch cannot leave a
    truncated tree that a later run mistakes for a finished one. The marker is
    retired before any tree is touched, which keeps "marker present implies
    cache complete" true at every instant rather than merely at the end.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    if marker.is_file():
        try:
            recorded = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            recorded = {}
        complete = all((cache_dir / up.name).is_dir() for up in _UPSTREAMS)
        if complete and recorded.get("version") == _CACHE_VERSION:
            return cache_dir

    _refuse_unverified_tls()
    marker.unlink(missing_ok=True)

    record: dict[str, dict[str, object]] = {}
    for upstream in _UPSTREAMS:
        target = cache_dir / upstream.name
        staging = cache_dir / f".{upstream.name}.part"
        shutil.rmtree(staging, ignore_errors=True)
        try:
            head, kept, headline = _populate(upstream, staging)
            shutil.rmtree(target, ignore_errors=True)
            staging.replace(target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        record[upstream.name] = {
            "url": upstream.url,
            # Empty for an upstream fetched page by page: raw content is served
            # per branch, not per revision, so there is no sha to record and
            # claiming one would be fiction.
            "head": head,
            "files": kept,
            # The first line of the licence file as it was actually read, not
            # the string this adapter went looking for.
            "licence": headline,
        }
        print(f"   windocs: {upstream.name} {head[:12] or '(no revision)'} — "
              f"{kept} {upstream.suffix} files")

    marker.write_text(
        json.dumps(
            {
                "version": _CACHE_VERSION,
                "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "note": ("no upstream here ships release tags, so HEAD is "
                         "recorded rather than pinned; see the module "
                         "docstring"),
                "upstreams": record,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


# --------------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------------

def _under(relative: str, prefixes: tuple[str, ...]) -> bool:
    """True if *relative* is one of *prefixes* or sits inside one."""
    return any(
        relative == prefix or relative.startswith(prefix + "/")
        for prefix in prefixes
    )


def _verdict(upstream: _Upstream, relative: str) -> str | None:
    """``"dense"``, ``"gated"`` or ``None`` for a cache-relative path.

    Order matters: the named exceptions win over everything, exclusions win
    over the tree lists, and an upstream with no dense trees is dense
    everywhere that is left.
    """
    if relative in upstream.always:
        return "dense"
    if _under(relative, upstream.exclude):
        return None
    if not upstream.root_files and "/" not in relative:
        return None
    if _under(relative, upstream.gated):
        return "gated"
    if not upstream.dense or _under(relative, upstream.dense):
        return "dense"
    return None


def _walk(tree: Path, suffix: str) -> list[str]:
    """Every cached file of *suffix* as a tree-relative path, sorted.

    ``os.walk(followlinks=False)`` rather than ``Path.rglob``: rglob follows
    directory symlinks, and a sibling adapter in this package once followed a
    repository's data symlink onto an external volume and copied the corpus
    cache back into the corpus, relabelled.
    """
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(tree, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(
            name for name in dirnames if not (here / name).is_symlink()
        )
        for name in sorted(filenames):
            if not name.endswith(suffix):
                continue
            path = here / name
            if path.is_symlink():
                continue
            out.append(path.relative_to(tree).as_posix())
    return out


def _documents(path: Path) -> Iterator[Document]:
    """Yield one document per selected page, in upstream then path order.

    Exact duplicates are dropped here with the same fingerprint the build uses,
    so the count this source reports is the count it actually contributes
    rather than a number that shrinks downstream. On the current cache it finds
    **none** — the five upstreams do not overlap, and within each one the same
    page is not published twice — and it stays anyway, at the cost of one hash
    per document, because the five-upstream shape is exactly the one where a
    future addition starts republishing somebody else's pages. Reporting zero
    is also worth something: it says the 2,954 documents are 2,954 distinct
    ones.
    """
    held: dict[str, list[int]] = {}
    kept_chars = 0
    kept_docs = 0
    seen: set[str] = set()

    for upstream in _UPSTREAMS:
        tree = path / upstream.name
        if not tree.is_dir():
            raise SourceError(
                f"windocs: no {upstream.name}/ under {path}; run fetch first"
            )
        # off-tree, gate, degenerate, short, duplicate
        tally = held.setdefault(upstream.name, [0, 0, 0, 0, 0])
        floor = upstream.min_chars or _MIN_CHARS

        for relative in _walk(tree, upstream.suffix):
            verdict = _verdict(upstream, relative)
            if verdict is None:
                tally[0] += 1
                continue
            try:
                # utf-8-sig: a minority of these files carry a BOM, and a stray
                # U+FEFF at the head of a document is a token the model would
                # otherwise learn to expect before every Windows page.
                raw = (tree / relative).read_text(encoding="utf-8-sig",
                                                  errors="replace")
            except OSError:
                continue

            if upstream.suffix == ".xml":
                text = _render_xml(raw)
            else:
                text = _render_markdown(raw)

            if len(text) < floor:
                tally[3] += 1
                continue
            if verdict == "gated" and not _relevant(text):
                tally[1] += 1
                continue
            if _degenerate(text):
                tally[2] += 1
                continue
            key = fingerprint(text)
            if key in seen:
                tally[4] += 1
                continue
            seen.add(key)

            kept_chars += len(text)
            kept_docs += 1
            yield Document(
                text=text,
                source="windocs",
                register=Register.SYSTEM,
                side=Side.NEUTRAL,
                ident=f"{upstream.name}/{relative}",
            )

    # Nothing here is held back silently: a selection this opinionated should
    # have to say out loud how much it threw away, every build.
    print(f"   windocs: {kept_docs} documents / {kept_chars/1e6:.1f}M chars")
    for name, (off_tree, gated, dump, short, duplicate) in held.items():
        print(f"     {name:<20} dropped {off_tree:>5} off-tree, {gated:>4} by "
              f"the content gate, {dump:>2} data dump(s), {short:>4} too "
              f"short, {duplicate:>3} duplicate")


SPEC = SourceSpec(
    name="windocs",
    license=(
        "Composite, one statement per upstream, each read out of the "
        "repository at fetch time and refused if it no longer says this. "
        "MicrosoftDocs/win32: CC BY 4.0 for the documentation (LICENSE) and "
        "MIT for the code samples in it (LICENSE-CODE), Microsoft "
        "Corporation. MicrosoftDocs/windowsserverdocs: CC BY 4.0 and MIT, "
        "same split, Microsoft Corporation. MicrosoftDocs/sysinternals: "
        "CC BY 4.0 and MIT, same split, Microsoft Corporation. "
        "olafhartong/sysmon-modular: MIT (license.md). "
        "MicrosoftDocs/defender-docs: MIT for both prose and code — this one "
        "really is MIT and not CC BY 4.0 like its three Microsoft siblings, "
        "read out of its LICENSE rather than assumed from them. "
        "SwiftOnSecurity/sysmon-config is deliberately NOT used: it carries no "
        "licence file and no licence statement anywhere in the repository, and "
        "an unlicensed upstream is exactly what source.py refuses. Every "
        "licence file is copied into the cache beside the text it covers. "
        "Nothing is redistributed by this project: each build fetches from "
        "upstream on its own machine."
    ),
    url="https://github.com/MicrosoftDocs/win32",
    register=Register.SYSTEM,
    side=Side.NEUTRAL,
    fetch=_fetch,
    documents=_documents,
    #: The five upstreams yield 2,954 documents / 15.3M characters today. The
    #: floor sits well under that so it catches breakage — a renamed tree, a
    #: withdrawn repository, a sparse cone that matched nothing — rather than
    #: ordinary upstream editing. Each upstream additionally enforces its own
    #: file floor at fetch time, so a single repository failing is loud before
    #: this is ever reached.
    expect_min_docs=2000,
    notes=(
        "Windows security internals: the access-token/SID/privilege/ACL model, "
        "LSA and the authentication packages, the registry and WMI persistence "
        "surfaces, the Event Log and ETW substrate with the audit subcategories "
        "that decide which event ids get written, Sysmon's schema plus real "
        "modular Sysmon rule configuration, AMSI and code integrity, plus the "
        "Defender and ASIM log schemas an analyst queries. Selection "
        "is two-tier: trees that are on-topic by location (win32 desktop-src "
        "Sec*/WES/ETW/AMSI/ProcThread, WindowsServerDocs/security, all of "
        "sysinternals) are taken whole, and mixed trees (AD DS identity, the "
        "cmd.exe command reference, WmiSdk, TaskSchd, Debug, SecProv) are "
        "filtered page by page against six families of security vocabulary — a "
        "content gate would keep only 7% of the Event Log API tree, which is "
        "why location decides first. desktop-src/Debug/pe-format.md is named "
        "explicitly because a file-format specification scores nothing on "
        "security words and is the most security-relevant page in its tree; "
        "identity/ad-ds/deploy/Schema-Updates.md is refused because 1.38 MB at "
        "33% distinct lines is an LDIF dump, not documentation. defender-docs "
        "contributes eighteen hand-named reference pages and no tree at all, "
        "because the gate is useless there: Defender product prose is made of "
        "the gate's own vocabulary, so everything passes. MSDN-converted "
        "HTML and Markdown link targets are stripped from prose, fenced code "
        "and table alignment are kept verbatim, and backslash-escaped "
        "underscores are undone so the corpus does not learn SE\\_DEBUG\\_NAME "
        "with backslashes in it. The withdrawal of MicrosoftDocs/"
        "windows-itpro-docs from public GitHub took the per-event-id auditing "
        "reference with it; forks are not used in its place."
    ),
)
