"""Third-party personal data: one scrubber, shared by the programming adapters.

**Why this file exists at all, and why its name starts with an underscore.**

``build.py`` has a chokepoint — every document from every source passes through
``_redacted`` — and that chokepoint is excellent at exactly one thing: removing
*this machine's* identity. It knows this host's addresses, this operator's name
and mail, this volume's label. It cannot know the name of a university
classmate, or the mail address a stranger put in a copyright header in 2008,
because those are not facts about this machine.

That gap is not hypothetical here. An eight-agent audit of the shipped corpus
found 23,535 occurrences of eleven distinct private values, and the ones that
mattered most were the ones the chokepoint was never going to catch: the full
names and personal ``.edu`` addresses of three people who never agreed to be in
anybody's training data. They arrived through a source that collected text from
repositories, and every adapter in this family collects text from repositories.

So the four programming-knowledge adapters strip third-party mail addresses
themselves, *before* the chokepoint, and they all do it with this function
rather than each with its own copy. :mod:`training.corpus.net` already records
what happens when security-relevant code is copied three times: one of the
copies drifts. A scrubber is security-relevant code.

The leading underscore is load-bearing. ``discover_sources()`` skips any module
under ``sources/`` whose name starts with ``_``, so this file is a helper and
never a source — it declares no ``SPEC`` and could not be built if it did.

**What is stripped and what is deliberately kept.**

Stripped: mail addresses, in the plain form, in angle brackets, behind
``mailto:``, and written with the HTML entities that documentation toolchains
emit for ``@``. Replaced with a fixed marker rather than deleted, because a
deletion silently welds the two halves of a sentence together and a marker says
"something was here" to anyone reading the corpus later.

Kept: **names.** A maintainer named in the AUTHOR section of a published man
page, an author credited in a ``@qhelp`` reference, a copyright holder named in
a licence header — these are published attributions, several of them required
by the licence the text arrives under (GPL-2 §1 and GPL-3 §4 both say the
notices stay), and removing them would make the corpus less honest rather than
more private. The line this family draws is between *a person published as the
author of this document* and *a person's contact details or a private
individual's identity*, and it draws it deliberately rather than by accident.

Not a replacement for the chokepoint, and not claimed to be one. This runs
first and is narrow; ``build.py`` still runs afterwards and is the thing that
knows about this host.
"""

from __future__ import annotations

import re

__all__ = ["EMAIL_MARKER", "count_emails", "strip_emails"]

#: What replaces an address. Deliberately not an empty string: see the module
#: docstring. Deliberately not something that looks like an address either, so a
#: later scan of the corpus for leaks cannot be fooled by this marker.
EMAIL_MARKER = "[address removed]"

#: A mail address as it is actually written in source trees and documentation.
#:
#: Three properties are doing work here, and each of them exists because the
#: obvious looser pattern destroys something real:
#:
#: * The local part may not be preceded by a word character, ``@``, ``/`` or
#:   ``.``. Without that, ``docs/auditd.conf.5`` and a Go module path
#:   ``gopkg.in/yaml.v2`` are not at risk but ``user@@host`` and a second pass
#:   over an already-marked address are.
#: * The domain must end in a run of at least two letters, so
#:   ``package@1.2.3``, ``npm install foo@^1.0`` and CodeQL's own metadata keys
#:   (``@name``, ``@kind``, ``@problem.severity``) do not match. CodeQL query
#:   headers are *made* of ``@`` tokens and a careless pattern eats them.
#: * The TLD run is bounded. An unbounded ``[A-Za-z]+`` tail will happily
#:   swallow the remainder of a run-together identifier in minified text.
_LOCAL = r"[A-Za-z0-9](?:[A-Za-z0-9._%+'-]{0,62}[A-Za-z0-9])?"
_DOMAIN = r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}"
_EMAIL = re.compile(
    rf"(?<![\w@/.]){_LOCAL}@{_DOMAIN}\b"
)

#: ``@`` as a documentation toolchain writes it when it does not want a literal.
#: ECMAXML, DocBook and qhelp all pass through HTML entities, and an address
#: written ``steve&#64;example.org`` is still an address.
_ENTITY_AT = re.compile(r"&(?:#0*64|#[xX]0*40|commat|AT);")

#: ``mailto:`` immediately before an address, so the scheme goes with it rather
#: than being left behind as ``mailto:[address removed]``.
_MAILTO = re.compile(r"\bmailto:\s*", re.IGNORECASE)

#: ``<addr>`` and ``(addr)`` wrappers, the two forms a copyright header uses.
#: Collapsed after substitution so the corpus does not carry ``<[address
#: removed]>``.
_WRAPPED = re.compile(r"[<(]\s*" + re.escape(EMAIL_MARKER) + r"\s*[>)]")

#: Reserved for documentation and testing, and therefore **deliberate
#: content** — kept, not removed.
#:
#: These two sets are deliberately the same as ``build.py``'s
#: ``_EMAIL_RESERVED_TLDS`` and ``_EMAIL_RESERVED_DOMAINS``, and the agreement
#: is the point. The first version of this module stripped everything that
#: matched, which over-reached in a measurable way: the four addresses it
#: removed from ``codeqlhelp``'s tree were placeholder addresses inside the
#: CWE-640 e-mail-header-injection samples, where the address *is* the example.
#: Rewriting one of those "corrupts the example while protecting nobody" —
#: ``build.py``'s own words, and the same discipline it applies by not counting
#: ``192.0.2.0/24`` as a leak.
#:
#: Restated here rather than imported because ``build.py`` imports the sources
#: package and a source importing ``build`` closes that circle. The duplication
#: is two frozensets of literals from RFC 2606 §2-3 and RFC 6761, which is the
#: kind that does not drift; the test suite pins them against ``build.py``'s
#: copies so that if one ever moves, the suite says so.
RESERVED_TLDS = frozenset({"test", "example", "invalid", "localhost"})
RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})


def _is_reserved(domain: str) -> bool:
    """True for the documentation and testing domains RFC 2606/6761 reserve."""
    domain = domain.casefold()
    if domain in RESERVED_DOMAINS:
        return True
    if any(domain.endswith("." + reserved) for reserved in RESERVED_DOMAINS):
        return True
    return domain.rpartition(".")[2] in RESERVED_TLDS


def _is_removable(address: str) -> bool:
    """Whether this address is somebody's identity rather than documentation."""
    return not _is_reserved(address.rpartition("@")[2])


def strip_emails(text: str) -> tuple[str, int]:
    """Return *text* with mail addresses replaced, and how many were replaced.

    The count is returned rather than logged because the caller is the thing
    that knows which document this was, and because a source that cannot say
    how many addresses it removed cannot be audited. ``psconcept`` reports zero
    across its whole tree and that zero is only meaningful because it was
    counted rather than assumed.

    Entity-encoded ``@`` is normalised to a literal ``@`` first, so one pattern
    covers both spellings. That rewrite is confined to text that then matches an
    address: a document containing ``&commat;`` with nothing address-shaped
    around it is returned with its entity intact, because rewriting it would be
    an edit this function was not asked to make.

    Addresses at a reserved documentation domain are left exactly as they were —
    see :data:`RESERVED_DOMAINS`. They are examples, and an example with its
    address removed is a worse example and a no better corpus.
    """
    candidate = _ENTITY_AT.sub("@", text)
    if candidate != text and not any(
            _is_removable(found) for found in _EMAIL.findall(candidate)):
        candidate = text  # the entity was not part of a removable address.

    hits = 0

    def _one(match: re.Match[str]) -> str:
        nonlocal hits
        if not _is_removable(match.group(0)):
            return match.group(0)
        hits += 1
        return EMAIL_MARKER

    cleaned = _EMAIL.sub(_one, candidate)
    if not hits:
        return text, 0
    cleaned = _MAILTO.sub("", cleaned)
    cleaned = _WRAPPED.sub(EMAIL_MARKER, cleaned)
    return cleaned, hits


def count_emails(text: str) -> int:
    """How many addresses :func:`strip_emails` would remove. Does not rewrite.

    Exists for the tests and for the fetch-time scan each adapter runs over its
    whole cache: "the strip worked" is a claim about the *output*, and the only
    way to check it is to count again afterwards and get zero.

    **Counts what the stripper would take, not what the pattern matches**, and
    the two differ by exactly the reserved documentation domains. Keeping the
    two definitions in step is what makes "zero addresses in the emitted
    documents" a coherent claim rather than a different question answered by a
    different ruler — which is the shape of the three measurement bugs in this
    project's history, all of which were in the instrument.
    """
    return sum(1 for found in _EMAIL.findall(_ENTITY_AT.sub("@", text))
               if _is_removable(found))
