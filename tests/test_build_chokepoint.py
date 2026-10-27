"""The corpus build's redaction chokepoint, and the gate that checks its work.

An audit of the shipped corpus found that the redactor was *correct* and the
corpus was *dirty*, which sounds impossible until you notice that nothing ever
read the output back. `ownrepos.py` grew an email redactor because it had swept
up a university README listing four people by name with their addresses — the
author's own and three `.edu` addresses belonging to other students. The
redactor removed all eight when run by hand. It had never been run: its mtime
was twenty days later than the corpus file's, and the shipped document carried
all eight with not one placeholder anywhere in 208,346 documents.

That is the sentence every test in this file is about: **a redactor that was
added but never run is indistinguishable, from the code, from one that ran and
found nothing.** Only a pass over the written bytes tells those apart.

Four more defects in the same chokepoint, each reproduced here before it was
fixed:

* a redaction refusal **truncated the source and wrote the prefix to disk**,
  while the comment above it claimed "one bad source is skipped and named";
* `_redacted` touched `doc.text` and not `doc.ident`, which several adapters
  build from a filesystem path;
* redaction was **not** the last thing to touch the text — `_strip_boilerplate`
  mutates afterwards;
* a source that produced zero documents with no error appeared in neither of
  `balance_report`'s two tables and read as a source that simply had nothing to
  give.

**Every value in this file is fabricated.** RFC 2606 reserved domains, RFC 3849
documentation prefixes, invented names at invented domains, and `verify.py`'s
own synthetic calibration needles. Where a test needs a real host identifier it
derives it at runtime and asserts on its *absence*; nothing here writes one
anywhere. :class:`TestThisFileLeaksNothing` is that claim, enforced — because
the audit which found these problems created a new on-disk leak by writing its
own needle table to a JSON file, and a test suite is a file like any other.
"""
from __future__ import annotations

import importlib
import itertools
import json
from pathlib import Path

import pytest

import training.corpus.build as build_mod
from training.corpus.build import (
    GATE_MARKER,
    CorpusGateFailed,
    balance_report,
    build,
    read_documents,
)

# --------------------------------------------------------------------------
# throwaway adapters
# --------------------------------------------------------------------------

_PREAMBLE = """
from pathlib import Path

from training.corpus.source import Document, Register, Side, SourceSpec

"""

_seq = itertools.count()


def _adapter(tmp_path: Path, monkeypatch, body: str, **spec_kwargs):
    """Materialise a throwaway adapter module and return its SPEC.

    A real module on disk rather than a stub object, because ``spawn`` imports
    the adapter in the child and a lambda would not survive the pickle. Same
    shape as the watchdog tests' helper, kept local so this file does not depend
    on another test module's private.
    """
    name = f"_chokepoint_probe_{next(_seq)}"
    kwargs = {
        "name": repr(name),
        "license": repr("throwaway"),
        "url": repr("https://example.invalid/probe"),
        "register": "Register.PROSE",
        "side": "Side.NEUTRAL",
        "expect_min_docs": "1",
    }
    kwargs.update({k: repr(v) if isinstance(v, str) else str(v)
                   for k, v in spec_kwargs.items()})
    fields = "".join(f"    {k}={v},\n" for k, v in kwargs.items())
    module = _PREAMBLE + body + f"""

SPEC = SourceSpec(
    fetch=_fetch,
    documents=_documents,
{fields})
"""
    (tmp_path / f"{name}.py").write_text(module, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    return importlib.import_module(name).SPEC


#: Ten documents whose sixth carries a tripwire the test's redactor refuses on.
#: A marker in the text rather than a call count, because a counting raiser goes
#: on raising for every later source and would make "the blast radius is one
#: source" untestable — the bug would hide the fix.
_TEN_TRIP = """
def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    for i in range(10):
        trip = " TRIPWIRE" if i == 5 else ""
        yield Document(
            text=(f"document number {i} of a throwaway probe source, padded "
                  f"out{trip}"),
            source=SPEC.name, register=Register.PROSE, side=Side.NEUTRAL,
            ident=f"doc{i}")
"""

#: Ten clean documents, each distinct and each long enough to clear min_chars.
#: Texts 0-4 and 6-9 are byte-identical to _TEN_TRIP's, which is what makes the
#: dedup-release test mean something.
_TEN = """
def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    for i in range(10):
        yield Document(
            text=f"document number {i} of a throwaway probe source, padded out",
            source=SPEC.name, register=Register.PROSE, side=Side.NEUTRAL,
            ident=f"doc{i}")
"""

#: Yields nothing at all, cleanly. The zero-document case.
_EMPTY = """
def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    return
    yield
"""

#: Raises part way through — an ordinary malformed upstream file. Its prefix is
#: meant to survive; that behaviour is pinned so the refusal fix cannot
#: accidentally generalise to it.
_PARSE_ERROR = """
def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    for i in range(3):
        yield Document(
            text=f"well formed document {i} from a probe source, padded out ok",
            source=SPEC.name, register=Register.PROSE, side=Side.NEUTRAL,
            ident=f"ok{i}")
    raise ValueError("upstream layout changed half way down the walk")
"""

#: Redaction refuses in the CHILD. The adapter installs the raiser itself, at
#: import time, so that it is in place in the spawned process where a
#: monkeypatch in the parent cannot reach — and so the parent's own module is
#: never touched. ``spawn`` imports this module in the child because the SPEC's
#: callables live in it.
_CHILD_REFUSES = """
def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    # Installed HERE, inside the generator, and not at module import.
    #
    # Two reasons, both learned by watching this file fail. `_adapter` imports
    # this module in the PARENT to read its SPEC, so an import-time patch
    # poisons the parent's redactor for the rest of the session -- that took
    # thirty-five other tests with it on the first run. And a
    # `parent_process() is not None` guard at import time does not work either:
    # `spawn` imports this module while UNPICKLING the Process object, which
    # happens before `_bootstrap` installs the child's parent handle, so the
    # guard reads None in the child too and the patch never lands.
    #
    # The generator body runs only where documents are produced -- the child,
    # under the watchdog -- and runs before the first redaction, because
    # `_child_main` takes one document from this iterator before it redacts it.
    import multiprocessing as _mp

    import training.trajectories as _traj

    if _mp.parent_process() is not None:
        _real = _traj.redact_identity

        def _raiser(text: str) -> str:
            if "TRIPWIRE" in text:
                raise RuntimeError("identity survived redaction and this "
                                   "document must not be written: "
                                   "['the home path']")
            return _real(text)

        _traj.redact_identity = _raiser

    for i in range(10):
        trip = " TRIPWIRE" if i == 5 else ""
        yield Document(
            text=(f"document number {i} of a throwaway probe source, padded "
                  f"out{trip}"),
            source=SPEC.name, register=Register.PROSE, side=Side.NEUTRAL,
            ident=f"doc{i}")
"""

#: Emits a value drawn from verify.py's synthetic calibration needle set. The
#: real redactor has no reason to touch it — it is nobody's identifier — so it
#: reaches the written file and the gate is asked about it with the matching
#: synthetic needle table. That is how "the gate fails a dirty build" is tested
#: without a dirty build.
_SYNTHETIC_NEEDLE = """
def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    yield Document(
        text="session opened for user synthetic-operator on the build host",
        source=SPEC.name, register=Register.PROSE, side=Side.NEUTRAL,
        ident="synthetic")
"""

#: Carries fabricated addresses: one at a documentation domain (kept), one role
#: mailbox (kept) and one at a person-shaped address (rewritten under the
#: default policy).
_ADDRESSES = """
def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    yield Document(
        text=("reported by d.vrok@kvothe-labs.io, demo account "
              "user@example.com, disclosures to security@kvothe-labs.io"),
        source=SPEC.name, register=Register.PROSE, side=Side.NEUTRAL,
        ident="addresses")
"""


def _run(tmp_path, monkeypatch, specs, **kwargs):
    """Call the REAL build() against throwaway specs, into our own scratch dir.

    Never near the real corpus directory: these tests write documents and
    delete files, and a test that can reach his corpus is one bad default away
    from destroying it. The directory is not named here either — the volume it
    sits on is itself one of the identifiers this file must not contain.
    """
    monkeypatch.setattr(build_mod, "discover_sources", lambda: list(specs))
    kwargs.setdefault("max_source_share", 0.0)   # a 1-source corpus is 100%
    kwargs.setdefault("min_chars", 1)
    return build(tmp_path / "out", tmp_path / "cache", **kwargs)


def _lines(out_dir: Path, name: str) -> list[dict]:
    path = out_dir / f"{name}.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


# --------------------------------------------------------------------------
# 1. the blast radius
# --------------------------------------------------------------------------

class TestARedactionRefusalDiscardsTheWholeSource:
    """The comment used to say "one bad source is skipped and named". It lied.

    `except Exception` wrapped the entire document loop while `kept` was
    appended to inside it, and `collected[spec.name] = kept` ran unconditionally
    after the `with` block. So a refusal **truncated** the source and wrote
    every document before the offending one to disk — and those are exactly the
    untrustworthy ones, because they came out of the same adapter and the same
    walk as the document caught carrying identity. The only thing separating
    them was that the redactor had not reached them yet.

    Reproduced with the real `build()`: 5 of 10 documents written for the
    failing source, which then appeared in `balance_report`'s register coverage
    as a healthy contributor *and* in its list of sources that failed.

    The timeout path one branch above has always done this correctly, and this
    file's own words for it are "skipped and named is honest; truncated and
    counted is not".
    """

    @staticmethod
    def _refuse_on_tripwire(monkeypatch):
        """Make the real redactor refuse on the one document that carries the
        tripwire, and behave normally on every other.

        Patched at :mod:`training.trajectories`, not at ``build._redacted``,
        because the thing under test is how build.py *classifies and contains* a
        refusal — patching the wrapper would skip the code that does it.

        Keyed on the text rather than on a call count, because a counting raiser
        keeps raising for every later source and "the blast radius is one
        source" would then be untestable.
        """
        import training.trajectories as traj

        real = traj.redact_identity

        def raiser(text: str) -> str:
            if "TRIPWIRE" in text:
                raise RuntimeError(
                    "identity survived redaction and this document must not "
                    "be written: ['the home path']")
            return real(text)

        monkeypatch.setattr(traj, "redact_identity", raiser)

    def test_not_one_document_is_written(self, tmp_path, monkeypatch):
        """The reproduction. Zero, not five."""
        spec = _adapter(tmp_path, monkeypatch, _TEN_TRIP)
        self._refuse_on_tripwire(monkeypatch)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert _lines(tmp_path / "out", spec.name) == []
        assert not (tmp_path / "out" / f"{spec.name}.jsonl").exists()
        assert stats[0].docs == 0 and stats[0].chars == 0

    def test_the_source_is_named_in_the_failure_list(self, tmp_path, monkeypatch):
        spec = _adapter(tmp_path, monkeypatch, _TEN_TRIP)
        self._refuse_on_tripwire(monkeypatch)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        report = balance_report(stats)
        assert "sources that failed" in report
        assert spec.name in report.split("sources that failed", 1)[1]

    def test_it_is_not_counted_as_a_healthy_contributor(self, tmp_path, monkeypatch):
        """It used to appear in BOTH tables, which is the worst of the two.

        `balance_report` builds its register table from `[s for s in stats if
        s.docs]`, so leaving the pre-refusal counts in place described a source
        as contributing while also listing it as failed.
        """
        spec = _adapter(tmp_path, monkeypatch, _TEN_TRIP)
        self._refuse_on_tripwire(monkeypatch)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert [s for s in stats if s.docs] == []
        assert "total: 0.0M chars across 0 documents" in balance_report(stats)

    def test_it_is_called_a_refusal_and_not_a_parse_failure(self, tmp_path,
                                                            monkeypatch):
        """"parse failed" sends the reader to the adapter's parser.

        The thing that needs fixing is that the adapter is handing the
        chokepoint text carrying this machine's identity, which is a different
        bug in a different place with a different fix.
        """
        spec = _adapter(tmp_path, monkeypatch, _TEN_TRIP)
        self._refuse_on_tripwire(monkeypatch)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert "REDACTION REFUSED" in stats[0].error
        assert "parse failed" not in stats[0].error

    def test_it_is_relisted_after_the_balance_report(self, tmp_path, monkeypatch,
                                                     capsys):
        """Follows the _TIMEOUTS / _STALE_REMOVED precedent, and needs its own
        list rather than a line in theirs: a timeout says re-run, a refusal says
        an adapter is leaking and will refuse again identically forever."""
        spec = _adapter(tmp_path, monkeypatch, _TEN_TRIP)
        self._refuse_on_tripwire(monkeypatch)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)
        out = capsys.readouterr().out

        assert "DISCARDED WHOLE" in out
        assert out.index("DISCARDED WHOLE") > out.index("register coverage")
        assert spec.name in out.split("DISCARDED WHOLE", 1)[1]

    def test_other_sources_are_unaffected(self, tmp_path, monkeypatch):
        """The blast radius is one source, which is what the comment claimed
        and the code did not do."""
        bad = _adapter(tmp_path, monkeypatch, _TEN_TRIP)
        good = _adapter(tmp_path, monkeypatch, _TEN)
        self._refuse_on_tripwire(monkeypatch)
        stats = _run(tmp_path, monkeypatch, [bad, good], source_timeout=0.0)

        by_name = {s.name: s for s in stats}
        assert by_name[bad.name].docs == 0
        assert by_name[good.name].docs == 10
        assert len(_lines(tmp_path / "out", good.name)) == 10

    def test_a_discarded_source_releases_its_dedup_claim(self, tmp_path,
                                                         monkeypatch):
        """Its fingerprints must not go on suppressing a later source's text.

        `seen` is shared across sources. Documents collected before a refusal
        had already claimed their fingerprints, so discarding the source without
        releasing them left a later source silently short — and the later source
        is then the one that looks broken.
        """
        bad = _adapter(tmp_path, monkeypatch, _TEN_TRIP)
        good = _adapter(tmp_path, monkeypatch, _TEN)   # same text, no tripwire
        self._refuse_on_tripwire(monkeypatch)
        stats = _run(tmp_path, monkeypatch, [bad, good], source_timeout=0.0)

        by_name = {s.name: s for s in stats}
        assert by_name[good.name].docs == 10, "the discarded source's "
        assert by_name[good.name].duplicates == 0

    def test_a_refusal_in_the_child_discards_the_whole_source(self, tmp_path,
                                                              monkeypatch):
        """The same containment across the process boundary.

        The child redacts before it writes its transport file, so a refusal can
        happen over there, where it reaches the parent only as a string in the
        status record. Classifying that string as "parse failed" would reinstate
        the truncation in the one path that actually runs in production.
        """
        spec = _adapter(tmp_path, monkeypatch, _CHILD_REFUSES)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=120.0)

        assert _lines(tmp_path / "out", spec.name) == []
        assert stats[0].docs == 0
        assert "REDACTION REFUSED" in stats[0].error
        assert "parse failed" not in stats[0].error

    def test_an_ordinary_parse_failure_still_keeps_its_prefix(self, tmp_path,
                                                              monkeypatch):
        """Pinned so the refusal fix cannot quietly generalise to this.

        A malformed upstream file is one bad file in a walk, and the documents
        before it are fine — that is why the in-process build has always allowed
        a partial yield. Only a redaction refusal taints what came before it.
        """
        spec = _adapter(tmp_path, monkeypatch, _PARSE_ERROR)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert len(_lines(tmp_path / "out", spec.name)) == 3
        assert "parse failed after 3 docs" in stats[0].error
        assert "REDACTION REFUSED" not in stats[0].error


# --------------------------------------------------------------------------
# 2. ident
# --------------------------------------------------------------------------

class TestIdentIsRedactedToo:
    """`_redacted` touched `doc.text` only, and `ident` is written beside it.

    Several adapters build `ident` from a filesystem path — `logsamples` from
    the repository path, `metasploit` from the module path, `cloudsec`,
    `sigma`, `nuclei` and `elastic` from relative paths — so an absolute path
    off this machine in any adapter's `ident` landed in the corpus with no
    redaction and no check. It does not reach the tokenizer, which reads
    `row["text"]` only. It reaches everyone who reads or is sent the file.

    The needle here is **derived at runtime** and only ever asserted absent.
    """

    def test_an_identity_bearing_ident_is_rewritten(self):
        from training.corpus.source import Document, Register, Side
        from training.trajectories import identity_leaks

        home = str(Path.home())
        doc = Document(text="a clean document with nothing to redact in it",
                       source="probe", register=Register.PROSE,
                       side=Side.NEUTRAL, ident=f"{home}/notes/readme.md")
        assert identity_leaks(doc.ident), (
            "vacuous unless the fixture's ident actually leaks")

        clean = build_mod._redacted(doc)
        assert not identity_leaks(clean.ident)
        assert home not in clean.ident
        assert clean.text == doc.text

    def test_the_written_jsonl_carries_the_redacted_ident(self, tmp_path,
                                                          monkeypatch):
        """End to end, because `ident` is written at the final write loop and
        an in-memory assertion would not have caught the original bug."""
        from training.trajectories import identity_leaks

        home = str(Path.home()).replace("\\", "\\\\")
        body = _TEN.replace('ident=f"doc{i}"',
                            f'ident=f"{home}/repo/doc{{i}}.md"')
        spec = _adapter(tmp_path, monkeypatch, body)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        rows = _lines(tmp_path / "out", spec.name)
        assert len(rows) == 10
        for row in rows:
            assert not identity_leaks(row["ident"]), row["ident"]

    def test_a_document_with_nothing_to_redact_is_untouched(self):
        """Every source pays this on every document, so it must be a no-op when
        there is nothing to do — and a redactor that edits clean text is one
        that will eventually corrupt a payload."""
        from training.corpus.source import Document, Register, Side

        doc = Document(text="CVE-2024-21412 cvss: 9.8 vector CVSS:3.1/AV:N",
                       source="probe", register=Register.PROSE,
                       side=Side.NEUTRAL, ident="advisory-1")
        assert build_mod._redacted(doc) is doc

    def test_a_document_without_an_ident_field_is_tolerated(self):
        """`_redacted` is called directly by tests with minimal stand-ins, and a
        redactor that demands a particular shape of input is one somebody routes
        around."""
        from dataclasses import dataclass

        @dataclass
        class _Doc:
            text: str

        original = "nothing identifying here at all, just ordinary prose text"
        assert build_mod._redacted(_Doc(text=original)).text == original


# --------------------------------------------------------------------------
# 3. the email policy
# --------------------------------------------------------------------------

#: (text, rewritten, kept, label) under the DEFAULT (redact) tier. Fabricated.
_EMAIL_FIXTURES = [
    ("Reported by Dana Vrok <dana.vrok@kvothe-labs.io>.", 1, 0,
     "a named person at a real-looking domain"),
    ("Team: a.quill@uni-fictional.edu, b.morrow@uni-fictional.edu", 2, 0,
     "two .edu addresses — the classmate case this whole pass is for"),
    ("From: j_okonkwo+spam@mail.fictional-corp.co.uk", 1, 0,
     "plus-addressing and a two-label suffix"),
    ("c2 = 'drop.box.9931@mailinator-fictional.top'", 1, 0,
     "an indicator-shaped address in a rule"),
    ("owner: v.petrova@acme.internal", 1, 0,
     ".internal is private-use, not reserved for documentation"),
    ("mail to user@example.com for the demo", 0, 1,
     "RFC 2606 second-level documentation domain"),
    ("see admin@host.invalid", 0, 1, "RFC 2606 .invalid"),
    ("probe fired at scanner@target.test", 0, 1, "RFC 2606 .test"),
    ("alice@sub.example.org signed off", 0, 1,
     "a subdomain of a documentation domain"),
    ("report to security@kvothe-labs.io", 0, 1,
     "RFC 2142 role mailbox at a real-looking domain"),
    ("bounced from MAILER-DAEMON@kvothe-labs.io", 0, 1,
     "automated sender, uppercase"),
    ("root@localhost.localdomain reported the fault", 0, 1,
     "a system account is a mailbox, not a person"),
    ("contributor-3@example.invalid", 0, 1,
     "this policy's own output — the idempotence case"),
    ("npm install left-pad@1.2.3", 0, 0, "a version spec is not an address"),
    ("git show HEAD@{upstream}", 0, 0, "a git revision is not an address"),
    ("use @staticmethod on the helper", 0, 0, "a decorator is not an address"),
    ("ssh deploy@build-host runs it", 0, 0,
     "user@host with no dotted suffix is not an address"),
    ("root@localhost reported the fault", 0, 0,
     "a bare localhost has no dotted suffix — not an address to this regex"),
]


class TestEmailPolicy:
    """Addresses are redacted HERE, once, with a written-down policy.

    Before this they were redacted in exactly one adapter as a courtesy, so the
    other forty-six passed every address straight through — and the one that had
    the redactor had never run it.

    **The line drawn, and why.** An address is kept only where it is part of the
    licensed artifact rather than incidental to it: `rfc`, because the IETF
    Trust provisions permit reproduction of an RFC *in full* and the author
    block is part of the document, and `kerneldocs`, because author and
    Signed-off-by lines are the DCO record and rewriting them misrepresents who
    certified a contribution rather than anonymising anyone. Measured against
    the shipped corpus those two carry 20,709 of the 28,805 address occurrences.

    Everything else redacts, including upstream material that is already public.
    The CC-BY and CC-BY-SA sources here satisfy attribution with the provenance
    line each adapter already writes, not with an address in a document body; a
    published checkpoint memorises what it is shown and cannot be grepped
    afterwards, so "already public" is not "safe to bake in"; and for the
    detection sources the signal a from-scratch model needs is that a rule
    matches on address-shaped strings, not the exact mail drop from 2019.

    Three carve-outs apply in every tier, and one rule has no exception
    anywhere: an address belonging to the operator of this machine is removed
    from every source including the exempt ones. He can publish his own address
    on his own website whenever he likes. A checkpoint is not somewhere he can
    un-publish it from.
    """

    @pytest.mark.parametrize(
        "text,rewritten,kept,label",
        [pytest.param(*f, id=f[3][:48]) for f in _EMAIL_FIXTURES])
    def test_calibrated_against_fixtures_built_first(self, text, rewritten,
                                                     kept, label):
        """Recall 6/6 fixtures (8/8 addresses), precision 12/12.

        One of these was corrected by its own first run and the correction is
        the reason this list is in the test file rather than in a scratch
        script: `root@localhost` was written expecting "kept by the reserved
        domain rule", and the detector returned "not an address at all" —
        because `localhost` has no dot, so the regex never reaches the rule.
        The detector was right and the fixture was mislabelled. Check the
        instrument first.
        """
        policy = build_mod._email_policy("ghsa")       # the default tier
        out, got_r, got_k = build_mod._redact_emails(text, policy)
        assert (got_r, got_k) == (rewritten, kept), label
        if not rewritten:
            assert out == text, "a kept address must not be rewritten"

    def test_an_exempt_source_keeps_a_third_party_address(self):
        policy = build_mod._email_policy("rfc")
        assert policy.keep_third_party
        text = "Author: Dana Vrok <dana.vrok@kvothe-labs.io>"
        out, rewritten, kept = build_mod._redact_emails(text, policy)
        assert (out, rewritten, kept) == (text, 0, 1)

    def test_the_operators_own_address_is_removed_even_from_an_exempt_source(
            self, monkeypatch):
        """The one rule with no exception.

        The needle is fabricated and injected, so this test proves the rule
        without naming anything of his.
        """
        monkeypatch.setattr(build_mod, "_host_email_needles",
                            lambda: frozenset({"d.vrok@kvothe-labs.io"}))
        for source in ("rfc", "kerneldocs", "ghsa", "ownrepos"):
            policy = build_mod._email_policy(source)
            out, rewritten, kept = build_mod._redact_emails(
                "From: D.Vrok@Kvothe-Labs.IO", policy)
            assert rewritten == 1 and kept == 0, source
            assert out == "From: operator@example.invalid"

    def test_the_replacement_is_varied_not_a_single_token(self):
        """A single-token redaction passes the privacy gate and makes the model
        worse.

        6,277 occurrences in the shipped corpus fall under the rewrite tier.
        Collapsing them onto one 26-character literal would create a new
        high-frequency sequence in a corpus whose measured problem is already
        literals repeated hundreds of times each. Privacy is satisfied by *any*
        substitution; generalisation only by a varied one.
        """
        placeholders = {
            build_mod._email_pseudonym(f"person{i}@fictional-{i % 37}.example.net")
            for i in range(5000)
        }
        assert len(placeholders) == 64, len(placeholders)
        assert all(p.endswith("@example.invalid") for p in placeholders)

    def test_the_bucket_is_a_class_label_and_not_a_fingerprint(self):
        """64 buckets over thousands of addresses is deliberately lossy.

        The bucket is derived from the address, so it carries information about
        it; roughly sixty real addresses share each one, which makes it a class
        label that no amount of corpus reading inverts. Pushing the count up
        buys variety and narrows each bucket toward identifying its members, and
        this is where that trade stops being worth taking.
        """
        buckets = {}
        for i in range(2000):
            addr = f"person{i}@fictional.example.net"
            buckets.setdefault(build_mod._email_pseudonym(addr), []).append(addr)
        assert min(len(v) for v in buckets.values()) >= 10

    def test_the_same_address_always_gets_the_same_placeholder(self):
        """blake2b, not `hash()`, which is salted per process. The corpus has to
        be reproducible across runs and machines or the dedup fingerprints move
        under it — the same argument `_cap_source_share` makes for its own
        selection."""
        one = build_mod._email_pseudonym("dana.vrok@kvothe-labs.io")
        two = build_mod._email_pseudonym("dana.vrok@kvothe-labs.io")
        assert one == two
        assert one != build_mod._email_pseudonym("dana.vroq@kvothe-labs.io")

    def test_a_second_pass_changes_nothing(self):
        """The parent re-redacts what the child already redacted, and
        `_reredact_mutated` runs after boilerplate removal, so non-idempotence
        would compound on every pass."""
        policy = build_mod._email_policy("ghsa")
        for text, _, _, label in _EMAIL_FIXTURES:
            once, _, _ = build_mod._redact_emails(text, policy)
            twice, _, _ = build_mod._redact_emails(once, policy)
            assert twice == once, label

    def test_the_counts_are_reported_per_source(self, tmp_path, monkeypatch,
                                                capsys):
        """A redactor that cannot show what it did on this run is one nobody can
        distinguish from a redactor that was never called, and that distinction
        is what twenty days of a shipped corpus cost."""
        spec = _adapter(tmp_path, monkeypatch, _ADDRESSES)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)
        out = capsys.readouterr().out

        assert "email policy" in out
        row = [ln for ln in out.splitlines() if ln.startswith(spec.name)]
        assert row, out
        assert "1" in row[0] and "2" in row[0], row[0]

    def test_the_counts_cross_the_process_boundary(self, tmp_path, monkeypatch,
                                                   capsys):
        """The child does the redaction when the watchdog is armed, which is
        every production build. A report that silently counted zero because the
        counting happened in another process would be the same class of lie as
        the redactor that was never called."""
        spec = _adapter(tmp_path, monkeypatch, _ADDRESSES)
        _run(tmp_path, monkeypatch, [spec], source_timeout=120.0)
        out = capsys.readouterr().out

        row = [ln for ln in out.splitlines() if ln.startswith(spec.name)]
        assert row, out
        assert build_mod._EMAIL_COUNTS[spec.name] == [1, 2]

    def test_a_policy_entry_for_a_missing_source_is_named(self, tmp_path,
                                                          monkeypatch, capsys):
        """A keep entry for a source that no longer exists is a policy nobody is
        getting — the silent-omission shape `discover_sources` refuses a
        hand-maintained registry for."""
        monkeypatch.setitem(build_mod._EMAIL_KEEP, "no_such_source", "why")
        spec = _adapter(tmp_path, monkeypatch, _TEN)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert "no_such_source" in capsys.readouterr().err

    def test_the_whole_policy_is_in_the_report(self, tmp_path, monkeypatch,
                                               capsys):
        """Each exemption is printed with its reason on every build, so an
        exemption cannot become an accident again."""
        spec = _adapter(tmp_path, monkeypatch, _ADDRESSES)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)
        out = capsys.readouterr().out

        for name in build_mod._EMAIL_KEEP:
            assert name in out
        assert "RFC 2606" in out and "RFC 2142" in out

    def test_the_written_document_carries_the_policy(self, tmp_path, monkeypatch):
        spec = _adapter(tmp_path, monkeypatch, _ADDRESSES)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        text = _lines(tmp_path / "out", spec.name)[0]["text"]
        assert "d.vrok@kvothe-labs.io" not in text
        assert "user@example.com" in text
        assert "security@kvothe-labs.io" in text
        assert "@example.invalid" in text


# --------------------------------------------------------------------------
# 4. ordering
# --------------------------------------------------------------------------

#: 30 documents sharing one long, prose-shaped line — enough to clear
#: boilerplate.py's 25-distinct-document threshold — with a synthetic two-part
#: needle on either side of it. Before stripping, the parts are separated by the
#: boilerplate line and no needle exists. After stripping, `BoilerplateFilter`
#: collapses the removed run to a single blank line and the two parts become
#: "ALPHA\n\nOMEGA", which IS the needle. Redaction in the document loop cannot
#: see it; only a pass after the mutation can.
_BOILERPLATE_JOIN = '''
_FURNITURE = ("This document is provided as is without any warranty of any "
              "kind whatsoever, express or implied.")


def _fetch(cache_dir: Path) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _documents(path: Path):
    for i in range(30):
        yield Document(
            text=(f"ALPHA\\n{_FURNITURE}\\nOMEGA — probe document number {i} "
                  f"with enough padding to clear the forty character floor"),
            source=SPEC.name, register=Register.PROSE, side=Side.NEUTRAL,
            ident=f"join{i}")
'''


class TestRedactionIsTheLastThingToTouchTheText:
    """`_redacted` ran in the document loop; `_strip_boilerplate` mutates after.

    So the guarantee the chokepoint comment implied — "every written byte passed
    redaction" — was really "every byte passed redaction and was then edited
    again". Boilerplate removal only deletes, so it cannot introduce a literal
    that was not already latent. It can delete the characters separating two
    halves of one, which is what this fixture does with a synthetic needle,
    using the real `boilerplate` module and the real `build()`.

    Re-redacting after the mutation is cheaper than an argument about whether
    line-granular deletion can ever join two fragments, and an invariant that
    rests on nobody adding a third transform later is not an invariant.
    """

    @staticmethod
    def _needle_redactor(monkeypatch):
        import training.trajectories as traj

        real = traj.redact_identity

        def fake(text: str) -> str:
            return real(text).replace("ALPHA\n\nOMEGA", "REDACTED-PAIR")

        monkeypatch.setattr(traj, "redact_identity", fake)

    def test_a_literal_boilerplate_removal_creates_is_redacted(self, tmp_path,
                                                               monkeypatch):
        spec = _adapter(tmp_path, monkeypatch, _BOILERPLATE_JOIN)
        self._needle_redactor(monkeypatch)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        rows = _lines(tmp_path / "out", spec.name)
        assert len(rows) == 30
        assert all("warranty of any kind" not in r["text"] for r in rows), (
            "vacuous unless the boilerplate line was actually stripped")
        leaked = [r["ident"] for r in rows if "ALPHA\n\nOMEGA" in r["text"]]
        assert leaked == [], leaked
        assert all("REDACTED-PAIR" in r["text"] for r in rows)

    def test_the_build_says_when_it_fired(self, tmp_path, monkeypatch, capsys):
        """Expected to be a no-op on every document, so when it is not, that is
        a finding about the boilerplate keys and it says so rather than quietly
        fixing it."""
        spec = _adapter(tmp_path, monkeypatch, _BOILERPLATE_JOIN)
        self._needle_redactor(monkeypatch)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert "REDACTION FIRED AFTER BOILERPLATE REMOVAL" in capsys.readouterr().out

    def test_a_refusal_after_the_mutation_discards_the_source(self, tmp_path,
                                                              monkeypatch):
        """Nothing has been written at that point, so the blast radius is
        identical to the document loop's."""
        import training.trajectories as traj

        spec = _adapter(tmp_path, monkeypatch, _BOILERPLATE_JOIN)
        real = traj.redact_identity

        def fake(text: str) -> str:
            if "ALPHA\n\nOMEGA" in text:
                raise RuntimeError("identity survived redaction and this "
                                   "document must not be written: ['probe']")
            return real(text)

        monkeypatch.setattr(traj, "redact_identity", fake)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert _lines(tmp_path / "out", spec.name) == []
        assert stats[0].docs == 0
        assert "REDACTION REFUSED" in stats[0].error


# --------------------------------------------------------------------------
# 5. the transport file
# --------------------------------------------------------------------------

class TestTheTransportFileIsWrittenRedacted:
    """The child used to write every document UNREDACTED to a real file.

    `_child_main` serialises each Document to `<mkdtemp>/documents.jsonl` in the
    exact schema the final corpus uses, and redaction happened later, in the
    parent, as the parent streamed it back. Under `scripts/overnight.sh` TMPDIR
    is the external volume, so that spill landed beside the corpus it was
    supposed to be a redacted version of, and it survived anything that stopped
    the parent before its `finally` — a SIGKILL, a power loss.

    Of the audit's two options — redact before the transport write, or guarantee
    the directory is removed even on a crash — the first is the only one that
    can actually be delivered. No cleanup code runs after SIGKILL. Redacting
    first makes the worst a crash can leave behind an artifact of the same class
    as the corpus itself, which is a guarantee that does not depend on cleanup
    running at all.
    """

    def test_the_spill_holds_no_identity(self, tmp_path, monkeypatch):
        """Read the transport bytes at the moment the parent opens them, which
        is before the `finally` removes the directory."""
        from training.trajectories import identity_leaks

        home = str(Path.home()).replace("\\", "\\\\")
        body = _TEN.replace(
            'text=f"document number {i} of a throwaway probe source, padded out"',
            f'text=f"document {{i}} read from {home}/repo/notes.md for a probe"')
        spec = _adapter(tmp_path, monkeypatch, body)

        spilled: list[str] = []
        real = build_mod._read_child_documents

        def capture(path: Path):
            spilled.append(path.read_text(encoding="utf-8"))
            return real(path)

        monkeypatch.setattr(build_mod, "_read_child_documents", capture)
        _run(tmp_path, monkeypatch, [spec], source_timeout=120.0)

        assert spilled, "the isolated path did not run"
        assert str(Path.home()) not in spilled[0]
        assert not identity_leaks(spilled[0])
        assert "/Users/operator" in spilled[0] or "operator" in spilled[0]

    def test_the_spill_directory_is_private(self, tmp_path, monkeypatch):
        """0700 stated rather than inherited. This directory holds every
        document of one source, and on a shared machine a transport file is as
        readable as the corpus."""
        import stat

        spec = _adapter(tmp_path, monkeypatch, _TEN)
        modes: list[int] = []
        real = build_mod._read_child_documents

        def capture(path: Path):
            modes.append(stat.S_IMODE(path.parent.stat().st_mode))
            return real(path)

        monkeypatch.setattr(build_mod, "_read_child_documents", capture)
        _run(tmp_path, monkeypatch, [spec], source_timeout=120.0)

        assert modes == [0o700]

    def test_the_spill_is_removed_on_the_happy_path(self, tmp_path, monkeypatch):
        spec = _adapter(tmp_path, monkeypatch, _TEN)
        seen: list[Path] = []
        real = build_mod._read_child_documents

        def capture(path: Path):
            seen.append(path.parent)
            return real(path)

        monkeypatch.setattr(build_mod, "_read_child_documents", capture)
        _run(tmp_path, monkeypatch, [spec], source_timeout=120.0)

        assert seen and not seen[0].exists()


# --------------------------------------------------------------------------
# 6. the gate
# --------------------------------------------------------------------------

verify = pytest.importorskip("training.corpus.verify",
                             reason="agent C's verifier has not landed yet")


class TestTheVerificationGate:
    """The missing piece. Everything above is a redactor; this is the check.

    From the code alone, a redactor that was added but never run is
    indistinguishable from one that ran and found nothing. The only thing that
    tells them apart is a pass over the written bytes — which is also why the
    gate reads the files rather than the in-memory documents: that makes the
    ordering of every transform irrelevant, which is the right way to hold this
    invariant rather than by inspecting call sites.

    Nothing is deleted on a failure. The leaking JSONL is the evidence that
    names the adapter, and destroying it to feel safer destroys the only thing
    that points at the bug. What stops the corpus being trained on is the
    marker, which `read_documents` refuses to read past.
    """

    @staticmethod
    def _synthetic_needles(monkeypatch):
        """Point the gate at verify.py's own fabricated calibration needles.

        That is how "the gate fails a dirty build" gets tested without a dirty
        build: `synthetic-operator` is nobody's identifier, the real redactor
        has no reason to touch it, and the synthetic table knows it.
        """
        monkeypatch.setattr(verify, "host_needles", verify._cal_needles)

    def test_it_fails_a_build_whose_output_carries_a_needle(self, tmp_path,
                                                            monkeypatch):
        spec = _adapter(tmp_path, monkeypatch, _SYNTHETIC_NEEDLE)
        self._synthetic_needles(monkeypatch)

        with pytest.raises(CorpusGateFailed) as caught:
            _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)
        assert "CORPUS GATE: FAILED" in str(caught.value)
        assert f"{spec.name}.jsonl" in str(caught.value)

    def test_the_failure_reports_fingerprints_and_never_the_value(
            self, tmp_path, monkeypatch):
        """Vigil's keystone property, held here: never print a full secret.

        The audit that found these problems created a new on-disk leak by
        writing its own needle table to a JSON file while its report claimed it
        had not. This gate will not repeat it.
        """
        spec = _adapter(tmp_path, monkeypatch, _SYNTHETIC_NEEDLE)
        self._synthetic_needles(monkeypatch)

        with pytest.raises(CorpusGateFailed) as caught:
            _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        report = str(caught.value)
        assert "synthetic-operator" not in report
        assert "sha256=" in report

    def test_the_marker_holds_no_value_either(self, tmp_path, monkeypatch):
        """The marker is a file, and a file is where the audit's own leak went."""
        spec = _adapter(tmp_path, monkeypatch, _SYNTHETIC_NEEDLE)
        self._synthetic_needles(monkeypatch)
        with pytest.raises(CorpusGateFailed):
            _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        marker = (tmp_path / "out" / GATE_MARKER).read_text(encoding="utf-8")
        assert marker.startswith("FAIL")
        assert "synthetic-operator" not in marker
        assert verify.scan_text(marker, needles=verify._cal_needles()) == []

    def test_nothing_is_deleted_on_a_failure(self, tmp_path, monkeypatch):
        """It is his data and the decision to destroy it is his. The file is
        also the only thing that names the leaking adapter."""
        spec = _adapter(tmp_path, monkeypatch, _SYNTHETIC_NEEDLE)
        self._synthetic_needles(monkeypatch)
        with pytest.raises(CorpusGateFailed):
            _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert (tmp_path / "out" / f"{spec.name}.jsonl").is_file()

    def test_read_documents_refuses_a_directory_that_failed(self, tmp_path,
                                                            monkeypatch):
        """One gate run protects the tokenizer, the shard writer and the data
        loader, because `read_documents` is the one door all three are
        documented to come through. A verdict enforced in each of them instead
        would reach whichever ones remembered."""
        spec = _adapter(tmp_path, monkeypatch, _SYNTHETIC_NEEDLE)
        self._synthetic_needles(monkeypatch)
        with pytest.raises(CorpusGateFailed):
            _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        with pytest.raises(CorpusGateFailed, match="FAILED verification"):
            list(read_documents(tmp_path / "out"))

    def test_a_clean_build_passes_and_records_that_it_did(self, tmp_path,
                                                          monkeypatch):
        """PASS is as important as FAIL: it is the evidence that the pass ran at
        all, which is exactly what the shipped corpus could not show."""
        spec = _adapter(tmp_path, monkeypatch, _TEN)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert stats[0].docs == 10
        marker = (tmp_path / "out" / GATE_MARKER).read_text(encoding="utf-8")
        assert marker.startswith(("PASS", "UNVERIFIED"))
        assert len(list(read_documents(tmp_path / "out"))) == 10

    def test_a_crashing_verifier_fails_closed(self, tmp_path, monkeypatch):
        """A scanner that crashed certified nothing, and "we could not check"
        has to resolve the same way as "it is dirty"."""
        spec = _adapter(tmp_path, monkeypatch, _TEN)

        def boom(*_a, **_k):
            raise OSError("the volume went away mid-scan")

        monkeypatch.setattr(verify, "verify_corpus", boom)
        with pytest.raises(CorpusGateFailed, match="verifier itself raised"):
            _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

    def test_a_thin_needle_table_withholds_the_pass(self, tmp_path, monkeypatch):
        """"0 leaks" from an empty table means *nothing was looked for*, which
        is the same fail-open as a redactor with an empty table. It is a
        statement about the instrument and not about the corpus, so it withholds
        the PASS rather than failing the build — three honest states instead of
        two that have to cover for each other."""
        spec = _adapter(tmp_path, monkeypatch, _TEN)
        self._synthetic_needles(monkeypatch)       # probes=("calibration",)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        marker = (tmp_path / "out" / GATE_MARKER).read_text(encoding="utf-8")
        assert marker.startswith("UNVERIFIED")
        assert "INSTRUMENT INCOMPLETE" in marker

    def test_a_missing_verifier_is_loud_but_not_fatal(self, tmp_path, monkeypatch,
                                                      capsys):
        """A deliberate, uncomfortable exception: refusing would make build.py
        unusable until the scanner lands. The one thing it must not be is
        quiet."""
        import sys

        spec = _adapter(tmp_path, monkeypatch, _TEN)
        monkeypatch.setitem(sys.modules, "training.corpus.verify", None)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        out = capsys.readouterr().out
        assert "UNVERIFIED" in out
        assert "NOTHING read them back" in out
        assert (tmp_path / "out" / GATE_MARKER).read_text(
            encoding="utf-8").startswith("UNVERIFIED")


# --------------------------------------------------------------------------
# 7. a source that gave nothing
# --------------------------------------------------------------------------

class TestAZeroDocumentSourceIsVisible:
    """It used to appear in neither of `balance_report`'s two tables.

    The register table is built from `[s for s in stats if s.docs]` and the
    failure list from `[s for s in stats if s.error]`, so a source with zero
    documents and no error vanished from the report entirely and read, to anyone
    looking, like a source that simply had nothing to give. `_note_if_emptied`
    already makes exactly this argument for a source a cap reduced to zero, and
    is wired only into the two cap functions — the same hole, one door along.

    The corpus has this shape today: a `wikipedia` adapter exists with no
    `wikipedia.jsonl` beside it, and the report cannot say whether it was
    skipped or had nothing to give.
    """

    def test_it_is_named_in_the_failure_list(self, tmp_path, monkeypatch):
        spec = _adapter(tmp_path, monkeypatch, _EMPTY)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert stats[0].docs == 0
        assert stats[0].error, "a source that gave nothing said nothing"
        report = balance_report(stats)
        assert spec.name in report.split("sources that failed", 1)[1]

    def test_the_message_says_the_whole_source_is_missing(self, tmp_path,
                                                          monkeypatch):
        """Recording it as an error is not a mischaracterisation: a whole
        upstream is absent from the corpus, and the failure list is the only
        channel the report already watches."""
        spec = _adapter(tmp_path, monkeypatch, _EMPTY)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        assert "produced 0 documents" in stats[0].error
        assert "absent from the corpus" in stats[0].error

    def test_a_real_failure_keeps_its_own_message(self, tmp_path, monkeypatch):
        """A source that failed for a reason must keep the reason. Overwriting
        it with "produced 0 documents" would hide the fetch error behind a
        symptom."""
        spec = _adapter(tmp_path, monkeypatch, _CHILD_REFUSES)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=120.0)

        assert "REDACTION REFUSED" in stats[0].error
        assert "produced 0 documents" not in stats[0].error

    def test_a_healthy_source_is_not_accused(self, tmp_path, monkeypatch):
        spec = _adapter(tmp_path, monkeypatch, _TEN)
        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)
        assert stats[0].error == ""


# --------------------------------------------------------------------------
# 8. the preflight
# --------------------------------------------------------------------------

class TestThePreflightRefusesAFailOpen:
    """`redact_identity` returns text unchanged when its table is empty.

    `pattern = _identity_pattern(); if pattern is None: return text` — so on a
    host whose account name, host name and temp dir are all generic (a container
    running as root, a CI runner, a uid missing from the passwd database) every
    document is returned byte-for-byte and *nothing says so*. A build with an
    empty table is identical in its output and in its log to a build where
    redaction ran and found nothing.

    Checked before a single byte is fetched, for the same reason `build()`
    refuses an unsatisfiable share cap up front: the condition is knowable from
    the start, and discovering it after an hour of downloads costs the hour.
    """

    @staticmethod
    def _empty_table(monkeypatch):
        import training.trajectories as traj

        monkeypatch.setattr(traj, "_identity_table", lambda: ())
        monkeypatch.setattr(traj, "redact_identity", lambda text: text)

    def test_an_empty_table_refuses_the_build(self, tmp_path, monkeypatch):
        spec = _adapter(tmp_path, monkeypatch, _TEN)
        self._empty_table(monkeypatch)

        with pytest.raises(SystemExit, match="would be a no-op"):
            _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)
        assert not (tmp_path / "out" / f"{spec.name}.jsonl").exists()

    def test_the_opt_out_proceeds_and_says_it_is_inactive(self, tmp_path,
                                                          monkeypatch, capsys):
        """A host with genuinely nothing to protect can build. What it cannot do
        is build quietly."""
        spec = _adapter(tmp_path, monkeypatch, _TEN)
        self._empty_table(monkeypatch)

        stats = _run(tmp_path, monkeypatch, [spec], source_timeout=0.0,
                     require_identity_table=False)
        assert stats[0].docs == 10
        assert "INACTIVE" in capsys.readouterr().err

    def test_a_broken_redactor_import_refuses_the_build(self, tmp_path,
                                                        monkeypatch):
        """`_redacted`'s stated contract: a corpus that is clean only when an
        optional import succeeds is a corpus nobody can make a claim about.
        Left to happen lazily inside the document loop it was caught as a
        per-source "parse failed" and the build carried on."""
        import sys

        spec = _adapter(tmp_path, monkeypatch, _TEN)
        monkeypatch.setitem(sys.modules, "training.trajectories", None)

        with pytest.raises(SystemExit, match="will not import"):
            _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

    def test_the_preflight_reports_what_it_found(self, tmp_path, monkeypatch,
                                                 capsys):
        """Counts, never values. "Nothing was found" and "nothing was looked
        for" have to be different lines in the log."""
        spec = _adapter(tmp_path, monkeypatch, _TEN)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        out = capsys.readouterr().out
        assert "redaction:" in out
        assert "identity form(s) for this host" in out


# --------------------------------------------------------------------------
# 9. this file, and the file it tests
# --------------------------------------------------------------------------

class TestThisFileLeaksNothing:
    """The audit's own worst finding, turned into a test.

    Six of the audit's working files wrote live MAC addresses, global IPv6
    addresses and an email address to disk as cleartext literals while the
    report claimed they had not. A test suite is a file like any other, and the
    only defence that survives contact with a deadline is an assertion.

    So: neither `build.py` nor this file may contain a host identifier, and
    every address literal in either must be in RFC 2606 reserved space.
    Derived at runtime, asserted absent, nothing written.
    """

    @staticmethod
    def _sources() -> dict[str, str]:
        return {
            "build.py": Path(build_mod.__file__).read_text(encoding="utf-8"),
            "test_build_chokepoint.py": Path(__file__).read_text(encoding="utf-8"),
        }

    def test_neither_file_contains_a_host_identifier(self):
        needles = verify.host_needles()
        for name, source in self._sources().items():
            leaks = verify.scan_text(source, needles=needles, field=name)
            assert leaks == [], [(leak.kind, leak.field) for leak in leaks]

    def test_no_address_literal_in_either_file_belongs_to_this_host(self):
        """A second instrument on the same question, derived independently.

        The scan above comes from `verify.py`'s needle table; this one comes
        from build.py's own `_host_email_needles`, which is built from `git
        config` and the environment in this process. Two tables assembled by
        different code agreeing is the difference between a result and a guess,
        and it is cheap here.
        """
        host = {a.lower() for a in build_mod._host_email_needles()}
        for name, source in self._sources().items():
            found = {a.lower() for a in build_mod._EMAIL.findall(source)}
            assert not (found & host), f"{name} names an address of this host"

    def test_the_host_needle_set_is_never_printed(self, tmp_path, monkeypatch,
                                                  capsys):
        """A fabricated needle is injected and the whole build output is
        searched for it. If the real set were ever printed, so would this be."""
        fabricated = "d.vrok@kvothe-labs.io"
        monkeypatch.setattr(build_mod, "_host_email_needles",
                            lambda: frozenset({fabricated}))
        spec = _adapter(tmp_path, monkeypatch, _ADDRESSES)
        _run(tmp_path, monkeypatch, [spec], source_timeout=0.0)

        captured = capsys.readouterr()
        assert fabricated not in captured.out
        assert fabricated not in captured.err
        marker = (tmp_path / "out" / GATE_MARKER).read_text(encoding="utf-8")
        assert fabricated not in marker
