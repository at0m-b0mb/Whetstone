"""Tests for the identity redaction the trajectory generator applies.

This corpus is produced by reading a real machine, and reading a real machine
returns who owns it. The account name, the home directory, the host name and
the per-user temp directory all arrive inside ordinary observations, and every
one of them ends up in the weights, because that is what a pretraining corpus
is for. A username in a text file is an afternoon's work to remove. A username
in a checkpoint is a training run thrown away.

So the property under test is not "the redactor has a function". It is that a
document cannot leave :func:`training.trajectories.generate_trajectories`
carrying this machine's identity, whatever the adapter underneath returned.

The existing generator tests stub the host with constant, anonymous payloads,
which is right for testing the generator's *choices* and is exactly why they
could not have caught this: an adapter that reports nothing about its machine
cannot leak anything about its machine. The fixture here reports one.

The other half of the file is about the failure the obvious fix introduces. A
blanket substitution of whatever ``getpass.getuser()`` returns rewrites every
``"runs_as":"root"`` in thirteen thousand documents when the corpus is built as
root, or on CI where the account is ``runner`` — teaching the model a world in
which nothing runs as root, silently, in a file nobody reads. Those tests pin
the names that must survive redaction untouched.
"""

from __future__ import annotations

import getpass
import json
import re
import socket
import tempfile
from pathlib import Path

import pytest

import whetstone.verbs  # noqa: F401  (registers the catalogue)
from training import trajectories as T
from whetstone.actions import REGISTRY, Observation


# --------------------------------------------------------------------------
# a machine that answers with its own name, the way a real adapter does
# --------------------------------------------------------------------------

def _identity_payload() -> dict[str, object]:
    """The identifying values a real host adapter puts in an observation.

    Taken live rather than hardcoded, for the same reason
    :func:`~training.trajectories._identity_table` is: a fixture pinned to one
    developer's username tests that developer's machine and passes everywhere
    else by accident.

    ``runs_as`` is in here as a control. It is not identity, it is load-bearing
    text, and a redactor that removes it has done more damage than the leak it
    was added to fix.
    """
    return {
        "user": getpass.getuser(),
        "real_name": getpass.getuser(),
        "home": str(Path.home()),
        "hostname": socket.gethostname(),
        "tmp": tempfile.gettempdir(),
        "runs_as": "root",
    }


class _LeakyHost:
    """A stand-in adapter that reports the machine it is running on.

    Constant within a run, so the generator's determinism assertions elsewhere
    would still hold if this were swapped in, and shaped like the payloads the
    real adapters return so that the kernel and the renderer treat it the same
    way.
    """

    platform = "linux"

    def implemented(self) -> tuple[str, ...]:
        return tuple(v.id for v in REGISTRY if v.target.value != "none")

    def execute(self, verb, action) -> Observation:
        if verb.id.startswith("vuln."):
            data: dict[str, object] = {"findings": []}
        elif verb.id.startswith("detect."):
            data = {"logged": False, "count": 0}
        else:
            data = _identity_payload()
        return Observation(action=action, ok=True, data=data,
                           platform=self.platform)


@pytest.fixture(scope="module")
def leaked_corpus() -> list[str]:
    """A small corpus generated against a host that answers with its own name.

    The sandbox worlds are switched off: they are slower, they write to disk,
    and the leak this file is about comes from the *host* worlds. The temp
    directory is still covered, because the leaky adapter reports it.
    """
    return list(T.generate_trajectories(
        repeats=2, seed=7, include_lab=False, observe=24, refusals=20,
        host_executor=_LeakyHost()))


@pytest.fixture
def fresh_table():
    """Clear the memoised identity table around a test that changes the machine.

    :func:`~training.trajectories._identity_table` is cached for the life of the
    process, which is right in a build and wrong in a test that monkeypatches
    what the machine is called. Cleared on the way in *and* on the way out, so a
    test cannot leave a fabricated table behind for the rest of the session.
    """
    # Bound before the yield, so that a test which monkeypatches one of these
    # names does not leave the teardown reaching for ``cache_clear`` on a plain
    # lambda. The teardown has to run whatever the test did to the module.
    table, pattern = T._identity_table, T._identity_pattern
    table.cache_clear()
    pattern.cache_clear()
    yield
    table.cache_clear()
    pattern.cache_clear()


def _identifying_values() -> dict[str, str]:
    """The values this machine would leak, or an empty mapping if it has none.

    A container running as ``root`` in ``/root`` with a hex host name has
    nothing worth substituting, and on such a machine the assertions below are
    vacuously true rather than wrong. Returning the mapping lets the tests skip
    honestly instead of passing for the wrong reason.
    """
    return {form: repl for form, repl in T._identity_table()}


# --------------------------------------------------------------------------
# the property: identity does not leave the generator
# --------------------------------------------------------------------------

class TestGeneratedCorpusCarriesNoIdentity:
    def test_the_fixture_would_really_have_leaked(self, leaked_corpus):
        """Guards the test below from passing for the wrong reason.

        If the leaky adapter ever stops reporting identity — a refactor of the
        payload, a renamed field — the assertion that the corpus is clean stays
        green while testing nothing at all. So: prove the raw payload is dirty
        before proving the rendered corpus is clean.
        """
        if not _identifying_values():
            pytest.skip("this machine has no identifying values to leak")
        raw = json.dumps(_identity_payload())
        assert T.identity_leaks(raw), (
            "the fixture no longer reports anything identifying, so the "
            "corpus-is-clean test below has nothing to catch")

    def test_no_document_carries_this_machines_identity(self, leaked_corpus):
        """The regression. Every one of these documents is built from an
        observation that named this machine, and not one of them says so."""
        assert leaked_corpus
        for text in leaked_corpus:
            leaks = T.identity_leaks(text)
            assert not leaks, f"{leaks!r} survived into a trajectory"

    def test_root_survives_redaction(self, leaked_corpus):
        """The corpus still knows that services run as root.

        The failure this pins is the one a blanket substitution introduces, and
        it is invisible in the output: every ``root`` quietly rewritten to the
        placeholder, thirteen thousand documents teaching a model that the
        privileged account on a Unix box is a user account.
        """
        assert any('"runs_as":"root"' in text for text in leaked_corpus)

    def test_paths_keep_their_shape(self, leaked_corpus):
        """A redacted home directory is still a home directory.

        ``<home>/Public`` would teach the model that observations contain
        angle-bracket holes, and at serving time it would meet a real path it
        has no shape for. The substitution swaps the name and leaves the path.
        """
        if str(Path.home()) not in _identifying_values():
            pytest.skip("this machine's home directory is not identifying")
        redacted = str(Path.home().parent / T._OPERATOR)
        assert any(redacted in text for text in leaked_corpus), (
            f"no document carries {redacted}; the home path was removed "
            "rather than substituted")


# --------------------------------------------------------------------------
# what must not be substituted
# --------------------------------------------------------------------------

class TestGenericNamesAreLeftAlone:
    @pytest.mark.parametrize("name", ["root", "admin", "ubuntu", "runner",
                                      "operator", "nobody"])
    def test_a_generic_account_name_never_enters_the_table(
            self, name, monkeypatch, fresh_table):
        """Building the corpus as one of these must not rewrite the corpus.

        ``root`` is the one that matters and ``runner`` is the one that would
        actually happen, because that is what GitHub Actions calls its account.
        """
        monkeypatch.setattr(getpass, "getuser", lambda: name)
        assert name not in {form for form, _ in T._identity_table()}
        assert T.redact_identity(f'{{"runs_as":"{name}"}}') == \
            f'{{"runs_as":"{name}"}}'

    def test_a_short_account_name_never_enters_the_table(
            self, monkeypatch, fresh_table):
        """A three-character name occurs inside unrelated words, and every one
        of those occurrences would be rewritten with no way to tell which were
        which afterwards."""
        monkeypatch.setattr(getpass, "getuser", lambda: "kai")
        assert "kai" not in {form for form, _ in T._identity_table()}


# --------------------------------------------------------------------------
# the spellings a value takes once it is inside JSON
# --------------------------------------------------------------------------

class TestSpellings:
    def test_a_posix_path_has_one_spelling(self):
        assert T._spellings("/Users/alice", "/Users/operator") == [
            ("/Users/alice", "/Users/operator")]

    def test_a_windows_path_has_three_and_they_are_paired(self):
        """The doubled form is what ``json.dumps`` emits, and the replacement
        has to be doubled with it: substituting a single-backslash
        ``C:\\Users\\operator`` into a JSON string produces ``\\U``, which is not
        a valid escape, and the document stops parsing."""
        forms = dict(T._spellings("C:\\Users\\alice", "C:\\Users\\operator"))
        assert forms["C:\\Users\\alice"] == "C:\\Users\\operator"
        assert forms["C:\\\\Users\\\\alice"] == "C:\\\\Users\\\\operator"
        assert forms["C:/Users/alice"] == "C:/Users/operator"

    def test_the_doubled_substitution_leaves_parseable_json(self):
        """The reason the pairing exists, asserted rather than described."""
        blob = json.dumps({"home": "C:\\Users\\alice"})
        forms = dict(T._spellings("C:\\Users\\alice", "C:\\Users\\operator"))
        for form, repl in forms.items():
            if form in blob:
                assert json.loads(blob.replace(form, repl))["home"] == \
                    "C:\\Users\\operator"


# --------------------------------------------------------------------------
# the refusal
# --------------------------------------------------------------------------

class TestRefusal:
    def test_a_survivor_refuses_the_document(self, monkeypatch, fresh_table):
        """Redaction that did not take must raise, not pass the text through.

        A redactor that silently returns unredacted text is worse than none,
        because everything downstream now believes the corpus is clean and the
        place that belief is cashed in is a checkpoint nobody can grep. Forced
        here by giving the substitution a pattern that matches nothing while the
        table still lists the literal.
        """
        if not _identifying_values():
            pytest.skip("this machine has no identifying values to leak")
        secret = T._identity_table()[0][0]
        monkeypatch.setattr(T, "_identity_pattern",
                            lambda: re.compile("(?!x)x"))
        with pytest.raises(RuntimeError, match="survived redaction"):
            T.redact_identity(f'{{"user":"{secret}"}}')

    def test_identity_leaks_reports_then_stops(self, fresh_table):
        """The predicate the corpus builder and the capture writer are meant to
        call before writing anything this machine produced."""
        if not _identifying_values():
            pytest.skip("this machine has no identifying values to leak")
        secret = T._identity_table()[0][0]
        dirty = f'{{"user":"{secret}"}}'
        # ``in`` rather than ``==``: the table holds every spelling, and macOS
        # reports its temp directory both with and without the /private prefix,
        # so one literal legitimately reports two overlapping entries.
        assert secret in T.identity_leaks(dirty)
        assert T.identity_leaks(T.redact_identity(dirty)) == []


# --------------------------------------------------------------------------
# the table itself
# --------------------------------------------------------------------------

class TestTableOrder:
    def test_longer_literals_come_first(self, fresh_table):
        """Alternation in :mod:`re` is leftmost-first, not longest-first.

        If the bare account name preceded the home path, ``/Users/alice/Public``
        would be half-substituted into ``/Users/operator/Public`` by the short
        rule — which happens to be the right answer here and is not in general:
        a home directory that does not contain the account name would be left
        standing. The order is the thing that makes the longest match win.
        """
        lengths = [len(form) for form, _ in T._identity_table()]
        assert lengths == sorted(lengths, reverse=True)

    def test_a_home_path_outranks_the_bare_account_name(self, fresh_table):
        table = [form for form, _ in T._identity_table()]
        home, user = str(Path.home()), getpass.getuser()
        if home not in table or user not in table:
            pytest.skip("this machine's home or account name is not identifying")
        assert table.index(home) < table.index(user)


# --------------------------------------------------------------------------
# the artifacts that are actually published
# --------------------------------------------------------------------------

#: The only account name the committed example runs may name. Everything else a
#: real run observed — ``root``, ``systemd-journal`` — is a system account that
#: names nobody; a human account name in here is the operator's.
_PUBLISHABLE_ACCOUNTS = frozenset({T._OPERATOR})

#: ``/var/folders/<two>/<28 characters>/T`` is macOS's per-user temp directory.
#: The 28-character component is stable for one account on one machine, so it is
#: a machine identifier wearing a path's clothes — and it also gives away that a
#: run labelled ``sandbox-linux`` happened on a Mac.
#:
#: Matched as the real token rather than as the bare ``/var/folders/`` prefix,
#: because the README in that directory has to be able to *describe* the shape
#: in order to explain why it was substituted, and a test that cannot tell the
#: explanation from the leak forbids writing the explanation down.
_PER_USER_TEMP = re.compile(r"/var/folders/[A-Za-z0-9_+-]{2}/[A-Za-z0-9_+-]{10,}")

#: Every home directory spelled in a published artifact, POSIX shapes only,
#: which is what the capture path has ever produced.
_HOME_PATH = re.compile(r"/(?:Users|home)/([A-Za-z0-9._-]+)")

_RUNS = Path(__file__).resolve().parent.parent / "examples" / "runs"


def _published_files() -> list[Path]:
    return sorted(p for p in _RUNS.rglob("*") if p.is_file())


class TestCommittedExampleRuns:
    """``examples/runs/`` is force-included by ``.gitignore`` and pushed to a
    public repository — the one directory in this project whose whole purpose is
    to be read by strangers. These two tests are what stops a re-capture from
    republishing the operator along with the proof of work.
    """

    def test_no_published_artifact_names_a_home_directory_or_temp_token(self):
        """Machine-independent, so it fails on a reviewer's machine too.

        :func:`~training.trajectories.identity_leaks` can only report the values
        of the machine it is asked on, so on any machine but the one that
        captured these runs it answers "clean" about somebody else's username.
        This test asks the question a different way — what *shape* is in the
        file — and therefore holds everywhere.
        """
        for path in _published_files():
            text = path.read_text(encoding="utf-8")
            assert not _PER_USER_TEMP.search(text), (
                f"{path.name} carries a macOS per-user temp path")
            names = set(_HOME_PATH.findall(text)) - _PUBLISHABLE_ACCOUNTS
            assert not names, f"{path.name} names home directories {sorted(names)}"

    def test_no_published_artifact_names_this_machine(self):
        """The other half, and the half that catches an account name.

        Only meaningful on the machine that captured the runs — which is the
        machine a re-capture will happen on, so it is the machine where it
        matters.
        """
        if not _identifying_values():
            pytest.skip("this machine has no identifying values to leak")
        for path in _published_files():
            leaks = T.identity_leaks(path.read_text(encoding="utf-8"))
            assert not leaks, f"{path.name} still carries {leaks!r}"
