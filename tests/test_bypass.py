"""The paths that went around the redaction chokepoint.

``build.py`` redacts on the way out. Everything downstream reads the *finished*
JSONL — ``read_documents`` globs ``*.jsonl``, ``iter_corpus`` walked raw text,
``_interleaved`` seeks by byte offset — so until the gate these tests pin,
nothing between a corpus directory and the weights looked at the text again.
That is the finding with the widest blast radius, because there is an
unredacted corpus on disk to prove it matters: ``corpus/clean/`` carries 5,356
raw identity occurrences, and a tokenizer fitted there keeps them as BPE
merges. A tokenizer.json ships. A checkpoint is not greppable and not
removable.

**Why these tests fabricate their needle.** The real needles are derived from
this machine at runtime, and a test may not write one to disk — that is exactly
the rule the privacy audit broke when six of its own working files wrote live
MAC addresses and global IPv6 addresses as cleartext literals while the report
claimed otherwise. So every value here is invented: an opaque synthetic
identifier, ``2001:db8::`` documentation addresses, reserved MACs,
``example.invalid`` mailboxes. The corpus is *full* of documentation IPs and
example addresses on purpose, so the gate is driven with a value that cannot
collide with either a real identifier or a deliberate fixture.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")

from training import data as D  # noqa: E402

#: A fabricated identifier. Not a real account name, host name, path, address
#: or mailbox — it is a literal nobody's machine can produce, which is the only
#: kind of needle a test file is allowed to contain.
NEEDLE = "synthetic-operator-9f21c4"

#: A second one, so a test can change the leak set and watch a token expire.
NEEDLE2 = "synthetic-operator-0e55ab"


@pytest.fixture(autouse=True)
def _clear_gate_state():
    """The gate's memo is per process, so a test must not inherit one.

    It is keyed on the cheap stat signature as a *cache*, never as the
    authority — the authority is the content digest. Clearing it here keeps
    that distinction from quietly making a test pass.
    """
    D._GATE_MEMO.clear()
    D._WARNED.clear()
    yield
    D._GATE_MEMO.clear()
    D._WARNED.clear()


@pytest.fixture()
def verify():
    """Agent C's artifact verifier.

    Skipped rather than stubbed when it is absent: the point of the gate is
    that it fails closed without a verifier, and
    :class:`TestTheGateFailsClosed` pins that case directly.
    """
    try:
        return importlib.import_module("training.corpus.verify")
    except Exception as exc:                       # pragma: no cover - absent
        pytest.skip(f"training/corpus/verify.py not importable: {exc!r}")


#: Fabricated values that make :func:`verify.Needles.gaps` empty, so the gate's
#: own blindness check is *satisfied* rather than switched off. Each is chosen
#: not to collide with anything the fixtures below write: the clean corpus
#: carries ``00:11:22:33:44:55`` and ``2001:db8::1`` on purpose, because this
#: corpus is full of documentation values and a gate that flagged them would
#: bury every real finding.
SYNTHETIC = {
    "identity": (NEEDLE, NEEDLE2),
    "mac": ("00:11:22:33:44:66",),
    "ipv4": ("10.255.255.254",),
    "volumes": ("SyntheticVolume9f21",),
    "probes": ("account", "hostname", "volumes", "network", "mac"),
}


@pytest.fixture()
def scanner(verify, monkeypatch):
    """Make the real verifier hunt for :data:`NEEDLE` instead of a real value.

    ``host_needles`` is substituted with a table built from fabricated values
    through the verifier's own :meth:`Needles.from_values`, which exists for
    exactly this — "tests, which must use fabricated values". Everything else
    is the shipped code: the real ``verify_corpus``, the real ``scan_text``,
    the real gate. What is fake is the needle, never the plumbing.

    It has to be this way round. The real needles are derived from this
    machine, and no test may write one into a fixture — that is the rule the
    privacy audit itself broke. And every value a test *is* allowed to write is
    a value a calibrated verifier must deliberately not flag.
    """
    table = verify.Needles.from_values(
        identity=SYNTHETIC["identity"], mac=SYNTHETIC["mac"],
        ipv4=SYNTHETIC["ipv4"], volumes=SYNTHETIC["volumes"],
        probes=SYNTHETIC["probes"])
    assert table.gaps() == (), (
        "the synthetic table must satisfy the coverage check, not dodge it")
    monkeypatch.setattr(verify, "host_needles", lambda **_k: table)
    return table


@pytest.fixture()
def blind_scanner(verify, monkeypatch):
    """A table the verifier itself reports as thin."""
    table = verify.Needles.from_values(identity=SYNTHETIC["identity"])
    assert table.gaps(), "this fixture is only interesting while it is blind"
    monkeypatch.setattr(verify, "host_needles", lambda **_k: table)
    return table


def _reads_the_environment(path: Path) -> list[str]:
    """Names in ``path`` that read the process environment.

    Parsed rather than grepped. A substring search over this project's source
    reports every docstring that *discusses* environment variables, which is
    the measurement bug this codebase keeps relearning: the first three times
    something here accused the model, the fault was in the ruler.
    """
    import ast

    found = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Attribute) and node.attr in {
                "environ", "environb", "getenv"}:
            found.append(f"line {node.lineno}: .{node.attr}")
        elif isinstance(node, ast.Name) and node.id in {"getenv", "environ"}:
            found.append(f"line {node.lineno}: {node.id}")
    return found


def _built(directory: Path, texts, *, name: str = "synth", idents=None) -> Path:
    """Write a built-corpus directory in ``build.py``'s own schema."""
    directory.mkdir(parents=True, exist_ok=True)
    rows = []
    for i, text in enumerate(texts):
        rows.append(json.dumps({
            "text": text, "source": name, "register": "prose",
            "side": "neutral",
            "ident": (idents[i] if idents else f"doc-{i}"),
        }))
    (directory / f"{name}.jsonl").write_text("\n".join(rows) + "\n",
                                             encoding="utf-8")
    return directory


def _clean_corpus(directory: Path) -> Path:
    return _built(directory, [
        "tcp 0 0 0.0.0.0:445 0.0.0.0:* LISTEN",
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "ping 2001:db8::1 from 00:11:22:33:44:55",
        "mail someone@example.invalid about CVE-2024-21412",
    ])


def _leaking_corpus(directory: Path) -> Path:
    return _built(directory, [
        "systemctl list-unit-files --type=service",
        f"captured on /Users/{NEEDLE}/Project/Whetstone with no redaction",
    ])


# ─────────────────────────────────────────────────────────────────────────────


class TestTheTokenizerRefusesALeakingCorpus:
    """``--clean`` is how the shipped tokenizer is fitted. It had no gate."""

    def test_iter_corpus_refuses_a_built_corpus(self, scanner, tmp_path):
        from training.tokenizer import train_tokenizer as tt

        clean = _leaking_corpus(tmp_path / "corpus")
        with pytest.raises(D.CorpusLeakError) as caught:
            list(tt.iter_corpus([clean]))
        assert caught.value.leaks, "the refusal must carry what it found"

    def test_iter_split_refuses(self, scanner, tmp_path):
        from training.tokenizer import train_tokenizer as tt

        clean = _leaking_corpus(tmp_path / "corpus")
        with pytest.raises(D.CorpusLeakError):
            list(tt.iter_split(clean, holdout=False))

    def test_train_refuses_before_it_fits_anything(self, scanner, tmp_path):
        pytest.importorskip("tokenizers")
        from training.tokenizer import train_tokenizer as tt

        clean = _leaking_corpus(tmp_path / "corpus")
        out = tmp_path / "tokenizer"
        with pytest.raises(D.CorpusLeakError):
            tt.train([clean], out)
        assert not (out / "tokenizer.json").exists(), (
            "a refused corpus must not leave a tokenizer behind")

    def test_a_clean_corpus_is_read_normally(self, scanner, tmp_path):
        from training.tokenizer import train_tokenizer as tt

        clean = _clean_corpus(tmp_path / "corpus")
        assert len(list(tt.iter_corpus([clean]))) == 4

    def test_the_raw_text_path_is_scanned_too(self, scanner, tmp_path):
        """The raw path is *by definition* material no chokepoint has seen.

        It exists so a new source can be smoke-tested before it has an
        adapter, which is precisely why it cannot be the one reader that
        checks nothing.
        """
        from training.tokenizer import train_tokenizer as tt

        raw = tmp_path / "raw"
        (raw / "nested").mkdir(parents=True)
        (raw / "a.txt").write_text("harmless shell transcript\n",
                                   encoding="utf-8")
        (raw / "nested" / "b.txt").write_text(
            f"/Users/{NEEDLE}/notes.txt\n", encoding="utf-8")
        with pytest.raises(D.CorpusLeakError):
            list(tt.iter_corpus([raw]))

    def test_the_raw_walk_does_not_follow_a_symlink(self, scanner, tmp_path):
        """``rglob`` followed symlinks. This repo has ``data`` -> the SSD.

        ``iter_corpus([Path('.')])`` walked straight into it and could pull the
        corpus cache back in as prose — the same door through which ``ownrepos``
        once made the corpus eat itself.
        """
        from training.tokenizer import train_tokenizer as tt

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "cache.txt").write_text("not corpus\n", encoding="utf-8")
        raw = tmp_path / "raw"
        raw.mkdir()
        (raw / "real.txt").write_text("the only document\n", encoding="utf-8")
        (raw / "link").symlink_to(elsewhere)
        (raw / "linked.txt").symlink_to(elsewhere / "cache.txt")

        assert list(tt.iter_corpus([raw])) == ["the only document\n"]

    def test_the_cli_refuses_before_it_spends_anything(self, scanner, tmp_path,
                                                       monkeypatch):
        """Refuse early and refuse cheaply.

        The readers below the CLI all gate themselves, so this is not where the
        guarantee lives — but a refusal should arrive before a vocabulary has
        been allocated and before gpt2 has been fetched over the network for a
        comparison that is not going to happen.
        """
        pytest.importorskip("tokenizers")
        from training.tokenizer import train_tokenizer as tt

        def _never(*_a, **_k):
            raise AssertionError("built a tokenizer for a refused corpus")

        monkeypatch.setattr(tt, "build_tokenizer", _never)
        monkeypatch.setattr(tt, "compare", _never)
        clean = _leaking_corpus(tmp_path / "corpus")
        assert tt.main(["--clean", str(clean),
                        "--out", str(tmp_path / "tok")]) == 2

    def test_the_cli_reports_the_refusal_and_exits_2(self, scanner, tmp_path,
                                                     capsys):
        pytest.importorskip("tokenizers")
        from training.tokenizer import train_tokenizer as tt

        clean = _leaking_corpus(tmp_path / "corpus")
        rc = tt.main(["--clean", str(clean), "--out", str(tmp_path / "tok")])
        assert rc == 2
        err = capsys.readouterr().err
        assert "REFUSING TO READ THIS CORPUS" in err
        assert "--accept-leaking-corpus" in err
        assert NEEDLE not in err, "a refusal must never print the value"


class TestTheLoaderRefusesALeakingCorpus:
    """``_interleaved`` is the only thing in data.py that opens a corpus."""

    def test_interleaved_refuses(self, scanner, tmp_path):
        clean = _leaking_corpus(tmp_path / "corpus")
        with pytest.raises(D.CorpusLeakError):
            list(D._interleaved([clean], seed=1))

    def test_tokenize_corpus_refuses_before_it_loads_the_tokenizer(
            self, scanner, tmp_path):
        """The gate runs first, which is why a missing tokenizer never surfaces."""
        pytest.importorskip("tokenizers")
        clean = _leaking_corpus(tmp_path / "corpus")
        with pytest.raises(D.CorpusLeakError):
            D.tokenize_corpus([clean], tmp_path / "nonexistent.json",
                              tmp_path / "shards")
        assert not (tmp_path / "shards").exists()

    def test_a_clean_corpus_interleaves_normally(self, scanner, tmp_path):
        clean = _clean_corpus(tmp_path / "corpus")
        assert len(list(D._interleaved([clean], seed=1))) == 4

    def test_an_ident_only_leak_is_refused(self, scanner, tmp_path):
        """``_redacted`` redacts ``doc.text`` only; ``doc.ident`` is written raw.

        Several adapters build ``ident`` from a filesystem path, so the field
        the chokepoint never touched is the field a scan has to cover.
        """
        clean = _built(tmp_path / "corpus", ["a harmless document"],
                       idents=[f"/Users/{NEEDLE}/repo__README.md"])
        with pytest.raises(D.CorpusLeakError):
            list(D._interleaved([clean], seed=1))


class TestTheOverride:
    """One explicit, loud, non-default way past — and no other."""

    def _token(self, directory) -> str:
        try:
            D.require_clean_corpus([directory])
        except D.CorpusLeakError as exc:
            return exc.token
        raise AssertionError("expected a refusal")

    def test_the_token_lets_it_through_and_says_what_it_permits(
            self, scanner, tmp_path, capsys):
        clean = _leaking_corpus(tmp_path / "corpus")
        token = self._token(clean)
        D._GATE_MEMO.clear()

        records = D.require_clean_corpus([clean],
                                         accept_leaking_corpus=token)
        err = capsys.readouterr().err
        assert "PERMITTING A LEAKING CORPUS" in err
        assert token in err
        assert "by kind:" in err and "by file:" in err
        assert NEEDLE not in err
        assert records[0].verified is False
        assert records[0].accepted_leaks >= 1

    def test_the_default_is_refusal(self, scanner, tmp_path):
        """No argument, no permission. The hatch cannot open by omission."""
        clean = _leaking_corpus(tmp_path / "corpus")
        with pytest.raises(D.CorpusLeakError):
            D.require_clean_corpus([clean])

    def test_a_wrong_token_is_refused_and_named_as_stale(self, scanner,
                                                         tmp_path):
        clean = _leaking_corpus(tmp_path / "corpus")
        with pytest.raises(D.CorpusLeakError) as caught:
            D.require_clean_corpus([clean],
                                   accept_leaking_corpus="deadbeefcafe")
        assert "does not match" in str(caught.value)

    def test_the_token_expires_when_the_corpus_changes(self, scanner, tmp_path):
        """So it cannot be parked in overnight.sh and keep permitting things."""
        clean = _leaking_corpus(tmp_path / "corpus")
        token = self._token(clean)
        D._GATE_MEMO.clear()
        D.require_clean_corpus([clean], accept_leaking_corpus=token)

        _built(clean, ["one document", f"and a second {NEEDLE2} leak"])
        D._GATE_MEMO.clear()
        with pytest.raises(D.CorpusLeakError) as caught:
            D.require_clean_corpus([clean], accept_leaking_corpus=token)
        assert caught.value.token != token

    def test_no_environment_variable_can_open_the_gate(self, scanner, tmp_path,
                                                       monkeypatch):
        clean = _leaking_corpus(tmp_path / "corpus")
        token = self._token(clean)
        D._GATE_MEMO.clear()
        for name in ("ACCEPT_LEAKING_CORPUS", "WHETSTONE_ACCEPT_LEAKING_CORPUS",
                     "WHETSTONE_ACCEPT", "WHETSTONE_FORCE", "FORCE",
                     "WHETSTONE_UNSAFE", "UNSAFE", "WHETSTONE_SKIP_VERIFY",
                     "SKIP_VERIFY", "WHETSTONE_NO_VERIFY"):
            monkeypatch.setenv(name, token)
        with pytest.raises(D.CorpusLeakError):
            D.require_clean_corpus([clean])

    def test_the_gate_reads_no_environment_at_all(self):
        """Structural, because the test above can only try names it thought of."""
        from training.tokenizer import train_tokenizer as tt

        for module in (D, tt):
            reads = _reads_the_environment(Path(module.__file__))
            assert not reads, (
                f"{module.__name__} reads the environment at {reads} — the "
                f"override must not be reachable from an env var")

    def test_it_is_not_called_force(self):
        pytest.importorskip("tokenizers")
        from training.tokenizer import train_tokenizer as tt

        with pytest.raises(SystemExit):
            tt._main(["--force", "--clean", "/nonexistent"])

    def test_the_flags_default_is_none(self):
        pytest.importorskip("tokenizers")
        import inspect

        from training.tokenizer import train_tokenizer as tt

        for func, name in ((D.require_clean_corpus, "accept_leaking_corpus"),
                           (D.tokenize_corpus, "accept_leaking_corpus"),
                           (D._interleaved, "accept_leaking_corpus"),
                           (tt.iter_corpus, "accept_leaking_corpus"),
                           (tt.iter_split, "accept_leaking_corpus"),
                           (tt.train, "accept_leaking_corpus"),
                           (D.Dataset.__init__, "accept_leaking_shards")):
            default = inspect.signature(func).parameters[name].default
            assert default is None, f"{func.__qualname__}({name}=) defaults on"

    def test_a_truthy_value_is_not_a_permission(self, scanner, tmp_path):
        """A flag that takes a token cannot be flipped on by a stray ``True``."""
        clean = _leaking_corpus(tmp_path / "corpus")
        for truthy in (True, 1, "yes", "true", "1", "force"):
            D._GATE_MEMO.clear()
            with pytest.raises(D.CorpusLeakError):
                D.require_clean_corpus([clean], accept_leaking_corpus=truthy)

    def test_the_gate_has_no_needles_parameter(self):
        """An empty needle table would verify every corpus and stamp it clean."""
        import inspect

        assert "needles" not in inspect.signature(
            D.require_clean_corpus).parameters


class TestTheStamp:
    """Cheap re-confirmation, or the gate gets patched out.

    Measured here against ``corpus/clean-v7``: a full verify pass costs 23.6 s
    and hashing every byte costs 0.50 s. A gate that charges 24 s to every
    tokenizer start, every shard build and every smoke test is a gate somebody
    deletes.
    """

    def test_a_clean_corpus_is_stamped_and_not_rescanned(self, scanner, verify,
                                                         tmp_path, monkeypatch):
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        assert (clean / D.STAMP_NAME).is_file()

        calls = []
        original = verify.verify_corpus
        monkeypatch.setattr(verify, "verify_corpus",
                            lambda *a, **k: calls.append(1) or original(*a, **k))
        D._GATE_MEMO.clear()
        records = D.require_clean_corpus([clean])
        assert not calls, "a valid stamp must answer without a rescan"
        assert records[0].from_stamp is True

    def test_an_equal_length_edit_invalidates_the_stamp(self, scanner,
                                                        tmp_path):
        """Why the stamp hashes content and not name-and-size.

        The most likely edit to a corpus file here is a redaction, and
        substituting a placeholder of the same length leaves every byte count
        untouched. ``corpus_identity``'s one-stat-per-file digest would call
        this corpus unchanged and skip the scan — wrong in the only direction
        that matters.
        """
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        path = clean / "synth.jsonl"
        before = path.stat().st_size

        rows = path.read_text(encoding="utf-8").splitlines()
        row = json.loads(rows[0])
        row["text"] = f"x {NEEDLE}"
        rewritten = json.dumps(row)
        pad = len(rows[0]) - len(rewritten)
        row["text"] = f"x {NEEDLE}" + (" " * pad if pad > 0 else "")
        rows[0] = json.dumps(row)[:len(rows[0])].ljust(len(rows[0]))
        path.write_text("\n".join(rows) + "\n", encoding="utf-8")
        assert path.stat().st_size == before, "the fixture must preserve size"

        D._GATE_MEMO.clear()
        with pytest.raises(D.CorpusLeakError):
            D.require_clean_corpus([clean])

    def test_a_stamp_whose_digest_disagrees_counts_as_absent(self, scanner,
                                                             tmp_path):
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        stamp_path = clean / D.STAMP_NAME
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        stamp["digest"] = "0" * 16
        stamp_path.write_text(json.dumps(stamp), encoding="utf-8")

        D._GATE_MEMO.clear()
        records = D.require_clean_corpus([clean])
        assert records[0].from_stamp is False, (
            "a stamp that does not describe these files must be ignored")

    def test_a_stamp_claiming_other_files_counts_as_absent(self, scanner,
                                                           tmp_path):
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        stamp_path = clean / D.STAMP_NAME
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        stamp["files"][0]["bytes"] += 1
        stamp_path.write_text(json.dumps(stamp), encoding="utf-8")

        D._GATE_MEMO.clear()
        assert D.require_clean_corpus([clean])[0].from_stamp is False

    def test_a_stamp_from_another_verifier_build_counts_as_absent(
            self, scanner, tmp_path):
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        stamp_path = clean / D.STAMP_NAME
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        stamp["verifier"]["contract"] = "f" * 16
        stamp_path.write_text(json.dumps(stamp), encoding="utf-8")

        D._GATE_MEMO.clear()
        assert D.require_clean_corpus([clean])[0].from_stamp is False

    def test_a_stamp_covering_fewer_kinds_counts_as_absent(self, scanner,
                                                           tmp_path):
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        stamp_path = clean / D.STAMP_NAME
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        stamp["verifier"]["kinds"] = stamp["verifier"]["kinds"][:1]
        stamp_path.write_text(json.dumps(stamp), encoding="utf-8")

        D._GATE_MEMO.clear()
        assert D.require_clean_corpus([clean])[0].from_stamp is False

    def test_a_changed_needle_table_invalidates_the_stamp(self, verify,
                                                          scanner, tmp_path,
                                                          monkeypatch):
        """A stamp is a claim about what was checked; the table is half of it.

        Mount a volume, renew an address, add an account, and yesterday's clean
        answer was produced against a table that did not contain today's
        needles. The stamp records one digest over the verifier's own
        fingerprints — no value, not even a per-value hash — so that change is
        noticed without anything being written down.
        """
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        D._GATE_MEMO.clear()
        assert D.require_clean_corpus([clean])[0].from_stamp is True

        wider = verify.Needles.from_values(
            identity=SYNTHETIC["identity"] + ("synthetic-operator-later",),
            mac=SYNTHETIC["mac"], ipv4=SYNTHETIC["ipv4"],
            volumes=SYNTHETIC["volumes"], probes=SYNTHETIC["probes"])
        monkeypatch.setattr(verify, "host_needles", lambda **_k: wider)
        D._GATE_MEMO.clear()
        assert D.require_clean_corpus([clean])[0].from_stamp is False

    def test_a_stamp_from_a_wider_verifier_still_counts(self, scanner,
                                                        tmp_path):
        """Superset, not equality — and the asymmetry is the point.

        A stamp written where the verifier could see *more* than it can see
        here still vouches for these bytes. The other direction does not, which
        is why a blind run never writes one.
        """
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        stamp_path = clean / D.STAMP_NAME
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        stamp["verifier"]["kinds"] = sorted(
            set(stamp["verifier"]["kinds"]) | {"future-kind"})
        stamp_path.write_text(json.dumps(stamp), encoding="utf-8")

        D._GATE_MEMO.clear()
        assert D.require_clean_corpus([clean])[0].from_stamp is True

    def test_an_unparseable_stamp_counts_as_absent(self, scanner, tmp_path):
        clean = _clean_corpus(tmp_path / "corpus")
        (clean / D.STAMP_NAME).write_text("{not json", encoding="utf-8")
        assert D.require_clean_corpus([clean])[0].from_stamp is False

    def test_a_stamp_claiming_leaks_counts_as_absent(self, scanner, tmp_path):
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        stamp_path = clean / D.STAMP_NAME
        stamp = json.loads(stamp_path.read_text(encoding="utf-8"))
        stamp["leaks"] = 3
        stamp_path.write_text(json.dumps(stamp), encoding="utf-8")

        D._GATE_MEMO.clear()
        assert D.require_clean_corpus([clean])[0].from_stamp is False

    def test_a_leaking_corpus_is_never_stamped(self, scanner, tmp_path):
        clean = _leaking_corpus(tmp_path / "corpus")
        token = None
        try:
            D.require_clean_corpus([clean])
        except D.CorpusLeakError as exc:
            token = exc.token
        assert not (clean / D.STAMP_NAME).exists()

        D._GATE_MEMO.clear()
        D.require_clean_corpus([clean], accept_leaking_corpus=token)
        assert not (clean / D.STAMP_NAME).exists(), (
            "permission is per invocation; a stamp would make it permanent")

    def test_the_stamp_holds_no_path_and_no_needle(self, scanner, tmp_path):
        """The audit that found these leaks created one by writing its needles.

        So: basenames, byte counts, digests, the verifier's contract and the
        kind names. No value, no path — the volume's own name is itself one of
        the kinds the verifier hunts for.
        """
        clean = _clean_corpus(tmp_path / "corpus")
        D.require_clean_corpus([clean])
        text = (clean / D.STAMP_NAME).read_text(encoding="utf-8")

        assert NEEDLE not in text and NEEDLE2 not in text
        assert str(tmp_path) not in text
        assert str(Path.home()) not in text
        stamp = json.loads(text)
        for entry in stamp["files"]:
            assert "/" not in entry["name"]
        assert "2001:db8::1" not in text, "no document content either"

    def test_the_raw_path_never_ingests_the_stamp(self, scanner, tmp_path):
        from training.tokenizer import train_tokenizer as tt

        raw = tmp_path / "raw"
        raw.mkdir()
        (raw / "a.txt").write_text("the only document\n", encoding="utf-8")
        (raw / D.STAMP_NAME).write_text('{"stamp": 1}\n', encoding="utf-8")
        assert list(tt.iter_corpus([raw])) == ["the only document\n"]


class TestTheGateFailsClosed:
    """"I could not check" must never mean "carry on".

    ``redact_identity`` opens with ``pattern = _identity_pattern(); if pattern
    is None: return text`` — so a build whose identity table comes back empty,
    which is what happens in a container or a CI image, returns Mac-captured
    text unchanged and silently. One analyst declined that path as unreachable
    and a verifier proved it reachable. The same shape of hole one layer up
    would be a gate that waves a corpus through when the verifier is missing.
    """

    def test_a_clean_answer_from_a_blind_table_is_refused(
            self, blind_scanner, tmp_path):
        """``verify_corpus`` returns ``[]`` for an empty table.

        So "no leaks" from a thin table says only that nothing was looked for,
        and the verifier publishes ``Needles.gaps()`` precisely so a caller can
        tell the two apart. A gate that cannot tell them apart is the
        ``if pattern is None: return text`` bug wearing a verifier.
        """
        clean = _clean_corpus(tmp_path / "corpus")
        with pytest.raises(D.CorpusUnverifiable) as caught:
            D.require_clean_corpus([clean])
        assert "blind to" in str(caught.value)
        assert not (clean / D.STAMP_NAME).exists(), (
            "a stamp here would make a blind answer permanent")

    def test_blindness_has_no_override(self, blind_scanner, tmp_path):
        """Unlike a leak, there is nothing here to acknowledge.

        The leak refusal can name what it found and hand over a token for it.
        This one cannot name anything, which is exactly why it does not get an
        escape hatch.
        """
        clean = _clean_corpus(tmp_path / "corpus")
        for attempt in ("", "deadbeefcafe", "yes", str(True)):
            D._GATE_MEMO.clear()
            with pytest.raises(D.CorpusUnverifiable):
                D.require_clean_corpus([clean],
                                       accept_leaking_corpus=attempt)

    def test_a_leak_outranks_blindness(self, blind_scanner, tmp_path):
        """A thin table that *did* find something gets the actionable refusal."""
        clean = _leaking_corpus(tmp_path / "corpus")
        with pytest.raises(D.CorpusLeakError) as caught:
            D.require_clean_corpus([clean])
        assert caught.value.token

    def test_a_missing_verifier_refuses(self, tmp_path, monkeypatch):
        import sys

        monkeypatch.setitem(sys.modules, "training.corpus.verify", None)
        with pytest.raises(D.CorpusUnverifiable):
            D.require_clean_corpus([_clean_corpus(tmp_path / "corpus")])

    def test_a_verifier_missing_a_pinned_function_refuses(self, tmp_path,
                                                          monkeypatch):
        import sys
        import types

        stub = types.ModuleType("training.corpus.verify")
        stub.verify_corpus = lambda *a, **k: []       # and nothing else
        monkeypatch.setitem(sys.modules, "training.corpus.verify", stub)
        with pytest.raises(D.CorpusUnverifiable) as caught:
            D.require_clean_corpus([_clean_corpus(tmp_path / "corpus")])
        for name in ("scan_text", "host_needles", "render"):
            assert name in str(caught.value)

    def test_an_empty_corpus_still_needs_a_verifier(self, tmp_path, monkeypatch):
        """There is nothing to find in an empty directory, and it still asks.

        A gate that answers "clean" before it has checked whether it *can*
        check is a gate whose clean answer means nothing.
        """
        import sys

        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setitem(sys.modules, "training.corpus.verify", None)
        with pytest.raises(D.CorpusUnverifiable):
            D.require_clean_corpus([empty])


class TestProvenanceRecordsWhatWasRead:
    """``clean-v8`` is a symlink to ``clean-v7``.

    So "v8 was verified" is a statement about v7's bytes, and every tokenizer
    and shard set filed under v8 inherits the mistake. A loader that reports it
    trained on v8 when it read v7 is lying about provenance, and provenance is
    the one thing a published checkpoint cannot be re-derived from.
    """

    def _linked(self, tmp_path):
        real = _clean_corpus(tmp_path / "clean-v7")
        link = tmp_path / "clean-v8"
        link.symlink_to(real, target_is_directory=True)
        return real, link

    def test_the_resolved_name_is_what_is_recorded(self, scanner, tmp_path):
        real, link = self._linked(tmp_path)
        record = D.require_clean_corpus([link])[0]
        assert record.given.name == "clean-v8"
        assert record.resolved.name == "clean-v7"
        assert record.redirected is True
        assert record.as_record()["resolved"] == "clean-v7"
        assert record.as_record()["given"] == "clean-v8"

    def test_a_real_directory_is_not_reported_as_redirected(self, scanner,
                                                            tmp_path):
        real, _link = self._linked(tmp_path)
        assert D.require_clean_corpus([real])[0].redirected is False

    def test_the_record_written_to_disk_holds_no_path(self, scanner, tmp_path):
        _real, link = self._linked(tmp_path)
        record = D.require_clean_corpus([link])[0].as_record()
        blob = json.dumps(record)
        assert str(tmp_path) not in blob
        assert "/" not in blob.replace("\\/", ""), (
            "basenames and digests only — the volume name is a needle kind")

    def test_the_repr_does_not_reveal_a_path(self, scanner, tmp_path):
        _real, link = self._linked(tmp_path)
        text = repr(D.require_clean_corpus([link])[0])
        assert str(tmp_path) not in text
        assert "clean-v8" in text and "clean-v7" in text

    def test_the_shard_index_carries_it(self, scanner, tmp_path):
        _real, link = self._linked(tmp_path)
        record = D.require_clean_corpus([link])[0]
        root = tmp_path / "tokenized-v8"
        root.mkdir()
        (root / "shard-0000.bin").write_bytes(
            np.arange(1, 4097, dtype=D.TOKEN_DTYPE).tobytes())
        D.ShardIndex(root=root, shards=[{"file": "shard-0000.bin",
                                         "tokens": 4096}],
                     total_tokens=4096, documents=4, vocab_size=16384,
                     corpus=[record.as_record()]).save()

        reloaded = D.ShardIndex.load(root)
        assert reloaded.corpus[0]["resolved"] == "clean-v7"
        report = reloaded.provenance_report()
        assert "SYMLINK" in report and "clean-v7" in report

    def test_a_shard_set_without_the_record_says_so(self, tmp_path, capsys):
        root = tmp_path / "tokenized"
        root.mkdir()
        (root / "shard-0000.bin").write_bytes(
            np.arange(1, 4097, dtype=D.TOKEN_DTYPE).tobytes())
        D.ShardIndex(root=root, shards=[{"file": "shard-0000.bin",
                                         "tokens": 4096}],
                     total_tokens=4096, documents=4, vocab_size=16384).save()

        D.Dataset(root, 64, split="train", seed=1, val_fraction=0.2)
        assert "no corpus provenance" in capsys.readouterr().err
        assert "no corpus provenance" in D.ShardIndex.load(
            root).provenance_report()

    def test_the_tokenizer_meta_records_the_resolved_name(self, tmp_path):
        pytest.importorskip("tokenizers")
        from training.tokenizer import train_tokenizer as tt

        real, link = self._linked(tmp_path)
        record = tt.corpus_record(link)
        assert record["given"] == "clean-v8"
        assert record["resolved"] == "clean-v7"
        assert record["symlink"] is True
        assert record["identity"] == tt.corpus_identity(real)
        assert str(tmp_path) not in json.dumps(record)


class TestShardsCannotLaunderThePermission:
    """Tokenise once with the override and every later run reads ``*.bin``."""

    def _shards(self, tmp_path, *, corpus):
        root = tmp_path / "tokenized"
        root.mkdir()
        (root / "shard-0000.bin").write_bytes(
            np.arange(1, 4097, dtype=D.TOKEN_DTYPE).tobytes())
        D.ShardIndex(root=root, shards=[{"file": "shard-0000.bin",
                                         "tokens": 4096}],
                     total_tokens=4096, documents=4, vocab_size=16384,
                     corpus=corpus).save()
        return root

    def _leaking_record(self):
        return [{"given": "clean", "resolved": "clean", "location": "0" * 12,
                 "files": 1, "bytes": 10, "digest": "a" * 16,
                 "kinds": ["identity"], "verifier": "b" * 16,
                 "verified": False, "accepted_leaks": 5356,
                 "token": "abc123def456"}]

    def test_the_loader_refuses_them(self, tmp_path):
        root = self._shards(tmp_path, corpus=self._leaking_record())
        with pytest.raises(D.CorpusLeakError) as caught:
            D.Dataset(root, 64, split="train", seed=1, val_fraction=0.2)
        assert "abc123def456" in str(caught.value)
        assert "5,356" in str(caught.value)

    def test_restating_the_permission_works_and_is_loud(self, tmp_path,
                                                        capsys):
        root = self._shards(tmp_path, corpus=self._leaking_record())
        D.Dataset(root, 64, split="train", seed=1, val_fraction=0.2,
                  accept_leaking_shards="abc123def456")
        err = capsys.readouterr().err
        assert "LEAKING CORPUS" in err and "in the weights" in err

    def test_a_wrong_token_does_not(self, tmp_path):
        root = self._shards(tmp_path, corpus=self._leaking_record())
        with pytest.raises(D.CorpusLeakError):
            D.Dataset(root, 64, split="train", seed=1, val_fraction=0.2,
                      accept_leaking_shards="not-the-token")

    def test_verified_shards_load_silently(self, tmp_path, capsys):
        record = self._leaking_record()
        record[0].update(verified=True, accepted_leaks=0, token="")
        root = self._shards(tmp_path, corpus=record)
        D.Dataset(root, 64, split="train", seed=1, val_fraction=0.2)
        assert capsys.readouterr().err == ""


class TestSamplingIsAPureFunctionOfSeedAndDraw:
    """The ROADMAP's first training bug, re-verified rather than assumed.

    A run resumed at step 1,000 re-served the batches steps 0-1,000 had already
    seen, and nothing raised: re-learning old data *does* lower loss, so the
    curve looked healthy the whole way. The fix is that a draw is derived from
    ``(seed, draw_index)`` and from nothing else — no long-lived generator
    state, so ``seek`` is exact from any step rather than approximate.
    """

    def _shards(self, tmp_path):
        root = tmp_path / "tokenized"
        root.mkdir()
        value = 1
        meta = []
        for i in range(3):
            np.arange(value, value + 4096, dtype=D.TOKEN_DTYPE).tofile(
                root / f"shard-{i:04d}.bin")
            meta.append({"file": f"shard-{i:04d}.bin", "tokens": 4096})
            value += 4096
        D.ShardIndex(root=root, shards=meta, total_tokens=3 * 4096,
                     documents=3, vocab_size=16384).save()
        return root

    def test_a_draw_depends_on_its_index_not_on_the_history(self, tmp_path):
        root = self._shards(tmp_path)
        walked = D.Dataset(root, 64, split="train", seed=7)
        for _ in range(5):
            walked.batch(2)
        walked.seek(2)
        after_history = walked.batch(2)[0]

        fresh = D.Dataset(root, 64, split="train", seed=7)
        fresh.seek(2)
        assert np.array_equal(fresh.batch(2)[0], after_history), (
            "draw 2 must be draw 2 regardless of what was served before it")

    def test_seek_reproduces_a_midstream_position_exactly(self, tmp_path):
        root = self._shards(tmp_path)
        uninterrupted = [D.Dataset(root, 64, split="train", seed=7)]
        served = [uninterrupted[0].batch(3)[0] for _ in range(8)]

        resumed = D.Dataset(root, 64, split="train", seed=7)
        resumed.seek(5)
        for expected in served[5:]:
            assert np.array_equal(resumed.batch(3)[0], expected)
        assert resumed.draw == 8

    def test_rewinding_replays_byte_for_byte(self, tmp_path):
        root = self._shards(tmp_path)
        data = D.Dataset(root, 64, split="train", seed=7)
        first = [data.batch(2)[0] for _ in range(3)]
        data.seek(0)
        again = [data.batch(2)[0] for _ in range(3)]
        for a, b in zip(first, again):
            assert np.array_equal(a, b)

    def test_the_val_split_is_sampled_independently(self, tmp_path):
        """A shared generator would couple evaluation to training position."""
        root = self._shards(tmp_path)
        train = D.Dataset(root, 64, split="train", seed=7, val_fraction=0.2)
        val = D.Dataset(root, 64, split="val", seed=7, val_fraction=0.2)
        before = val.batch(2)[0]
        for _ in range(4):
            train.batch(2)
        val.seek(0)
        assert np.array_equal(val.batch(2)[0], before)
