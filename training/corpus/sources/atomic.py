"""Atomic Red Team — real attack commands welded to the ATT&CK id that names them.

This is the source the corpus measurement in ``source.py`` was asking for. The
tokenizer lost 45% on ``T1547.001 Registry Run Keys`` because the corpus was
Python, C and Markdown: it had never met an ATT&CK identifier. It also lost on
shell, which is the register the model must *both* emit and read back.

Atomic Red Team is the rare source that is all three at once — every atomic test
is a shell command (``powershell`` / ``command_prompt`` / ``sh`` / ``bash``),
every one is red-side procedure rather than description, and every one sits
under a ``T####[.###]`` technique id. Nothing else in the corpus puts the id and
the command in the same 400 characters.

Two choices drive the whole adapter, and both follow from that:

**One document per atomic test, not per technique file.** A per-file document
would print ``T1003.001`` once at the top and then thirty commands below it; the
id would co-occur with the first command and be a thousand tokens away from the
last. Per-atomic, the id is re-stated next to *every* command it labels. 344
files become 1,862 documents and the identifier density goes up by roughly the
same factor — which is the entire reason this source is here.

**Everything around the command comes too.** The description says what the
command does, ``input_arguments`` carries the registry paths and file paths the
command interpolates, and ``dependencies`` carries a second layer of real shell
(``prereq_command`` / ``get_prereq_command``). Emitting the bare command would
throw away the prose-to-command binding that makes this source teach anything.

Upstream: https://github.com/redcanaryco/atomic-red-team (MIT, Red Canary Inc.)
"""

from __future__ import annotations

import json
import re
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from training.corpus import net
from training.corpus.source import (
    Document,
    Register,
    Side,
    SourceError,
    SourceSpec,
    normalise,
)

__all__ = ["SPEC"]

#: codeload serves the branch tarball directly — no git, no history, one request.
#: The repository is ~167 MB because of documentation images; we keep none of it.
_TARBALL = "https://codeload.github.com/redcanaryco/atomic-red-team/tar.gz/refs/heads/master"
_REPO = "https://github.com/redcanaryco/atomic-red-team"

#: Members worth extracting: ``<root>/atomics/T1003.001/T1003.001.yaml``. The
#: repository also holds per-technique Markdown, payload binaries and test
#: fixtures under the same tree; the YAML is the machine-readable original and
#: the Markdown is generated from it, so taking both would be self-duplication.
_MEMBER = re.compile(r"^[^/]+/atomics/(T\d{4}(?:\.\d{3})?)/(T\d{4}(?:\.\d{3})?\.yaml)$")
_LICENSE_MEMBER = re.compile(r"^[^/]+/LICENSE\.txt$")

#: Written only after extraction finishes, so an interrupted fetch is retried
#: rather than mistaken for a populated cache.
_MARKER = ".fetched.json"

#: Executors whose ``command`` is shell. ``manual`` is the fourth kind upstream
#: ships (16 tests): it carries human ``steps`` prose and no command at all, and
#: yielding it under ``Register.SHELL`` would put prose in the shell budget and
#: quietly corrupt the coverage report this corpus is built around.
_SHELL_EXECUTORS = frozenset({"powershell", "command_prompt", "sh", "bash"})


def _fetch(cache_dir: Path) -> Path:
    """Download and unpack the atomics tree into ``cache_dir``. Idempotent.

    Re-runs are free: if the marker file is present the function returns before
    touching the network. The build runs often and this tarball is 167 MB.

    The tarball is streamed (``r|gz``) and members are written by hand from the
    path components captured by :data:`_MEMBER` rather than handed to
    ``TarFile.extract``. That is deliberate: a tar member name is attacker-
    controlled data in the general case, and constructing the destination
    ourselves from two validated ``T####`` components makes path traversal
    unrepresentable without depending on ``filter="data"`` (3.12+ only).

    TLS goes through :func:`training.corpus.net.ssl_context` rather than
    ``urlopen``'s default, because the python.org macOS interpreter this project
    runs on has an empty CA store and would otherwise fail on a working network.
    That helper is shared on purpose: three private copies of trust-store logic
    is how one of them quietly drifts into ``CERT_NONE``. The body is still
    streamed here rather than going through ``net.download``, which buffers the
    whole response in memory — this tarball is 167 MB.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    marker = cache_dir / _MARKER
    atomics = cache_dir / "atomics"
    if marker.is_file() and atomics.is_dir():
        return cache_dir

    archive = cache_dir / ".download.tar.gz"
    request = urllib.request.Request(_TARBALL, headers={"User-Agent": net.USER_AGENT})
    written = 0
    # One finally for both stages: whatever goes wrong — a dead trust store, a
    # truncated body, a KeyboardInterrupt mid-stream — the partial archive is
    # removed rather than left in the cache for a later run to trip over.
    try:
        try:
            with urllib.request.urlopen(
                request, timeout=300, context=net.ssl_context()
            ) as response:
                if response.status != 200:
                    raise SourceError(
                        f"atomic: {_TARBALL} returned HTTP {response.status}"
                    )
                with archive.open("wb") as out:
                    while chunk := response.read(1 << 20):
                        out.write(chunk)
        except net.NetworkError as exc:  # no CA anywhere; the message says how to fix it
            raise SourceError(f"atomic: {exc}") from exc
        except OSError as exc:  # URLError and friends are all OSError subclasses
            raise SourceError(f"atomic: could not download {_TARBALL}: {exc}") from exc

        try:
            with tarfile.open(archive, mode="r|gz") as tar:
                for member in tar:
                    if not member.isfile():
                        continue
                    if _LICENSE_MEMBER.match(member.name):
                        stream = tar.extractfile(member)
                        if stream is not None:
                            (cache_dir / "LICENSE.txt").write_bytes(stream.read())
                        continue
                    match = _MEMBER.match(member.name)
                    if match is None:
                        continue
                    stream = tar.extractfile(member)
                    if stream is None:
                        continue
                    technique, filename = match.group(1), match.group(2)
                    destination = atomics / technique
                    destination.mkdir(parents=True, exist_ok=True)
                    (destination / filename).write_bytes(stream.read())
                    written += 1
        except tarfile.TarError as exc:
            raise SourceError(
                f"atomic: malformed tarball from {_TARBALL}: {exc}"
            ) from exc
    finally:
        # 167 MB of documentation images is not worth keeping on the corpus disk.
        archive.unlink(missing_ok=True)

    if written == 0:
        raise SourceError(
            "atomic: tarball contained no atomics/T*/T*.yaml members — the "
            "upstream repository layout has changed"
        )

    marker.write_text(
        json.dumps(
            {
                "url": _TARBALL,
                "fetched_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "technique_files": written,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return cache_dir


def _as_text(value: Any) -> str:
    """Render a YAML scalar as the string a reader would see.

    ``input_arguments`` defaults are typed (``integer``, ``float``, ``path``),
    so a naive ``.strip()`` blows up on the ones PyYAML hands back as ``int``.
    Booleans are lower-cased back to their YAML spelling rather than Python's,
    because the surface form is the thing this corpus collects.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _block(label: str, body: str) -> list[str]:
    """A labelled block, emitted flush-left.

    No wrapper indentation on purpose: the command body reaches the tokenizer
    with exactly the spacing upstream wrote, and ``normalise()`` preserves
    horizontal whitespace, so a PowerShell here-string or an indented ``if``
    block keeps its shape. Adding a wrapper indent would now survive too — and
    would be pure noise charged against every line of every command.
    """
    body = body.strip("\n")
    return [f"{label}:", body, ""] if body.strip() else []


def _render(technique: str, display_name: str, test: dict[str, Any]) -> str:
    """Assemble one atomic test into the text the model will see.

    The header restates ``technique`` on every document. That repetition is the
    deliverable, not sloppiness: it is what puts ``T1003.001`` two lines above
    ``rundll32.exe ... comsvcs.dll, MiniDump`` in 1,862 separate windows.
    """
    executor: dict[str, Any] = test.get("executor") or {}
    platforms = test.get("supported_platforms") or []
    lines: list[str] = [
        f"technique: {technique}",
        f"technique name: {display_name}",
        f"atomic test: {_as_text(test.get('name'))}",
        f"platforms: {', '.join(_as_text(p) for p in platforms)}",
        f"executor: {_as_text(executor.get('name'))}",
    ]
    if executor.get("elevation_required"):
        lines.append("elevation required: true")
    guid = _as_text(test.get("auto_generated_guid"))
    if guid:
        lines.append(f"guid: {guid}")
    lines.append("")

    lines += _block("description", _as_text(test.get("description")))

    arguments = test.get("input_arguments") or {}
    if isinstance(arguments, dict) and arguments:
        rows: list[str] = []
        for key, meta in arguments.items():
            meta = meta if isinstance(meta, dict) else {}
            kind = _as_text(meta.get("type")) or "string"
            rows.append(f"#{{{key}}} ({kind}) {_as_text(meta.get('description'))}".rstrip())
            default = _as_text(meta.get("default"))
            if default:
                # Defaults are where the registry hives, %TEMP% paths and UNC
                # shares live — the SYSTEM-register surface forms the tokenizer
                # is starved of, delivered attached to the command using them.
                rows.append(f"default: {default}")
        lines += _block("input arguments", "\n".join(rows))

    lines += _block("command", _as_text(executor.get("command")))
    lines += _block("cleanup command", _as_text(executor.get("cleanup_command")))

    dependencies = test.get("dependencies") or []
    if isinstance(dependencies, list) and dependencies:
        dep_executor = _as_text(test.get("dependency_executor_name"))
        rows = []
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                continue
            rows.append(f"- {_as_text(dependency.get('description')).strip()}")
            for key, label in (
                ("prereq_command", "prereq command"),
                ("get_prereq_command", "get prereq command"),
            ):
                body = _as_text(dependency.get(key)).strip("\n")
                if body.strip():
                    rows.append(f"{label}:")
                    rows.append(body)
        label = f"dependencies ({dep_executor})" if dep_executor else "dependencies"
        lines += _block(label, "\n".join(rows))

    return "\n".join(lines)


def _documents(path: Path) -> Iterator[Document]:
    """Yield one :class:`Document` per shell-executor atomic test.

    Files are walked in sorted order and tests in file order, so the corpus is
    byte-reproducible across builds.

    A YAML parse failure raises rather than being skipped. A silently dropped
    technique file is exactly the failure ``expect_min_docs`` exists to catch,
    and catching it at the file that broke — with its name — is worth more than
    a build that quietly ships 30 fewer techniques.
    """
    import yaml  # local import: PyYAML is only needed when this source is built

    files = sorted((path / "atomics").glob("T*/T*.yaml"))
    if not files:
        raise SourceError(f"atomic: no atomics/T*/T*.yaml under {path}")

    for file in files:
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError) as exc:
            raise SourceError(f"atomic: {file.name} failed to parse: {exc}") from exc
        if not isinstance(data, dict):
            raise SourceError(f"atomic: {file.name} is not a mapping")

        technique = _as_text(data.get("attack_technique")) or file.stem
        display_name = _as_text(data.get("display_name"))
        tests = data.get("atomic_tests") or []
        if not isinstance(tests, list):
            raise SourceError(f"atomic: {file.name} has a non-list atomic_tests")

        for index, test in enumerate(tests):
            if not isinstance(test, dict):
                continue
            executor = test.get("executor")
            if not isinstance(executor, dict):
                continue
            if _as_text(executor.get("name")) not in _SHELL_EXECUTORS:
                continue
            # The real gate. `manual` tests are the only ones upstream ships
            # without a command today, but testing for the command rather than
            # trusting the executor name keeps this honest if that changes.
            if not _as_text(executor.get("command")).strip():
                continue

            text = normalise(_render(technique, display_name, test))
            if len(text) < 80:
                continue  # nothing left to learn from; the ctor would reject empties
            guid = _as_text(test.get("auto_generated_guid")) or f"{index:03d}"
            yield Document(
                text=text,
                source="atomic",
                register=Register.SHELL,
                side=Side.RED,
                ident=f"{technique}/{guid}",
            )


SPEC = SourceSpec(
    name="atomic",
    license="MIT (Copyright (c) 2018 Red Canary, Inc.; LICENSE.txt is copied into the cache)",
    url=_REPO,
    register=Register.SHELL,
    side=Side.RED,
    fetch=_fetch,
    documents=_documents,
    #: Observed 1,862 on master at fetch time (1,878 atomic tests, 16 of them
    #: `manual` and command-less). The floor is set well below that so ordinary
    #: upstream churn is quiet, but a parser that starts dropping executors —
    #: the realistic regression — trips it immediately.
    expect_min_docs=1500,
    notes=(
        "One document per atomic test: technique id, display name, test name, "
        "platforms, description, input-argument defaults, the executor command, "
        "cleanup command and dependency prereq shell, in that order. Per-test "
        "rather than per-file so the T#### identifier co-occurs with every "
        "command it labels rather than only the first. `manual` executors are "
        "skipped — they carry prose steps, not shell, and would pollute the "
        "SHELL register budget. Commands retain their `#{argument}` "
        "placeholders; the defaults that fill them are emitted directly above."
    ),
)
