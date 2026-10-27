"""Where the large, uncommittable data lives.

Twenty-one call sites used to name **one machine's external volume** as their
default — ``/Volumes/<handle>/whetstone/...`` written out as a literal in
argparse defaults, module constants and shell variables. That is two separate
defects wearing one disguise.

The first is privacy. The volume name is one of the kinds
:mod:`training.corpus.verify` hunts for, and :mod:`tests.test_identity` already
pins the rule that a module must not carry a host literal. A default that names
the operator's disk puts a host identifier in every clone of a public
repository, for no gain: the path is not a secret worth keeping, but it is also
not a fact a stranger needs.

The second is that it simply does not work for anybody else. A default pointing
at a volume that exists on exactly one computer is not a default; it is a
trap that fails at the first file read, and it fails *late* — after the argument
parser has accepted it.

So the policy lives here, once, and is asked rather than copied. The repository
already carries ``data`` as a symlink to wherever the bulk actually sits, is
already ignored by git, and is already the name every doc uses — so the default
is simply that, anchored to the repository root rather than the working
directory. ``python3 scripts/foo.py`` run from anywhere resolves to the same
place, which a bare relative ``Path("data")`` would not.

**Why a function and not a module constant.** A constant freezes the
environment at import time, and the thing most likely to set
``WHETSTONE_DATA`` is a test or an overnight wrapper that imports first and
configures second. :func:`data_root` is read at the moment of use, so setting
the variable late still works. This is the same reason
:mod:`training.corpus.provenance` asks one shared question instead of letting
three gates each keep their own copy of the answer: a policy with three copies
has three chances to disagree, and the copy that disagrees quietly is the one
that matters.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["DATA_ENV", "LIMA_ENV", "data_root", "lima_home", "repo_root"]

#: Override the data root. Set it to an absolute path; it is expanded for
#: ``~`` so ``WHETSTONE_DATA=~/whetstone-data`` behaves as written.
DATA_ENV = "WHETSTONE_DATA"

#: Lima reads this itself, so the name is not ours to choose.
LIMA_ENV = "LIMA_HOME"


def repo_root() -> Path:
    """The checkout this module was imported from.

    ``parents[1]`` and not ``cwd``: a script invoked as
    ``python3 scripts/foo.py`` gets ``sys.path[0] == scripts/``, and a cron
    wrapper may have any working directory at all.
    """
    return Path(__file__).resolve().parents[1]


def data_root() -> Path:
    """Where weights, corpus, checkpoints, VM disks and logs live.

    Defaults to ``<repo>/data`` — the ignored symlink the repository already
    documents. Returns a path that may not exist: whether the bulk is mounted
    is the caller's question, and "absent" is a better error at the point of
    read than a silently wrong default.
    """
    raw = os.environ.get(DATA_ENV, "").strip()
    if raw:
        return Path(raw).expanduser()
    return repo_root() / "data"


def lima_home() -> Path:
    """``LIMA_HOME`` for the lab VMs, honouring an existing export.

    Lima is told where its state lives through the environment, so an operator
    who has already exported ``LIMA_HOME`` means it; we only supply a default.
    """
    raw = os.environ.get(LIMA_ENV, "").strip()
    if raw:
        return Path(raw).expanduser()
    return data_root() / "lab" / "lima"
