"""Platform adapters, and the registration side effects that wire them up.

Importing this package imports each platform module, whose ``@register_adapter``
decorator records the adapter in the registry that :func:`.base.get_adapter`
reads. That is the whole reason the imports below exist: without them a fresh
process would have an empty registry and ``get_adapter('windows')`` would fail
even on Windows.

The three imports are guarded individually. During the initial build the three
adapters land in separate commits, so on a checkout where — say — ``linux`` has
not been written yet, importing it would raise and take the whole package (and
therefore the Windows adapter that *is* present) down with it. Guarding each
import means a platform module that exists registers, and one that does not yet
exist is simply absent from the registry rather than a hard import failure —
which is the same "degrade, do not crash" rule the adapters themselves follow.
Once all three modules exist the guards are inert: every import succeeds.
"""

from __future__ import annotations

# Each import is for its register_adapter() side effect. Order is irrelevant.
try:  # noqa: SIM105 — an explicit block reads clearer than contextlib.suppress here
    from . import linux  # noqa: F401
except ImportError:
    pass

try:
    from . import macos  # noqa: F401
except ImportError:
    pass

try:
    from . import windows  # noqa: F401
except ImportError:
    pass
