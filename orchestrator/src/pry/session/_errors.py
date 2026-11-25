"""Session-level exceptions."""

from __future__ import annotations


class WrongMachineError(OSError):
    """A host answered the connect probe, but as a *different* machine than
    the one asked for — typically a recycled DHCP lease now held by another
    box. Subclasses ``OSError`` so every existing network-failure handler
    (reconnect's /24 auto-expand, the envelope classifier) treats it like
    any other unreachable-endpoint outcome.

    The message starts with ``wrong_machine`` so the error classifier maps
    it to ``kind='wrong_machine'`` without a bespoke code path.
    """

    kind = "wrong_machine"

    def __init__(self, *, host: str, label: str, expected: str,
                 answered: str, port: int = 0):
        self.host = host
        self.label = label
        self.expected = expected
        self.answered = answered
        ep = f"{host}:{port}" if port else host
        super().__init__(
            f"wrong_machine: {ep} answered as {answered!r}, but {label!r} "
            f"is {expected!r} — refusing to attach (that address now "
            "belongs to a different machine)")


class UnverifiedMachineError(WrongMachineError):
    """A *learned* endpoint (phone-home beacon, observed address, name
    resolution, last-good host) answered, but nothing proves it is the
    machine asked for: no stored computer_name to compare, no matching boot
    epoch, no verified sibling view at that address. Learned addresses are
    attacker-influenceable (the beacon intake is unauthenticated, mDNS is
    spoofable), so an unproven one is refused instead of attached.

    Subclasses :class:`WrongMachineError` so the envelope classifier keeps
    one ``wrong_machine`` kind and every OSError handler still applies; the
    message says what would prove the identity."""

    def __init__(self, *, host: str, label: str, answered: str,
                 port: int = 0, token_withheld: bool = False):
        self.host = host
        self.label = label
        self.expected = ""
        self.answered = answered
        self.token_withheld = token_withheld
        ep = f"{host}:{port}" if port else host
        OSError.__init__(
            self,
            f"wrong_machine: {ep} (a learned address) answered as "
            f"{answered or '<no name>'!r} but nothing proves it is "
            f"{label!r} — no stored computer_name, matching boot epoch or "
            "verified sibling view; refusing to attach"
            + (" (agent token withheld)" if token_withheld else "")
            + ". Record the identity with machines_manage(action='set', "
              f"machine={label!r}, computer_name=...) or connect with an "
              "explicit host=")


class AmbiguousTargetError(RuntimeError):
    """A tool call left ``name=`` empty (or used a bare view kind) while
    more than one machine is connected and the caller holds no focus.

    Carries the live machine list so the error envelope can name the
    options; the hint points at ``target_manage(action='use')``.
    """

    kind = "ambiguous_target"

    def __init__(self, machines: list[str]):
        self.machines = list(machines)
        super().__init__(
            "ambiguous target: " + (", ".join(self.machines) or "<none>")
            + " connected — pick one with "
              "target_manage(action='use', machine='<name>') "
              "or pass name='<machine>.kernel' explicitly")
        self.hint = ("target_manage(action='use', machine=...) sets your "
                     "chat's current machine; name='<machine>.kernel|user' "
                     "selects a view explicitly")
