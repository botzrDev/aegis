# botzr-aegis-confine

Linux Landlock + seccomp confinement derived from a [`CapabilityGrant`].

This helper is **authority-reducing only**. It holds no privilege, is not
setuid, and its only powers are to narrow the calling process and then
(via `aegis __confine-exec`) replace its own image with the target.
An attacker who invokes it with an empty profile gets exactly what
running the target directly would have given them. That is [ADR-0007],
and it is what separates this from the setuid sandbox helpers that have
historically been a vulnerability class.

Confinement is off unless `aegis wrap --confine` is given. See
[`docs/wrap.md`](../../docs/wrap.md) and
[ADR-0007](../../docs/adr/0007-confinement-via-self-restricting-re-exec.md).

[`CapabilityGrant`]: https://docs.rs/botzr-aegis-core/latest/botzr_aegis_core/struct.CapabilityGrant.html
