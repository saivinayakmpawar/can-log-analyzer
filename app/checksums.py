"""Checksum algorithms available to the checksum check.

The DBC format does not carry the algorithm, so every checksum must be declared
in the rules file. Add your own with :func:`register_checksum`::

    from app.checksums import register_checksum

    @register_checksum("my_crc")
    def my_crc(data: bytes, seed: int = 0) -> int:
        ...
"""
from __future__ import annotations

from collections.abc import Callable

ChecksumFn = Callable[..., int]
_REGISTRY: dict[str, ChecksumFn] = {}


def register_checksum(name: str) -> Callable[[ChecksumFn], ChecksumFn]:
    def deco(fn: ChecksumFn) -> ChecksumFn:
        _REGISTRY[name] = fn
        return fn

    return deco


def get_checksum(name: str) -> ChecksumFn | None:
    return _REGISTRY.get(name)


def available() -> list[str]:
    return sorted(_REGISTRY)


@register_checksum("xor8")
def xor8(data: bytes, init: int = 0) -> int:
    out = init & 0xFF
    for b in data:
        out ^= b
    return out


@register_checksum("sum8")
def sum8(data: bytes, init: int = 0) -> int:
    return (init + sum(data)) & 0xFF


@register_checksum("crc8")
def crc8(data: bytes, poly: int = 0x1D, init: int = 0xFF, xorout: int = 0xFF) -> int:
    """MSB-first CRC-8. Defaults are SAE J1850 (poly 0x1D, init 0xFF, xorout 0xFF)."""
    crc = init & 0xFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc ^ (xorout & 0xFF)


@register_checksum("crc8_sae_j1850")
def crc8_j1850(data: bytes) -> int:
    return crc8(data, 0x1D, 0xFF, 0xFF)
