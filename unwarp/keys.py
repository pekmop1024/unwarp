"""Local WireGuard keys. Public keys are X25519 with base point 9 (RFC 7748)."""

import base64
from secrets import token_bytes


def _clamp(raw: bytes) -> bytes:
    scalar = bytearray(raw)
    scalar[0] &= 248
    scalar[31] = (scalar[31] & 127) | 64
    return bytes(scalar)


def generate_private_key() -> str:
    """Generate the same 32-byte, clamped private-key format as wg genkey."""
    return base64.b64encode(_clamp(token_bytes(32))).decode('ascii')


def _cswap(swap: int, left: int, right: int) -> tuple[int, int]:
    difference = (left ^ right) & -swap
    return left ^ difference, right ^ difference


def _public_u(scalar: int) -> int:
    # Montgomery ladder from RFC 7748 §5. (x2:z2) and (x3:z3) are adjacent
    # multiples of the base point. Python big integers do not guarantee constant time.
    p = 2**255 - 19
    base_u = 9
    x2, z2 = 1, 0
    x3, z3 = base_u, 1
    previous_bit = 0
    for position in range(254, -1, -1):
        bit = (scalar >> position) & 1
        swap = previous_bit ^ bit
        x2, x3 = _cswap(swap, x2, x3)
        z2, z3 = _cswap(swap, z2, z3)
        previous_bit = bit

        a = (x2 + z2) % p
        b = (x2 - z2) % p
        aa = a * a % p
        bb = b * b % p
        e = (aa - bb) % p
        da = (x3 - z3) * a % p
        cb = (x3 + z3) * b % p
        x3 = (da + cb)**2 % p
        z3 = base_u * (da - cb)**2 % p
        x2 = aa * bb % p
        z2 = e * (aa + 121665 * e) % p

    x2, _ = _cswap(previous_bit, x2, x3)
    z2, _ = _cswap(previous_bit, z2, z3)
    return x2 * pow(z2, p - 2, p) % p


def derive_public_key(private_key: str) -> str:
    """Derive a WireGuard public key from a base64-encoded private key."""
    encoded = private_key.rstrip(' \t\r\n\v\f')
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise ValueError('invalid WireGuard private key') from None
    if len(raw) != 32 or base64.b64encode(raw).decode('ascii') != encoded:
        raise ValueError('invalid WireGuard private key')
    scalar = int.from_bytes(_clamp(raw), 'little')
    public = _public_u(scalar).to_bytes(32, 'little')
    return base64.b64encode(public).decode('ascii')
