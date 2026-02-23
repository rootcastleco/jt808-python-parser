"""Utility helpers for the JT808 protocol.

Functions
---------
escape(data)        Apply JT808 byte-stuffing (escape 0x7D and 0x7E).
unescape(data)      Reverse byte-stuffing.
checksum(data)      XOR checksum over *data*.
bcd_encode(digits)  Encode a decimal string as BCD bytes.
bcd_decode(data)    Decode BCD bytes to a decimal string.
"""

from __future__ import annotations

from .constants import ESCAPE_7D, ESCAPE_7E, ESCAPE_CHAR, FRAME_DELIMITER


# ---------------------------------------------------------------------------
# Escape / unescape
# ---------------------------------------------------------------------------

def escape(data: bytes) -> bytes:
    """Apply JT808 byte-stuffing to *data*.

    Rules (applied in order):
      * ``0x7D`` → ``0x7D 0x01``
      * ``0x7E`` → ``0x7D 0x02``
    """
    result = bytearray()
    for byte in data:
        if byte == ESCAPE_CHAR:
            result.extend([ESCAPE_CHAR, ESCAPE_7D])
        elif byte == FRAME_DELIMITER:
            result.extend([ESCAPE_CHAR, ESCAPE_7E])
        else:
            result.append(byte)
    return bytes(result)


def unescape(data: bytes) -> bytes:
    """Reverse JT808 byte-stuffing on *data*.

    Rules:
      * ``0x7D 0x01`` → ``0x7D``
      * ``0x7D 0x02`` → ``0x7E``

    Raises
    ------
    ValueError
        If an invalid escape sequence is encountered.
    """
    result = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte == ESCAPE_CHAR:
            if i + 1 >= len(data):
                raise ValueError("Truncated escape sequence at end of data")
            next_byte = data[i + 1]
            if next_byte == ESCAPE_7D:
                result.append(ESCAPE_CHAR)
            elif next_byte == ESCAPE_7E:
                result.append(FRAME_DELIMITER)
            else:
                raise ValueError(
                    f"Invalid escape sequence 0x7D 0x{next_byte:02X} at offset {i}"
                )
            i += 2
        else:
            result.append(byte)
            i += 1
    return bytes(result)


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

def checksum(data: bytes) -> int:
    """Return the JT808 XOR checksum of *data* as a single byte integer."""
    result = 0
    for byte in data:
        result ^= byte
    return result & 0xFF


# ---------------------------------------------------------------------------
# BCD helpers
# ---------------------------------------------------------------------------

def bcd_encode(digits: str) -> bytes:
    """Encode a decimal string *digits* as packed BCD bytes.

    Parameters
    ----------
    digits:
        A string of decimal characters.  If the length is odd it is
        left-padded with ``'0'``.

    Returns
    -------
    bytes
        Packed BCD representation.

    Raises
    ------
    ValueError
        If *digits* contains non-decimal characters.
    """
    if not digits.isdigit():
        raise ValueError(f"BCD input must contain only digits, got: {digits!r}")
    if len(digits) % 2:
        digits = "0" + digits
    return bytes(
        (int(digits[i]) << 4) | int(digits[i + 1])
        for i in range(0, len(digits), 2)
    )


def bcd_decode(data: bytes) -> str:
    """Decode packed BCD *data* to a decimal string (no leading zero stripping)."""
    result = []
    for byte in data:
        result.append(str((byte >> 4) & 0x0F))
        result.append(str(byte & 0x0F))
    return "".join(result)
