"""JT808 protocol parser and builder.

The public interface is the :class:`JT808Parser` class, which provides:

* :meth:`JT808Parser.parse` – parse a raw JT808 frame (including the ``0x7E``
  delimiters) and return a :class:`JT808Message` named-tuple.
* :meth:`JT808Parser.build` – assemble a complete JT808 frame from header
  fields and a pre-encoded body ``bytes`` object.

Supported message body parsers (all return a plain ``dict``):

==========  ===================================
Message ID  Description
==========  ===================================
``0x0001``  Terminal general reply
``0x0002``  Terminal heartbeat (empty body)
``0x0100``  Terminal registration
``0x0102``  Terminal authentication
``0x0200``  Location information report
``0x0704``  Location batch upload
``0x8001``  Platform general reply
``0x8100``  Terminal registration reply
==========  ===================================

Unknown message IDs are returned with ``body_raw`` containing the raw bytes.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, NamedTuple, Optional

from .constants import (
    FRAME_DELIMITER,
    HEADER_SIZE,
    MSG_LOCATION_BATCH_UPLOAD,
    MSG_LOCATION_REPORT,
    MSG_PLATFORM_GENERAL_REPLY,
    MSG_REGISTER_REPLY,
    MSG_TERMINAL_GENERAL_REPLY,
    MSG_TERMINAL_HEARTBEAT,
    MSG_TERMINAL_REGISTER,
    MSG_TERMINAL_REGISTER_AUTH,
    SUBPACKAGE_HEADER_EXTRA,
)
from .utils import bcd_decode, bcd_encode, checksum, escape, unescape


class JT808Message(NamedTuple):
    """Parsed JT808 message."""

    msg_id: int
    """16-bit message identifier."""

    attributes: int
    """Raw 16-bit message attributes field."""

    phone: str
    """Caller/terminal phone number (BCD-decoded, 12 digits)."""

    serial_no: int
    """Message serial number (0–65535)."""

    subpackage_total: Optional[int]
    """Total sub-packets (``None`` when not a sub-packaged message)."""

    subpackage_no: Optional[int]
    """Current sub-packet index (``None`` when not a sub-packaged message)."""

    body: Dict[str, Any]
    """Parsed message body as a plain dictionary."""

    body_raw: bytes
    """Raw (unescaped) message body bytes."""


class JT808Parser:
    """Parser and builder for JT808 frames.

    Parameters
    ----------
    strict:
        When ``True`` (default) raise :class:`ValueError` on checksum
        mismatch.  Set to ``False`` to log a warning and continue.
    """

    def __init__(self, strict: bool = True) -> None:
        self.strict = strict

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, frame: bytes) -> JT808Message:
        """Parse a complete JT808 frame and return a :class:`JT808Message`.

        Parameters
        ----------
        frame:
            Raw bytes including the leading and trailing ``0x7E`` delimiters.

        Raises
        ------
        ValueError
            On framing errors, invalid escapes, or checksum mismatches
            (when *strict* is ``True``).
        """
        frame = self._strip_delimiters(frame)
        frame = unescape(frame)
        self._verify_checksum(frame)

        # The checksum byte is the last byte; everything before it is
        # header + body.
        payload = frame[:-1]
        return self._parse_payload(payload)

    def build(
        self,
        msg_id: int,
        phone: str,
        serial_no: int,
        body: bytes = b"",
        encrypt: int = 0,
        subpackage_total: Optional[int] = None,
        subpackage_no: Optional[int] = None,
    ) -> bytes:
        """Build a complete JT808 frame.

        Parameters
        ----------
        msg_id:
            16-bit message identifier.
        phone:
            Terminal phone number (up to 12 decimal digits).
        serial_no:
            Message serial number (0–65535).
        body:
            Pre-encoded message body bytes.
        encrypt:
            Encryption type bits (bits 13-10 of the attributes word).
        subpackage_total:
            Total sub-packets (omit when not sub-packaged).
        subpackage_no:
            Current sub-packet index (omit when not sub-packaged).

        Returns
        -------
        bytes
            Complete framed JT808 message including ``0x7E`` delimiters.
        """
        body_len = len(body)
        if body_len > 0x3FF:
            raise ValueError(f"Body too long: {body_len} bytes (max 1023)")

        subpackage_flag = 1 if subpackage_total is not None else 0
        attributes = (subpackage_flag << 13) | (encrypt << 10) | (body_len & 0x3FF)

        phone_bcd = bcd_encode(phone.zfill(12))

        header = struct.pack(">HH", msg_id, attributes) + phone_bcd + struct.pack(">H", serial_no)
        if subpackage_flag:
            header += struct.pack(">HH", subpackage_total, subpackage_no)

        raw = header + body
        cs = checksum(raw)
        raw += bytes([cs])

        return bytes([FRAME_DELIMITER]) + escape(raw) + bytes([FRAME_DELIMITER])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _strip_delimiters(frame: bytes) -> bytes:
        if len(frame) < 2:
            raise ValueError("Frame too short")
        if frame[0] != FRAME_DELIMITER or frame[-1] != FRAME_DELIMITER:
            raise ValueError(
                f"Frame must start and end with 0x7E, got "
                f"0x{frame[0]:02X}...0x{frame[-1]:02X}"
            )
        return frame[1:-1]

    def _verify_checksum(self, data: bytes) -> None:
        if len(data) < 1:
            raise ValueError("Empty frame after delimiter removal")
        payload, cs_byte = data[:-1], data[-1]
        computed = checksum(payload)
        if computed != cs_byte:
            msg = (
                f"Checksum mismatch: expected 0x{computed:02X}, "
                f"got 0x{cs_byte:02X}"
            )
            if self.strict:
                raise ValueError(msg)

    def _parse_payload(self, payload: bytes) -> JT808Message:
        if len(payload) < HEADER_SIZE:
            raise ValueError(
                f"Payload too short for header: {len(payload)} bytes"
            )

        msg_id, attributes = struct.unpack_from(">HH", payload, 0)
        phone = bcd_decode(payload[4:10])
        serial_no = struct.unpack_from(">H", payload, 10)[0]

        subpackage_flag = bool(attributes & (1 << 13))
        offset = HEADER_SIZE
        subpackage_total = subpackage_no = None
        if subpackage_flag:
            if len(payload) < HEADER_SIZE + SUBPACKAGE_HEADER_EXTRA:
                raise ValueError("Payload too short for sub-packet header")
            subpackage_total, subpackage_no = struct.unpack_from(">HH", payload, offset)
            offset += SUBPACKAGE_HEADER_EXTRA

        body_raw = payload[offset:]
        body = self._parse_body(msg_id, body_raw)

        return JT808Message(
            msg_id=msg_id,
            attributes=attributes,
            phone=phone,
            serial_no=serial_no,
            subpackage_total=subpackage_total,
            subpackage_no=subpackage_no,
            body=body,
            body_raw=body_raw,
        )

    # ------------------------------------------------------------------
    # Body parsers
    # ------------------------------------------------------------------

    def _parse_body(self, msg_id: int, data: bytes) -> Dict[str, Any]:
        parsers = {
            MSG_TERMINAL_GENERAL_REPLY: self._parse_terminal_general_reply,
            MSG_TERMINAL_HEARTBEAT: self._parse_heartbeat,
            MSG_TERMINAL_REGISTER: self._parse_terminal_register,
            MSG_TERMINAL_REGISTER_AUTH: self._parse_terminal_auth,
            MSG_LOCATION_REPORT: self._parse_location,
            MSG_LOCATION_BATCH_UPLOAD: self._parse_location_batch,
            MSG_PLATFORM_GENERAL_REPLY: self._parse_platform_general_reply,
            MSG_REGISTER_REPLY: self._parse_register_reply,
        }
        parser = parsers.get(msg_id)
        if parser is None:
            return {}
        return parser(data)

    # 0x0001 – Terminal general reply
    @staticmethod
    def _parse_terminal_general_reply(data: bytes) -> Dict[str, Any]:
        if len(data) < 5:
            raise ValueError("Terminal general reply too short")
        serial_no, msg_id, result = struct.unpack_from(">HHB", data, 0)
        return {"reply_serial_no": serial_no, "reply_msg_id": msg_id, "result": result}

    # 0x0002 – Heartbeat (empty body)
    @staticmethod
    def _parse_heartbeat(_data: bytes) -> Dict[str, Any]:
        return {}

    # 0x0100 – Terminal registration
    @staticmethod
    def _parse_terminal_register(data: bytes) -> Dict[str, Any]:
        if len(data) < 37:
            raise ValueError("Terminal registration body too short")
        province_id, city_id = struct.unpack_from(">HH", data, 0)
        manufacturer_id = data[4:9].decode("ascii", errors="replace").rstrip("\x00")
        terminal_model = data[9:29].decode("ascii", errors="replace").rstrip("\x00")
        terminal_id = data[29:36].decode("ascii", errors="replace").rstrip("\x00")
        plate_color = data[36]
        plate_no = data[37:].decode("gbk", errors="replace") if len(data) > 37 else ""
        return {
            "province_id": province_id,
            "city_id": city_id,
            "manufacturer_id": manufacturer_id,
            "terminal_model": terminal_model,
            "terminal_id": terminal_id,
            "plate_color": plate_color,
            "plate_no": plate_no,
        }

    # 0x0102 – Terminal authentication
    @staticmethod
    def _parse_terminal_auth(data: bytes) -> Dict[str, Any]:
        auth_code = data.decode("ascii", errors="replace").rstrip("\x00")
        return {"auth_code": auth_code}

    # 0x0200 – Location information report
    @staticmethod
    def _parse_location(data: bytes) -> Dict[str, Any]:
        if len(data) < 28:
            raise ValueError("Location report body too short")
        alarm, status, lat_raw, lng_raw, altitude, speed, direction = struct.unpack_from(
            ">IIIIHHH", data, 0
        )
        time_bcd = bcd_decode(data[22:28])
        # Latitude/longitude are in units of 1e-6 degrees
        latitude = lat_raw / 1_000_000.0
        longitude = lng_raw / 1_000_000.0

        # Apply south/west flags
        from .constants import STATUS_LATITUDE_SOUTH, STATUS_LONGITUDE_WEST
        if status & STATUS_LATITUDE_SOUTH:
            latitude = -latitude
        if status & STATUS_LONGITUDE_WEST:
            longitude = -longitude

        result: Dict[str, Any] = {
            "alarm": alarm,
            "status": status,
            "latitude": latitude,
            "longitude": longitude,
            "altitude": altitude,
            "speed": speed / 10.0,
            "direction": direction,
            "time": time_bcd,
            "extra": {},
        }

        # Parse additional info items
        offset = 28
        while offset < len(data):
            if offset + 2 > len(data):
                break
            item_id = data[offset]
            item_len = data[offset + 1]
            offset += 2
            if offset + item_len > len(data):
                break
            item_data = data[offset: offset + item_len]
            result["extra"][item_id] = item_data
            offset += item_len

        return result

    # 0x0704 – Location batch upload
    def _parse_location_batch(self, data: bytes) -> Dict[str, Any]:
        if len(data) < 3:
            raise ValueError("Location batch upload body too short")
        count, data_type = struct.unpack_from(">HB", data, 0)
        items = []
        offset = 3
        for _ in range(count):
            if offset + 2 > len(data):
                break
            item_len = struct.unpack_from(">H", data, offset)[0]
            offset += 2
            if offset + item_len > len(data):
                break
            item_data = data[offset: offset + item_len]
            try:
                items.append(self._parse_location(item_data))
            except (ValueError, struct.error):
                items.append({"raw": item_data})
            offset += item_len
        return {"count": count, "data_type": data_type, "items": items}

    # 0x8001 – Platform general reply
    @staticmethod
    def _parse_platform_general_reply(data: bytes) -> Dict[str, Any]:
        if len(data) < 5:
            raise ValueError("Platform general reply too short")
        serial_no, msg_id, result = struct.unpack_from(">HHB", data, 0)
        return {"reply_serial_no": serial_no, "reply_msg_id": msg_id, "result": result}

    # 0x8100 – Terminal registration reply
    @staticmethod
    def _parse_register_reply(data: bytes) -> Dict[str, Any]:
        if len(data) < 3:
            raise ValueError("Register reply too short")
        serial_no, result = struct.unpack_from(">HB", data, 0)
        auth_code = data[3:].decode("ascii", errors="replace") if result == 0 else ""
        return {"reply_serial_no": serial_no, "result": result, "auth_code": auth_code}
