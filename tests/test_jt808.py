"""Tests for the jt808 Python parser."""

import struct

import pytest

from jt808 import (
    JT808Parser,
    bcd_decode,
    bcd_encode,
    checksum,
    escape,
    unescape,
)
from jt808.constants import (
    ALARM_EMERGENCY,
    EXTRA_MILEAGE,
    FRAME_DELIMITER,
    MSG_LOCATION_REPORT,
    MSG_PLATFORM_GENERAL_REPLY,
    MSG_REGISTER_REPLY,
    MSG_TERMINAL_GENERAL_REPLY,
    MSG_TERMINAL_HEARTBEAT,
    MSG_TERMINAL_REGISTER,
    MSG_TERMINAL_REGISTER_AUTH,
    REGISTER_RESULT_SUCCESS,
    RESULT_SUCCESS,
    STATUS_ACC_ON,
    STATUS_LOCATED,
)


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------


class TestBCD:
    def test_encode_even_digits(self):
        assert bcd_encode("1234") == bytes([0x12, 0x34])

    def test_encode_odd_digits(self):
        assert bcd_encode("123") == bytes([0x01, 0x23])

    def test_encode_phone(self):
        assert bcd_encode("013912345678") == bytes([0x01, 0x39, 0x12, 0x34, 0x56, 0x78])

    def test_decode(self):
        assert bcd_decode(bytes([0x01, 0x39, 0x12, 0x34, 0x56, 0x78])) == "013912345678"

    def test_encode_then_decode_roundtrip(self):
        phone = "013912345678"
        assert bcd_decode(bcd_encode(phone)) == phone

    def test_encode_invalid(self):
        with pytest.raises(ValueError):
            bcd_encode("12AB")


class TestEscape:
    def test_no_special_bytes(self):
        data = bytes([0x01, 0x02, 0x03])
        assert escape(data) == data

    def test_escape_7e(self):
        assert escape(bytes([0x7E])) == bytes([0x7D, 0x02])

    def test_escape_7d(self):
        assert escape(bytes([0x7D])) == bytes([0x7D, 0x01])

    def test_escape_mixed(self):
        data = bytes([0x01, 0x7D, 0x7E, 0x02])
        expected = bytes([0x01, 0x7D, 0x01, 0x7D, 0x02, 0x02])
        assert escape(data) == expected


class TestUnescape:
    def test_no_special_bytes(self):
        data = bytes([0x01, 0x02, 0x03])
        assert unescape(data) == data

    def test_unescape_7e(self):
        assert unescape(bytes([0x7D, 0x02])) == bytes([0x7E])

    def test_unescape_7d(self):
        assert unescape(bytes([0x7D, 0x01])) == bytes([0x7D])

    def test_unescape_mixed(self):
        escaped = bytes([0x01, 0x7D, 0x01, 0x7D, 0x02, 0x02])
        expected = bytes([0x01, 0x7D, 0x7E, 0x02])
        assert unescape(escaped) == expected

    def test_invalid_escape(self):
        with pytest.raises(ValueError):
            unescape(bytes([0x7D, 0x03]))

    def test_truncated_escape(self):
        with pytest.raises(ValueError):
            unescape(bytes([0x7D]))

    def test_roundtrip(self):
        original = bytes(range(256))
        assert unescape(escape(original)) == original


class TestChecksum:
    def test_empty(self):
        assert checksum(b"") == 0

    def test_single_byte(self):
        assert checksum(bytes([0xAB])) == 0xAB

    def test_xor(self):
        assert checksum(bytes([0xAB, 0xCD])) == 0xAB ^ 0xCD

    def test_cancellation(self):
        assert checksum(bytes([0xFF, 0xFF])) == 0x00


# ---------------------------------------------------------------------------
# Frame builder / parser roundtrip helpers
# ---------------------------------------------------------------------------

def _make_parser() -> JT808Parser:
    return JT808Parser(strict=True)


def _build_frame(
    msg_id: int,
    phone: str,
    serial_no: int,
    body: bytes = b"",
) -> bytes:
    return _make_parser().build(msg_id, phone, serial_no, body)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestParserHeartbeat:
    """0x0002 – Terminal heartbeat (empty body)."""

    def test_parse_heartbeat(self):
        frame = _build_frame(MSG_TERMINAL_HEARTBEAT, "013912345678", 1)
        msg = _make_parser().parse(frame)
        assert msg.msg_id == MSG_TERMINAL_HEARTBEAT
        assert msg.phone == "013912345678"
        assert msg.serial_no == 1
        assert msg.body == {}
        assert msg.body_raw == b""


class TestParserTerminalGeneralReply:
    """0x0001 – Terminal general reply."""

    def test_parse(self):
        body = struct.pack(">HHB", 42, MSG_TERMINAL_HEARTBEAT, RESULT_SUCCESS)
        frame = _build_frame(MSG_TERMINAL_GENERAL_REPLY, "013912345678", 5, body)
        msg = _make_parser().parse(frame)
        assert msg.msg_id == MSG_TERMINAL_GENERAL_REPLY
        assert msg.body["reply_serial_no"] == 42
        assert msg.body["reply_msg_id"] == MSG_TERMINAL_HEARTBEAT
        assert msg.body["result"] == RESULT_SUCCESS


class TestParserTerminalRegisterAuth:
    """0x0102 – Terminal authentication."""

    def test_parse(self):
        auth_code = "ABCDEF123456"
        body = auth_code.encode("ascii")
        frame = _build_frame(MSG_TERMINAL_REGISTER_AUTH, "013912345678", 3, body)
        msg = _make_parser().parse(frame)
        assert msg.msg_id == MSG_TERMINAL_REGISTER_AUTH
        assert msg.body["auth_code"] == auth_code


class TestParserPlatformGeneralReply:
    """0x8001 – Platform general reply."""

    def test_parse(self):
        body = struct.pack(">HHB", 10, MSG_TERMINAL_HEARTBEAT, RESULT_SUCCESS)
        frame = _build_frame(MSG_PLATFORM_GENERAL_REPLY, "000000000000", 1, body)
        msg = _make_parser().parse(frame)
        assert msg.msg_id == MSG_PLATFORM_GENERAL_REPLY
        assert msg.body["reply_serial_no"] == 10
        assert msg.body["result"] == RESULT_SUCCESS


class TestParserRegisterReply:
    """0x8100 – Terminal registration reply."""

    def test_parse_success_with_auth_code(self):
        auth_code = "TOKEN123"
        body = struct.pack(">HB", 1, REGISTER_RESULT_SUCCESS) + auth_code.encode("ascii")
        frame = _build_frame(MSG_REGISTER_REPLY, "000000000000", 1, body)
        msg = _make_parser().parse(frame)
        assert msg.msg_id == MSG_REGISTER_REPLY
        assert msg.body["result"] == REGISTER_RESULT_SUCCESS
        assert msg.body["auth_code"] == auth_code

    def test_parse_failure_no_auth_code(self):
        body = struct.pack(">HB", 1, 0x01)  # vehicle already registered
        frame = _build_frame(MSG_REGISTER_REPLY, "000000000000", 1, body)
        msg = _make_parser().parse(frame)
        assert msg.body["result"] == 0x01
        assert msg.body["auth_code"] == ""


class TestParserLocationReport:
    """0x0200 – Location information report."""

    def _build_location_body(
        self,
        alarm: int = 0,
        status: int = STATUS_ACC_ON | STATUS_LOCATED,
        lat: float = 31.234567,
        lng: float = 121.234567,
        altitude: int = 50,
        speed: float = 60.0,
        direction: int = 90,
        time: str = "260101120000",
        extra: bytes = b"",
    ) -> bytes:
        lat_raw = int(abs(lat) * 1_000_000)
        lng_raw = int(abs(lng) * 1_000_000)
        speed_raw = int(speed * 10)
        time_bcd = bcd_encode(time)
        body = struct.pack(
            ">IIIIHHH",
            alarm, status, lat_raw, lng_raw, altitude, speed_raw, direction,
        )
        body += time_bcd + extra
        return body

    def test_parse_basic(self):
        body = self._build_location_body()
        frame = _build_frame(MSG_LOCATION_REPORT, "013912345678", 7, body)
        msg = _make_parser().parse(frame)
        assert msg.msg_id == MSG_LOCATION_REPORT
        b = msg.body
        assert abs(b["latitude"] - 31.234567) < 1e-4
        assert abs(b["longitude"] - 121.234567) < 1e-4
        assert b["altitude"] == 50
        assert abs(b["speed"] - 60.0) < 0.1
        assert b["direction"] == 90
        assert b["time"] == "260101120000"
        assert b["alarm"] == 0
        assert b["status"] == STATUS_ACC_ON | STATUS_LOCATED

    def test_parse_south_west(self):
        from jt808.constants import STATUS_LATITUDE_SOUTH, STATUS_LONGITUDE_WEST
        status = STATUS_ACC_ON | STATUS_LOCATED | STATUS_LATITUDE_SOUTH | STATUS_LONGITUDE_WEST
        body = self._build_location_body(status=status, lat=33.0, lng=118.0)
        frame = _build_frame(MSG_LOCATION_REPORT, "013912345678", 8, body)
        msg = _make_parser().parse(frame)
        assert msg.body["latitude"] < 0
        assert msg.body["longitude"] < 0

    def test_parse_alarm_flags(self):
        body = self._build_location_body(alarm=ALARM_EMERGENCY)
        frame = _build_frame(MSG_LOCATION_REPORT, "013912345678", 9, body)
        msg = _make_parser().parse(frame)
        assert msg.body["alarm"] & ALARM_EMERGENCY

    def test_parse_extra_items(self):
        # Add mileage extra info item: id=0x01, len=4, value=12345 km
        extra = bytes([EXTRA_MILEAGE, 4]) + struct.pack(">I", 12345)
        body = self._build_location_body(extra=extra)
        frame = _build_frame(MSG_LOCATION_REPORT, "013912345678", 10, body)
        msg = _make_parser().parse(frame)
        assert EXTRA_MILEAGE in msg.body["extra"]
        assert struct.unpack(">I", msg.body["extra"][EXTRA_MILEAGE])[0] == 12345


class TestParserEdgeCases:
    def test_strict_checksum_error(self):
        parser = JT808Parser(strict=True)
        frame = _build_frame(MSG_TERMINAL_HEARTBEAT, "013912345678", 1)
        # Corrupt the checksum byte (second to last byte, before trailing 0x7E)
        corrupted = bytearray(frame)
        corrupted[-2] ^= 0xFF
        with pytest.raises(ValueError, match="Checksum mismatch"):
            parser.parse(bytes(corrupted))

    def test_non_strict_checksum_survives(self):
        parser = JT808Parser(strict=False)
        frame = _build_frame(MSG_TERMINAL_HEARTBEAT, "013912345678", 1)
        corrupted = bytearray(frame)
        corrupted[-2] ^= 0xFF
        # Should not raise
        msg = parser.parse(bytes(corrupted))
        assert msg.msg_id == MSG_TERMINAL_HEARTBEAT

    def test_missing_delimiters(self):
        parser = _make_parser()
        with pytest.raises(ValueError):
            parser.parse(b"\x01\x02\x03")

    def test_body_too_long(self):
        parser = _make_parser()
        with pytest.raises(ValueError, match="Body too long"):
            parser.build(MSG_TERMINAL_HEARTBEAT, "013912345678", 1, body=b"\x00" * 1024)

    def test_unknown_msg_id_returns_empty_body(self):
        frame = _build_frame(0x9999, "013912345678", 1, b"\xDE\xAD")
        msg = _make_parser().parse(frame)
        assert msg.msg_id == 0x9999
        assert msg.body == {}
        assert msg.body_raw == b"\xDE\xAD"

    def test_escape_in_body_roundtrip(self):
        # Body containing 0x7E and 0x7D should be correctly escaped/unescaped
        body = bytes([0x7D, 0x7E, 0x7D, 0x7E])
        frame = _build_frame(0x9999, "013912345678", 1, body)
        assert FRAME_DELIMITER not in frame[1:-1]  # no unescaped 7E inside
        msg = _make_parser().parse(frame)
        assert msg.body_raw == body

    def test_subpackage_fields(self):
        frame = _make_parser().build(
            MSG_TERMINAL_HEARTBEAT, "013912345678", 1,
            subpackage_total=3, subpackage_no=1,
        )
        msg = _make_parser().parse(frame)
        assert msg.subpackage_total == 3
        assert msg.subpackage_no == 1

    def test_no_subpackage_fields(self):
        frame = _build_frame(MSG_TERMINAL_HEARTBEAT, "013912345678", 1)
        msg = _make_parser().parse(frame)
        assert msg.subpackage_total is None
        assert msg.subpackage_no is None


class TestParserTerminalRegister:
    """0x0100 – Terminal registration."""

    def test_parse(self):
        province_id = 31
        city_id = 100
        manufacturer_id = b"MANUF"
        terminal_model = b"MODEL001            "  # 20 bytes
        terminal_id = b"TERM001"  # 7 bytes
        plate_color = 1
        plate_no = "沪A12345".encode("gbk")

        body = (
            struct.pack(">HH", province_id, city_id)
            + manufacturer_id
            + terminal_model
            + terminal_id
            + bytes([plate_color])
            + plate_no
        )
        frame = _build_frame(MSG_TERMINAL_REGISTER, "013912345678", 2, body)
        msg = _make_parser().parse(frame)
        assert msg.msg_id == MSG_TERMINAL_REGISTER
        assert msg.body["province_id"] == province_id
        assert msg.body["city_id"] == city_id
        assert msg.body["plate_color"] == plate_color
        assert "沪A12345" in msg.body["plate_no"]
