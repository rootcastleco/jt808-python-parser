"""
Unit tests for the JT808 Python Parser.

Run with:
    python -m pytest tests.py -v
or:
    python tests.py
"""

import struct
import unittest

from parser import (
    START_FLAG,
    MSG_HEARTBEAT,
    MSG_LOCATION_REPORT,
    MSG_TERMINAL_AUTH,
    MSG_TERMINAL_REGISTER,
    MSG_PLATFORM_RESPONSE,
    JT808Header,
    JT808Location,
    JT808Register,
    JT808Auth,
    JT808PlatformResponse,
    JT808Packet,
    hexstr_to_bytes,
    bytes_to_hex,
    unescape,
    escape,
    calc_checksum,
    bcd_to_str,
    decode_alarm_bits,
    decode_status_bits,
    parse_header,
    parse_0200_base,
    parse_additional_items,
    parse_0200_location,
    parse_0100_register,
    parse_0102_auth,
    parse_8001_platform_response,
    parse_jt808_frame,
    build_header,
    build_jt808_frame,
)


# ==========================
# Helper to build a 0x0200 body
# ==========================

def _make_location_body(
    alarm=0,
    status=0b11,
    lat=39774000,
    lon=116352000,
    alt=50,
    speed=600,
    direction=90,
    time_bcd=b"\x24\x01\x15\x12\x30\x00",
    extra=b"",
) -> bytes:
    base = struct.pack(">IIIIHHH", alarm, status, lat, lon, alt, speed, direction)
    base += time_bcd
    return base + extra


# ==========================
# Utility Tests
# ==========================

class TestHexstrToBytes(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(hexstr_to_bytes("7e02"), b"\x7e\x02")

    def test_spaces_and_newlines(self):
        self.assertEqual(hexstr_to_bytes("7e 02 00\n"), b"\x7e\x02\x00")

    def test_empty(self):
        self.assertEqual(hexstr_to_bytes(""), b"")


class TestBytesToHex(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(bytes_to_hex(b"\x7e\x02\xff"), "7E 02 FF")

    def test_empty(self):
        self.assertEqual(bytes_to_hex(b""), "")


class TestUnescape(unittest.TestCase):
    def test_escape_7e(self):
        # 0x7d 0x02 -> 0x7e
        self.assertEqual(unescape(bytes([0x7d, 0x02])), bytes([0x7e]))

    def test_escape_7d(self):
        # 0x7d 0x01 -> 0x7d
        self.assertEqual(unescape(bytes([0x7d, 0x01])), bytes([0x7d]))

    def test_passthrough(self):
        self.assertEqual(unescape(b"\x01\x02\x03"), b"\x01\x02\x03")

    def test_mixed(self):
        data = bytes([0x01, 0x7d, 0x02, 0x03, 0x7d, 0x01, 0x04])
        self.assertEqual(unescape(data), bytes([0x01, 0x7e, 0x03, 0x7d, 0x04]))

    def test_trailing_7d(self):
        # Lone 0x7d at end should pass through unchanged
        self.assertEqual(unescape(bytes([0x7d])), bytes([0x7d]))


class TestEscape(unittest.TestCase):
    def test_escape_7e(self):
        self.assertEqual(escape(bytes([0x7e])), bytes([0x7d, 0x02]))

    def test_escape_7d(self):
        self.assertEqual(escape(bytes([0x7d])), bytes([0x7d, 0x01]))

    def test_passthrough(self):
        self.assertEqual(escape(b"\x01\x02\x03"), b"\x01\x02\x03")

    def test_roundtrip(self):
        original = bytes([0x7e, 0x7d, 0x01, 0x02, 0x7e])
        self.assertEqual(unescape(escape(original)), original)


class TestCalcChecksum(unittest.TestCase):
    def test_all_same(self):
        self.assertEqual(calc_checksum(bytes([0xAA, 0xAA])), 0x00)

    def test_single(self):
        self.assertEqual(calc_checksum(bytes([0xAB])), 0xAB)

    def test_multi(self):
        data = bytes([0x01, 0x02, 0x03])
        expected = 0x01 ^ 0x02 ^ 0x03
        self.assertEqual(calc_checksum(data), expected)

    def test_empty(self):
        self.assertEqual(calc_checksum(b""), 0x00)


class TestBcdToStr(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(bcd_to_str(b"\x01\x23"), "0123")

    def test_zeros(self):
        self.assertEqual(bcd_to_str(b"\x00\x00\x00"), "000000")

    def test_phone(self):
        phone_bcd = bytes([0x01, 0x38, 0x00, 0x00, 0x12, 0x34])
        self.assertEqual(bcd_to_str(phone_bcd), "013800001234")


class TestDecodeAlarmBits(unittest.TestCase):
    def test_no_alarms(self):
        self.assertEqual(decode_alarm_bits(0), [])

    def test_emergency(self):
        result = decode_alarm_bits(0b1)  # bit 0
        self.assertIn("Emergency alarm", result)

    def test_speeding(self):
        result = decode_alarm_bits(0b10)  # bit 1
        self.assertIn("Speeding alarm", result)

    def test_multiple(self):
        result = decode_alarm_bits(0b11)  # bits 0 and 1
        self.assertIn("Emergency alarm", result)
        self.assertIn("Speeding alarm", result)


class TestDecodeStatusBits(unittest.TestCase):
    def test_no_status(self):
        self.assertEqual(decode_status_bits(0), [])

    def test_acc_on(self):
        result = decode_status_bits(0b1)  # bit 0
        self.assertIn("ACC on", result)

    def test_positioned(self):
        result = decode_status_bits(0b10)  # bit 1
        self.assertIn("Positioned", result)


# ==========================
# Header Parsing Tests
# ==========================

class TestParseHeader(unittest.TestCase):
    def _make_header_bytes(
        self,
        msg_id=0x0200,
        body_len=28,
        encryption=0,
        has_subpackage=False,
        phone_bcd=b"\x01\x38\x00\x00\x12\x34",
        flow_id=1,
    ) -> bytes:
        body_props = body_len & 0x03FF
        body_props |= (encryption & 0x07) << 10
        if has_subpackage:
            body_props |= 1 << 13
        header = struct.pack(">HH", msg_id, body_props)
        header += phone_bcd
        header += struct.pack(">H", flow_id)
        return header

    def test_basic_header(self):
        data = self._make_header_bytes()
        hdr, idx = parse_header(data)
        self.assertEqual(hdr.msg_id, 0x0200)
        self.assertEqual(hdr.body_len, 28)
        self.assertEqual(hdr.encryption, 0)
        self.assertFalse(hdr.has_subpackage)
        # phone_bcd 01 38 00 00 12 34 decodes to "013800001234"; leading zero is stripped
        self.assertEqual(hdr.phone, "13800001234")
        self.assertEqual(hdr.flow_id, 1)
        self.assertEqual(idx, 12)

    def test_subpackage_header(self):
        base = self._make_header_bytes(has_subpackage=True)
        # Append subpackage fields: total=2, seq=1
        base += struct.pack(">HH", 2, 1)
        hdr, idx = parse_header(base)
        self.assertTrue(hdr.has_subpackage)
        self.assertEqual(hdr.total_subpackages, 2)
        self.assertEqual(hdr.subpackage_seq, 1)
        self.assertEqual(idx, 16)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_header(b"\x00" * 5)


# ==========================
# 0x0200 Location Parsing Tests
# ==========================

class TestParse0200Base(unittest.TestCase):
    def test_basic(self):
        body = _make_location_body()
        loc, idx = parse_0200_base(body)
        self.assertAlmostEqual(loc.latitude, 39.774, places=3)
        self.assertAlmostEqual(loc.longitude, 116.352, places=3)
        self.assertEqual(loc.altitude, 50)
        self.assertAlmostEqual(loc.speed, 60.0, places=1)
        self.assertEqual(loc.direction, 90)
        self.assertEqual(loc.time, "240115123000")
        self.assertEqual(idx, 28)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_0200_base(b"\x00" * 10)


class TestParseAdditionalItems(unittest.TestCase):
    def test_mileage_item(self):
        # item_id=0x01, len=4, value=1234 (unit: 0.1 km)
        extra = bytes([0x01, 0x04, 0x00, 0x00, 0x04, 0xD2])
        result = parse_additional_items(extra, 0)
        self.assertIn(0x01, result)
        self.assertAlmostEqual(result[0x01], 123.4, places=1)

    def test_fuel_item(self):
        # item_id=0x02, len=2, value=500 (unit: 0.1 liter = 50.0 liters)
        extra = bytes([0x02, 0x02, 0x01, 0xF4])
        result = parse_additional_items(extra, 0)
        self.assertIn(0x02, result)
        self.assertAlmostEqual(result[0x02], 50.0, places=1)

    def test_unknown_item_stored_as_bytes(self):
        extra = bytes([0xFF, 0x03, 0xAA, 0xBB, 0xCC])
        result = parse_additional_items(extra, 0)
        self.assertIn(0xFF, result)
        self.assertEqual(result[0xFF], bytes([0xAA, 0xBB, 0xCC]))

    def test_malformed_truncated(self):
        # item claims 4 bytes but only 2 available
        extra = bytes([0x01, 0x04, 0x00, 0x00])
        result = parse_additional_items(extra, 0)
        self.assertEqual(result, {})

    def test_empty(self):
        self.assertEqual(parse_additional_items(b"", 0), {})


# ==========================
# 0x0100 Register Parsing Tests
# ==========================

class TestParse0100Register(unittest.TestCase):
    def _make_register_body(self) -> bytes:
        body = struct.pack(">HH", 31, 100)         # province=31, city=100
        body += b"ROOTC"                             # manufacturer_id (5 bytes)
        body += b"ModelX".ljust(20, b"\x00")        # terminal_model (20 bytes)
        body += b"T001".ljust(7, b"\x00")[:7]       # terminal_id (7 bytes)
        body += bytes([1])                           # license_plate_color=1 (blue)
        body += "A12345".encode("gbk")              # license_plate
        return body

    def test_basic(self):
        body = self._make_register_body()
        reg = parse_0100_register(body)
        self.assertEqual(reg.province_id, 31)
        self.assertEqual(reg.city_id, 100)
        self.assertEqual(reg.manufacturer_id, "ROOTC")
        self.assertEqual(reg.terminal_model, "ModelX")
        self.assertEqual(reg.terminal_id, "T001")
        self.assertEqual(reg.license_plate_color, 1)
        self.assertEqual(reg.license_plate, "A12345")

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_0100_register(b"\x00" * 10)


# ==========================
# 0x0102 Auth Parsing Tests
# ==========================

class TestParse0102Auth(unittest.TestCase):
    def test_basic(self):
        auth = parse_0102_auth(b"MyAuthToken123")
        self.assertEqual(auth.auth_code, "MyAuthToken123")

    def test_empty(self):
        auth = parse_0102_auth(b"")
        self.assertEqual(auth.auth_code, "")


# ==========================
# 0x8001 Platform Response Parsing Tests
# ==========================

class TestParse8001PlatformResponse(unittest.TestCase):
    def test_success(self):
        body = struct.pack(">HHB", 5, 0x0200, 0)  # flow=5, msg=0x0200, result=success
        resp = parse_8001_platform_response(body)
        self.assertEqual(resp.response_flow_id, 5)
        self.assertEqual(resp.response_msg_id, 0x0200)
        self.assertEqual(resp.result, 0)

    def test_failure(self):
        body = struct.pack(">HHB", 3, 0x0100, 1)
        resp = parse_8001_platform_response(body)
        self.assertEqual(resp.result, 1)

    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_8001_platform_response(b"\x00\x00\x00")


# ==========================
# Frame Parsing Tests (build + parse roundtrip)
# ==========================

class TestBuildAndParseFrame(unittest.TestCase):
    def test_location_roundtrip(self):
        body = _make_location_body()
        frame = build_jt808_frame(
            msg_id=MSG_LOCATION_REPORT,
            body=body,
            phone="013800001234",
            flow_id=1,
        )
        # Must start and end with 0x7E
        self.assertEqual(frame[0], START_FLAG)
        self.assertEqual(frame[-1], START_FLAG)

        pkt = parse_jt808_frame(frame)
        self.assertEqual(pkt.msg_id, MSG_LOCATION_REPORT)
        self.assertEqual(pkt.header.phone, "13800001234")
        self.assertEqual(pkt.header.flow_id, 1)
        self.assertIsNotNone(pkt.location)
        self.assertAlmostEqual(pkt.location.latitude, 39.774, places=3)
        self.assertAlmostEqual(pkt.location.longitude, 116.352, places=3)
        self.assertEqual(pkt.location.altitude, 50)
        self.assertAlmostEqual(pkt.location.speed, 60.0, places=1)
        self.assertEqual(pkt.location.direction, 90)
        self.assertEqual(pkt.location.time, "240115123000")

    def test_location_with_extra_items(self):
        # Add mileage (0x01) extra item: 1234 -> 123.4 km
        extra = bytes([0x01, 0x04, 0x00, 0x00, 0x04, 0xD2])
        body = _make_location_body(extra=extra)
        frame = build_jt808_frame(
            msg_id=MSG_LOCATION_REPORT,
            body=body,
            phone="013800001234",
            flow_id=2,
        )
        pkt = parse_jt808_frame(frame)
        self.assertIsNotNone(pkt.location)
        self.assertAlmostEqual(pkt.location.extra[0x01], 123.4, places=1)

    def test_heartbeat_frame(self):
        frame = build_jt808_frame(
            msg_id=MSG_HEARTBEAT,
            body=b"",
            phone="013800001234",
            flow_id=10,
        )
        pkt = parse_jt808_frame(frame)
        self.assertEqual(pkt.msg_id, MSG_HEARTBEAT)
        self.assertIsNone(pkt.location)
        self.assertIsNone(pkt.register)
        self.assertIsNone(pkt.auth)
        self.assertIsNone(pkt.platform_response)

    def test_auth_frame(self):
        body = b"AuthCode999"
        frame = build_jt808_frame(
            msg_id=MSG_TERMINAL_AUTH,
            body=body,
            phone="013800001234",
            flow_id=3,
        )
        pkt = parse_jt808_frame(frame)
        self.assertEqual(pkt.msg_id, MSG_TERMINAL_AUTH)
        self.assertIsNotNone(pkt.auth)
        self.assertEqual(pkt.auth.auth_code, "AuthCode999")

    def test_platform_response_frame(self):
        body = struct.pack(">HHB", 1, MSG_LOCATION_REPORT, 0)
        frame = build_jt808_frame(
            msg_id=MSG_PLATFORM_RESPONSE,
            body=body,
            phone="013800001234",
            flow_id=100,
        )
        pkt = parse_jt808_frame(frame)
        self.assertEqual(pkt.msg_id, MSG_PLATFORM_RESPONSE)
        self.assertIsNotNone(pkt.platform_response)
        self.assertEqual(pkt.platform_response.response_msg_id, MSG_LOCATION_REPORT)
        self.assertEqual(pkt.platform_response.result, 0)

    def test_escaped_bytes_in_frame(self):
        # Build a frame where the body contains 0x7e and 0x7d bytes that must be escaped
        body = _make_location_body(alarm=0x7E7D0000)  # triggers escaping
        frame = build_jt808_frame(
            msg_id=MSG_LOCATION_REPORT,
            body=body,
            phone="013800001234",
            flow_id=99,
        )
        # The inner bytes (between the two 0x7E flags) must not contain bare 0x7E
        inner = frame[1:-1]
        self.assertNotIn(0x7E, inner)

        pkt = parse_jt808_frame(frame)
        self.assertEqual(pkt.location.alarm, 0x7E7D0000)

    def test_checksum_mismatch_raises(self):
        body = _make_location_body()
        frame = bytearray(build_jt808_frame(
            msg_id=MSG_LOCATION_REPORT,
            body=body,
            phone="013800001234",
            flow_id=1,
        ))
        # Corrupt the second-to-last byte (checksum position before final 0x7e)
        frame[-2] ^= 0xFF
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            parse_jt808_frame(bytes(frame))

    def test_invalid_start_flag_raises(self):
        body = _make_location_body()
        frame = bytearray(build_jt808_frame(
            msg_id=MSG_LOCATION_REPORT,
            body=body,
            phone="013800001234",
            flow_id=1,
        ))
        frame[0] = 0x00
        with self.assertRaises(ValueError):
            parse_jt808_frame(bytes(frame))

    def test_frame_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_jt808_frame(b"\x7e\x00\x7e")


if __name__ == "__main__":
    unittest.main(verbosity=2)
