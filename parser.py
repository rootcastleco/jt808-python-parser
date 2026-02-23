from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple, List

# ==========================
# Constants
# ==========================

START_FLAG = 0x7e
ESCAPE = 0x7d
ESCAPE_7E = 0x02
ESCAPE_7D = 0x01

# Common Message IDs
MSG_TERMINAL_REGISTER = 0x0100
MSG_TERMINAL_AUTH = 0x0102
MSG_HEARTBEAT = 0x0002
MSG_LOCATION_REPORT = 0x0200
MSG_PLATFORM_RESPONSE = 0x8001

# Alarm bit definitions (JT/T 808-2019, Table 4)
ALARM_BITS = {
    0: "Emergency alarm",
    1: "Speeding alarm",
    2: "Fatigue driving alarm",
    3: "Dangerous driving alarm",
    4: "GNSS module failure",
    5: "GNSS antenna disconnected",
    6: "GNSS antenna short circuit",
    7: "Low terminal battery",
    8: "Terminal main power off",
    9: "LCD or display failure",
    10: "TTS module failure",
    11: "Camera failure",
    18: "Day driving overtime alarm",
    19: "Overtime parking alarm",
    20: "In-and-out area alarm",
    21: "In-and-out route alarm",
    22: "Route driving time insufficient/excess alarm",
    23: "Route deviation alarm",
    28: "VSS failure",
    29: "Oil level anomaly alarm",
    30: "Stolen vehicle alarm",
    31: "Illegal ignition alarm",
}

# Status bit definitions (JT/T 808-2019, Table 5)
# Only bits with standard definitions are listed; undefined bit positions are intentionally omitted.
STATUS_BITS = {
    0: "ACC on",
    1: "Positioned",
    2: "Latitude S (south) when set, N (north) when clear",
    3: "Longitude W (west) when set, E (east) when clear",
    4: "Operational",
    5: "Encrypted",
    10: "Open door",
    11: "Middle door open",
    12: "Back door open",
    13: "Driver door open",
    14: "Custom door open",
    18: "Using GPS",
    19: "Using BeiDou",
    20: "Using GLONASS",
    21: "Using Galileo",
}


# ==========================
# Data Classes
# ==========================

@dataclass
class JT808Header:
    msg_id: int
    body_len: int
    encryption: int
    has_subpackage: bool
    reserved: int
    phone: str
    flow_id: int
    total_subpackages: Optional[int] = None
    subpackage_seq: Optional[int] = None


@dataclass
class JT808Location:
    alarm: int
    status: int
    latitude: float
    longitude: float
    altitude: int
    speed: float
    direction: int
    time: str  # YYMMDDhhmmss
    extra: Dict[int, Any] = field(default_factory=dict)  # additional info items


@dataclass
class JT808Register:
    province_id: int
    city_id: int
    manufacturer_id: str   # 5 bytes (ASCII)
    terminal_model: str    # 20 bytes (ASCII, null-padded)
    terminal_id: str       # 7 bytes (ASCII, null-padded)
    license_plate_color: int
    license_plate: str     # GBK string


@dataclass
class JT808Auth:
    auth_code: str         # variable-length ASCII string


@dataclass
class JT808PlatformResponse:
    response_flow_id: int  # flow ID of the terminal message being acknowledged
    response_msg_id: int   # message ID of the terminal message being acknowledged
    result: int            # 0=success, 1=failure, 2=wrong message, 3=unsupported


@dataclass
class JT808Packet:
    header: JT808Header
    body_raw: bytes
    msg_id: int
    location: Optional[JT808Location] = None
    register: Optional[JT808Register] = None
    auth: Optional[JT808Auth] = None
    platform_response: Optional[JT808PlatformResponse] = None


# ==========================
# Utility Functions
# ==========================

def hexstr_to_bytes(s: str) -> bytes:
    """
    Convert a hex string like '7e 02 00 00' to bytes.
    Spaces and newlines are ignored.
    """
    s = s.replace(" ", "").replace("\n", "").replace("\r", "")
    return bytes.fromhex(s)


def bytes_to_hex(b: bytes) -> str:
    """
    Convert bytes to a space-separated hex string (for debugging).
    """
    return " ".join(f"{x:02X}" for x in b)


def unescape(data: bytes) -> bytes:
    """
    JT808 unescape:
      0x7d 0x02 -> 0x7e
      0x7d 0x01 -> 0x7d
    Applied to header+body+checksum inside 0x7e ... 0x7e. [web:13][web:19]
    """
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == ESCAPE and i + 1 < len(data):
            nxt = data[i + 1]
            if nxt == ESCAPE_7E:
                out.append(START_FLAG)
                i += 2
                continue
            elif nxt == ESCAPE_7D:
                out.append(ESCAPE)
                i += 2
                continue
        out.append(b)
        i += 1
    return bytes(out)


def escape(data: bytes) -> bytes:
    """
    JT808 escape for sending:
      0x7e -> 0x7d 0x02
      0x7d -> 0x7d 0x01 [web:13][web:19]
    """
    out = bytearray()
    for b in data:
        if b == START_FLAG:
            out.append(ESCAPE)
            out.append(ESCAPE_7E)
        elif b == ESCAPE:
            out.append(ESCAPE)
            out.append(ESCAPE_7D)
        else:
            out.append(b)
    return bytes(out)


def calc_checksum(data: bytes) -> int:
    """
    XOR all bytes from the first byte of header to the last byte of body. [web:3][web:10]
    """
    cs = 0
    for b in data:
        cs ^= b
    return cs & 0xFF


def bcd_to_str(b: bytes) -> str:
    """
    Decode BCD bytes to string, e.g. b'\u0001#' -> '0123'.
    Used for phone number and time fields. [web:10][web:21]
    """
    result = []
    for x in b:
        high = (x >> 4) & 0x0F
        low = x & 0x0F
        result.append(str(high))
        result.append(str(low))
    return "".join(result)


def decode_alarm_bits(alarm: int) -> List[str]:
    """
    Decode the alarm DWORD from a 0x0200 location report into a list of active alarm descriptions.
    """
    active = []
    for bit, name in ALARM_BITS.items():
        if (alarm >> bit) & 1:
            active.append(name)
    return active


def decode_status_bits(status: int) -> List[str]:
    """
    Decode the status DWORD from a 0x0200 location report into a list of active status descriptions.
    """
    active = []
    for bit, name in STATUS_BITS.items():
        if (status >> bit) & 1:
            active.append(name)
    return active


# ==========================
# Header Parsing
# ==========================

def parse_header(data: bytes) -> Tuple[JT808Header, int]:
    """
    Parse JT808 header from data (starting at index 0).
    Returns (header, header_length_bytes).
    Header format (without subpackage) is 12 bytes: [web:3][web:10][web:21]
      0-1: msg_id (WORD)
      2-3: body_props (WORD)
      4-9: phone (BCD, 6 bytes)
      10-11: flow_id (WORD)
    If subpackage bit set, then +4 bytes:
      12-13: total_subpackages (WORD)
      14-15: subpackage_seq (WORD)
    """
    if len(data) < 12:
        raise ValueError("Header too short")

    msg_id = int.from_bytes(data[0:2], "big")
    body_props = int.from_bytes(data[2:4], "big")

    body_len = body_props & 0x03FF  # bits 0-9
    encryption = (body_props >> 10) & 0x07  # bits 10-12
    has_subpackage = ((body_props >> 13) & 0x01) == 1  # bit 13
    reserved = (body_props >> 14) & 0x03  # bits 14-15

    phone_bcd = data[4:10]
    phone = bcd_to_str(phone_bcd).lstrip("0")

    flow_id = int.from_bytes(data[10:12], "big")

    idx = 12
    total_sub = None
    sub_seq = None

    if has_subpackage:
        if len(data) < 16:
            raise ValueError("Header indicates subpackage but data too short")
        total_sub = int.from_bytes(data[12:14], "big")
        sub_seq = int.from_bytes(data[14:16], "big")
        idx = 16

    header = JT808Header(
        msg_id=msg_id,
        body_len=body_len,
        encryption=encryption,
        has_subpackage=has_subpackage,
        reserved=reserved,
        phone=phone,
        flow_id=flow_id,
        total_subpackages=total_sub,
        subpackage_seq=sub_seq,
    )
    return header, idx


# ==========================
# 0x0200 Location Body Parsing
# ==========================

def parse_0200_base(body: bytes) -> Tuple[JT808Location, int]:
    """
    Parse the fixed part of 0x0200 (Location Report) body. [web:10][web:13]
    Layout (first 28 bytes):
      0-3   alarm (DWORD)
      4-7   status (DWORD)
      8-11  latitude (DWORD, 1e-6 degrees)
      12-15 longitude (DWORD, 1e-6 degrees)
      16-17 altitude (WORD, meter)
      18-19 speed (WORD, 1/10 km/h)
      20-21 direction (WORD, degrees)
      22-27 time (6 bytes BCD YYMMDDhhmmss)
    After that come additional info items.
    """
    if len(body) < 28:
        raise ValueError("0x0200 body too short for base part")

    alarm = int.from_bytes(body[0:4], "big")
    status = int.from_bytes(body[4:8], "big")
    lat_raw = int.from_bytes(body[8:12], "big")
    lon_raw = int.from_bytes(body[12:16], "big")
    altitude = int.from_bytes(body[16:18], "big")
    speed_raw = int.from_bytes(body[18:20], "big")
    direction = int.from_bytes(body[20:22], "big")
    time_bcd = body[22:28]

    latitude = lat_raw / 1_000_000.0
    longitude = lon_raw / 1_000_000.0
    speed = speed_raw / 10.0

    time_str = bcd_to_str(time_bcd)  # "YYMMDDhhmmss"

    loc = JT808Location(
        alarm=alarm,
        status=status,
        latitude=latitude,
        longitude=longitude,
        altitude=altitude,
        speed=speed,
        direction=direction,
        time=time_str,
        extra={},
    )
    return loc, 28


def parse_additional_items(body: bytes, start_idx: int) -> Dict[int, Any]:
    """
    Parse additional information items for 0x0200. [web:11][web:19]
    Each item format:
      1 byte: id
      1 byte: length (len)
      len bytes: value
    Returns a dictionary: {id: parsed_value}.
    Parsing of a few common IDs is implemented; others are stored as raw bytes.
    """
    idx = start_idx
    result: Dict[int, Any] = {}

    while idx + 2 <= len(body):
        item_id = body[idx]
        item_len = body[idx + 1]
        idx += 2

        if idx + item_len > len(body):
            # malformed, stop
            break

        value_bytes = body[idx:idx + item_len]
        idx += item_len

        # Common item examples (IDs may vary by version) [web:11][web:20]
        # 0x01: mileage (DWORD, 0.1 km)
        # 0x02: fuel (WORD, 0.1 liter)
        # 0x03: speed from tachograph (WORD, 0.1 km/h)
        # 0x25: signal strength, etc.
        if item_id == 0x01 and item_len == 4:
            val = int.from_bytes(value_bytes, "big") / 10.0
        elif item_id == 0x02 and item_len == 2:
            val = int.from_bytes(value_bytes, "big") / 10.0
        elif item_id == 0x03 and item_len == 2:
            val = int.from_bytes(value_bytes, "big") / 10.0
        else:
            # store raw bytes if we don't know this item
            val = value_bytes

        result[item_id] = val

    return result


def parse_0200_location(body: bytes) -> JT808Location:
    """
    Parse full 0x0200 location body: fixed part + additional items. [web:10][web:11]
    """
    loc, idx = parse_0200_base(body)
    loc.extra = parse_additional_items(body, idx)
    return loc


# ==========================
# 0x0100 Terminal Register Body Parsing
# ==========================

def parse_0100_register(body: bytes) -> JT808Register:
    """
    Parse the 0x0100 (Terminal Registration) message body.
    Layout:
      0-1   province_id (WORD)
      2-3   city_id (WORD)
      4-8   manufacturer_id (5 bytes, ASCII)
      9-28  terminal_model (20 bytes, ASCII, null-padded)
      29-35 terminal_id (7 bytes, ASCII, null-padded)
      36    license_plate_color (BYTE): 0=no plate, 1=blue, 2=yellow, 3=black, 4=white
      37+   license_plate (GBK string, variable length)
    """
    if len(body) < 37:
        raise ValueError("0x0100 body too short")

    province_id = int.from_bytes(body[0:2], "big")
    city_id = int.from_bytes(body[2:4], "big")
    manufacturer_id = body[4:9].decode("ascii", errors="replace").rstrip("\x00")
    terminal_model = body[9:29].decode("ascii", errors="replace").rstrip("\x00")
    terminal_id = body[29:36].decode("ascii", errors="replace").rstrip("\x00")
    license_plate_color = body[36]
    license_plate = body[37:].decode("gbk", errors="replace")

    return JT808Register(
        province_id=province_id,
        city_id=city_id,
        manufacturer_id=manufacturer_id,
        terminal_model=terminal_model,
        terminal_id=terminal_id,
        license_plate_color=license_plate_color,
        license_plate=license_plate,
    )


# ==========================
# 0x0102 Terminal Auth Body Parsing
# ==========================

def parse_0102_auth(body: bytes) -> JT808Auth:
    """
    Parse the 0x0102 (Terminal Authentication) message body.
    The body is a variable-length ASCII authentication code string.
    """
    auth_code = body.decode("ascii", errors="replace")
    return JT808Auth(auth_code=auth_code)


# ==========================
# 0x8001 Platform General Response Body Parsing
# ==========================

def parse_8001_platform_response(body: bytes) -> JT808PlatformResponse:
    """
    Parse the 0x8001 (Platform General Response) message body.
    Layout:
      0-1  response_flow_id (WORD) - flow ID of the terminal message being acknowledged
      2-3  response_msg_id (WORD)  - message ID of the terminal message being acknowledged
      4    result (BYTE)           - 0=success, 1=failure, 2=wrong message, 3=unsupported
    """
    if len(body) < 5:
        raise ValueError("0x8001 body too short")

    response_flow_id = int.from_bytes(body[0:2], "big")
    response_msg_id = int.from_bytes(body[2:4], "big")
    result = body[4]

    return JT808PlatformResponse(
        response_flow_id=response_flow_id,
        response_msg_id=response_msg_id,
        result=result,
    )


# ==========================
# Frame Parsing
# ==========================

def parse_jt808_frame(frame: bytes) -> JT808Packet:
    """
    Parse a single JT808 frame:
      0x7e <escaped header+body+checksum> 0x7e [web:3][web:10]
    Steps:
      - Check start/end flags
      - Unescape inner bytes
      - Verify checksum
      - Parse header
      - Parse body (currently 0x0200 location in detail)
    """
    if len(frame) < 5:
        raise ValueError("Frame too short")

    if frame[0] != START_FLAG or frame[-1] != START_FLAG:
        raise ValueError("Invalid start/end flag")

    # Remove flags and unescape
    inner = frame[1:-1]
    inner = unescape(inner)

    if len(inner) < 13:  # header + checksum minimum
        raise ValueError("Inner data too short")

    # Last byte is checksum
    data_no_cs = inner[:-1]
    recv_cs = inner[-1]
    calc_cs = calc_checksum(data_no_cs)
    if recv_cs != calc_cs:
        raise ValueError(
            f"Checksum mismatch: received=0x{recv_cs:02X}, calculated=0x{calc_cs:02X}"
        )

    # Parse header
    header, header_len = parse_header(data_no_cs)

    # Extract body
    body_start = header_len
    body_end = body_start + header.body_len
    if body_end > len(data_no_cs):
        raise ValueError("Body length exceeds available data")

    body = data_no_cs[body_start:body_end]

    pkt = JT808Packet(
        header=header,
        body_raw=body,
        msg_id=header.msg_id,
    )

    # Detailed body parsing for selected message IDs
    if header.msg_id == MSG_LOCATION_REPORT:
        pkt.location = parse_0200_location(body)
    elif header.msg_id == MSG_TERMINAL_REGISTER:
        pkt.register = parse_0100_register(body)
    elif header.msg_id == MSG_TERMINAL_AUTH:
        pkt.auth = parse_0102_auth(body)
    elif header.msg_id == MSG_PLATFORM_RESPONSE:
        pkt.platform_response = parse_8001_platform_response(body)
    # MSG_HEARTBEAT (0x0002) has no body; pkt fields remain None.

    # For additional message IDs, add parsers here.

    return pkt


# ==========================
# Frame Building (Optional)
# ==========================

def build_header(
    msg_id: int,
    body: bytes,
    phone: str,
    flow_id: int,
    encryption: int = 0,
    has_subpackage: bool = False,
    total_subpackages: int = 0,
    subpackage_seq: int = 0,
) -> bytes:
    """
    Build a JT808 header for sending.
    - phone: numeric string, up to 12 digits, BCD-encoded into 6 bytes. [web:10][web:21]
    """
    body_len = len(body)
    if body_len > 0x03FF:
        raise ValueError("Body too long for single packet")

    body_props = body_len & 0x03FF
    body_props |= (encryption & 0x07) << 10
    if has_subpackage:
        body_props |= 1 << 13

    # reserved bits (14-15) left 0

    # encode phone as BCD, 6 bytes (12 digits)
    phone = phone.zfill(12)[-12:]
    phone_bytes = bytearray()
    for i in range(0, 12, 2):
        d1 = int(phone[i])
        d2 = int(phone[i + 1])
        phone_bytes.append((d1 << 4) | d2)

    header = bytearray()
    header.extend(msg_id.to_bytes(2, "big"))
    header.extend(body_props.to_bytes(2, "big"))
    header.extend(phone_bytes)
    header.extend(flow_id.to_bytes(2, "big"))

    if has_subpackage:
        header.extend(total_subpackages.to_bytes(2, "big"))
        header.extend(subpackage_seq.to_bytes(2, "big"))

    return bytes(header)


def build_jt808_frame(
    msg_id: int,
    body: bytes,
    phone: str,
    flow_id: int,
    encryption: int = 0,
    has_subpackage: bool = False,
    total_subpackages: int = 0,
    subpackage_seq: int = 0,
) -> bytes:
    """
    Build a complete JT808 frame (0x7e ... 0x7e) including header, body, checksum and escaping. [web:3][web:10]
    """
    header = build_header(
        msg_id=msg_id,
        body=body,
        phone=phone,
        flow_id=flow_id,
        encryption=encryption,
        has_subpackage=has_subpackage,
        total_subpackages=total_subpackages,
        subpackage_seq=subpackage_seq,
    )
    data_no_cs = header + body
    cs = calc_checksum(data_no_cs)
    full = data_no_cs + bytes([cs])
    escaped = escape(full)
    frame = bytes([START_FLAG]) + escaped + bytes([START_FLAG])
    return frame


# ==========================
# Example Usage
# ==========================

if __name__ == "__main__":
    # Build a sample 0x0200 location report frame and parse it back.
    # Phone: 013800001234, Flow ID: 1
    # Location: lat=39.774000, lon=116.352000, alt=50m, speed=60.0 km/h, dir=90
    # Time: 2024-01-15 12:30:00 (BCD: 24 01 15 12 30 00)
    import struct

    alarm = 0
    status = 0b00000000_00000000_00000000_00000011  # ACC on + positioned
    lat_raw = int(39.774 * 1_000_000)   # 39774000
    lon_raw = int(116.352 * 1_000_000)  # 116352000
    altitude = 50
    speed_raw = 600   # 60.0 km/h
    direction = 90
    time_bcd = bytes([0x24, 0x01, 0x15, 0x12, 0x30, 0x00])  # 24/01/15 12:30:00

    body = struct.pack(">IIIIHHH", alarm, status, lat_raw, lon_raw, altitude, speed_raw, direction)
    body += time_bcd

    frame = build_jt808_frame(
        msg_id=MSG_LOCATION_REPORT,
        body=body,
        phone="013800001234",
        flow_id=1,
    )

    print("Raw Frame:", bytes_to_hex(frame))

    pkt = parse_jt808_frame(frame)

    print("Message ID:", f"0x{pkt.msg_id:04X}")
    print("Phone:", pkt.header.phone)
    print("Flow ID:", pkt.header.flow_id)
    print("Has subpackage:", pkt.header.has_subpackage)
    print("Body length:", pkt.header.body_len)

    if pkt.location:
        loc = pkt.location
        print("Location:")
        print("  Alarm:", loc.alarm, decode_alarm_bits(loc.alarm))
        print("  Status:", bin(loc.status), decode_status_bits(loc.status))
        print("  Latitude:", loc.latitude)
        print("  Longitude:", loc.longitude)
        print("  Altitude (m):", loc.altitude)
        print("  Speed (km/h):", loc.speed)
        print("  Direction:", loc.direction)
        print("  Time (YYMMDDhhmmss):", loc.time)
        print("  Extra items:", loc.extra)
    else:
        print("No location parsed (message id is not 0x0200).")
