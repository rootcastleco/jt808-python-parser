# jt808-python-parser

A lightweight, pure-Python implementation of the **JT/T 808** (JT808) vehicle tracking protocol parser and frame builder, maintained by [rootcastle](https://github.com/rootcastleco).

---

## Features

- **Zero dependencies** – uses only the Python standard library
- **Frame parsing** – unescape, checksum verification, header + body decoding
- **Frame building** – construct valid JT808 frames ready to send
- **Message type support**:
  - `0x0002` – Terminal Heartbeat (no body)
  - `0x0100` – Terminal Registration
  - `0x0102` – Terminal Authentication
  - `0x0200` – Location Report (fixed part + additional info items)
  - `0x8001` – Platform General Response
- **Alarm & status bit decoding** – human-readable descriptions for all standard alarm and status flags
- **Comprehensive unit tests** included

---

## Protocol Overview

JT/T 808 is a Chinese national standard (GB/T 19056) for vehicle tracking terminals communicating with a fleet management platform over TCP/UDP. Each JT808 frame has the structure:

```
0x7E | <escaped: header + body + checksum> | 0x7E
```

Byte stuffing rules:
- `0x7E` inside the frame → `0x7D 0x02`
- `0x7D` inside the frame → `0x7D 0x01`

The checksum is the XOR of all bytes from the first header byte to the last body byte.

---

## Installation

No installation required. Copy `parser.py` into your project:

```bash
cp parser.py your_project/
```

Python 3.8 or later is required.

---

## Quick Start

### Parse a location report frame

```python
from parser import parse_jt808_frame, decode_alarm_bits, decode_status_bits

# Raw JT808 frame bytes (must start and end with 0x7E)
frame = bytes.fromhex("7e020000...")

pkt = parse_jt808_frame(frame)

print(f"Message ID : 0x{pkt.msg_id:04X}")
print(f"Phone      : {pkt.header.phone}")
print(f"Flow ID    : {pkt.header.flow_id}")

if pkt.location:
    loc = pkt.location
    print(f"Latitude   : {loc.latitude}")
    print(f"Longitude  : {loc.longitude}")
    print(f"Altitude   : {loc.altitude} m")
    print(f"Speed      : {loc.speed} km/h")
    print(f"Direction  : {loc.direction}°")
    print(f"Time       : {loc.time}")          # YYMMDDhhmmss
    print(f"Alarms     : {decode_alarm_bits(loc.alarm)}")
    print(f"Status     : {decode_status_bits(loc.status)}")
    print(f"Extra items: {loc.extra}")
```

### Build a location report frame

```python
import struct
from parser import build_jt808_frame, MSG_LOCATION_REPORT

alarm     = 0
status    = 0b11          # ACC on + positioned
lat_raw   = int(39.774 * 1_000_000)
lon_raw   = int(116.352 * 1_000_000)
altitude  = 50            # metres
speed_raw = 600           # 60.0 km/h (unit: 1/10 km/h)
direction = 90            # degrees
time_bcd  = bytes([0x24, 0x01, 0x15, 0x12, 0x30, 0x00])  # 2024-01-15 12:30:00

body = struct.pack(">IIIIHHH", alarm, status, lat_raw, lon_raw, altitude, speed_raw, direction)
body += time_bcd

frame = build_jt808_frame(
    msg_id=MSG_LOCATION_REPORT,
    body=body,
    phone="013800001234",
    flow_id=1,
)
# Send `frame` over your TCP/UDP connection
```

### Parse a terminal registration frame

```python
from parser import parse_jt808_frame, MSG_TERMINAL_REGISTER

pkt = parse_jt808_frame(frame_bytes)
if pkt.register:
    reg = pkt.register
    print(f"Province ID        : {reg.province_id}")
    print(f"City ID            : {reg.city_id}")
    print(f"Manufacturer ID    : {reg.manufacturer_id}")
    print(f"Terminal Model     : {reg.terminal_model}")
    print(f"Terminal ID        : {reg.terminal_id}")
    print(f"License Plate Color: {reg.license_plate_color}")
    print(f"License Plate      : {reg.license_plate}")
```

---

## API Reference

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `START_FLAG` | `0x7E` | Frame delimiter |
| `MSG_HEARTBEAT` | `0x0002` | Heartbeat message ID |
| `MSG_TERMINAL_REGISTER` | `0x0100` | Terminal registration message ID |
| `MSG_TERMINAL_AUTH` | `0x0102` | Terminal authentication message ID |
| `MSG_LOCATION_REPORT` | `0x0200` | Location report message ID |
| `MSG_PLATFORM_RESPONSE` | `0x8001` | Platform general response message ID |

---

### Data Classes

#### `JT808Header`
| Field | Type | Description |
|-------|------|-------------|
| `msg_id` | `int` | Message ID |
| `body_len` | `int` | Body length in bytes |
| `encryption` | `int` | Encryption flag (bits 10–12 of body properties word) |
| `has_subpackage` | `bool` | Whether the message is split across subpackages |
| `reserved` | `int` | Reserved bits |
| `phone` | `str` | Terminal phone number (BCD-decoded, leading zeros stripped) |
| `flow_id` | `int` | Message flow sequence number |
| `total_subpackages` | `int \| None` | Total subpackage count (when `has_subpackage=True`) |
| `subpackage_seq` | `int \| None` | Subpackage sequence number (when `has_subpackage=True`) |

#### `JT808Location`
| Field | Type | Description |
|-------|------|-------------|
| `alarm` | `int` | Alarm flags DWORD |
| `status` | `int` | Status flags DWORD |
| `latitude` | `float` | Latitude in decimal degrees |
| `longitude` | `float` | Longitude in decimal degrees |
| `altitude` | `int` | Altitude in metres |
| `speed` | `float` | Speed in km/h |
| `direction` | `int` | Heading in degrees (0–359, 0 = North) |
| `time` | `str` | Timestamp as `YYMMDDhhmmss` (BCD-decoded) |
| `extra` | `dict` | Additional info items `{item_id: value}` |

#### `JT808Register`
| Field | Type | Description |
|-------|------|-------------|
| `province_id` | `int` | Province code |
| `city_id` | `int` | City code |
| `manufacturer_id` | `str` | 5-byte ASCII manufacturer identifier |
| `terminal_model` | `str` | 20-byte ASCII terminal model (null-trimmed) |
| `terminal_id` | `str` | 7-byte ASCII terminal identifier (null-trimmed) |
| `license_plate_color` | `int` | 0=no plate, 1=blue, 2=yellow, 3=black, 4=white |
| `license_plate` | `str` | License plate number (GBK-decoded) |

#### `JT808Auth`
| Field | Type | Description |
|-------|------|-------------|
| `auth_code` | `str` | Authentication token string |

#### `JT808PlatformResponse`
| Field | Type | Description |
|-------|------|-------------|
| `response_flow_id` | `int` | Flow ID of the terminal message being acknowledged |
| `response_msg_id` | `int` | Message ID of the terminal message being acknowledged |
| `result` | `int` | 0=success, 1=failure, 2=wrong message, 3=unsupported |

#### `JT808Packet`
| Field | Type | Description |
|-------|------|-------------|
| `header` | `JT808Header` | Parsed header |
| `body_raw` | `bytes` | Raw (unescaped) body bytes |
| `msg_id` | `int` | Message ID (mirror of `header.msg_id`) |
| `location` | `JT808Location \| None` | Parsed location (0x0200 only) |
| `register` | `JT808Register \| None` | Parsed registration (0x0100 only) |
| `auth` | `JT808Auth \| None` | Parsed auth (0x0102 only) |
| `platform_response` | `JT808PlatformResponse \| None` | Parsed platform response (0x8001 only) |

---

### Functions

#### Parsing

```python
parse_jt808_frame(frame: bytes) -> JT808Packet
```
Parse a complete JT808 frame including unescape and checksum verification.

```python
parse_header(data: bytes) -> tuple[JT808Header, int]
```
Parse a JT808 header from raw bytes. Returns `(header, header_length)`.

```python
parse_0200_location(body: bytes) -> JT808Location
```
Parse a 0x0200 location report body (fixed fields + additional info items).

```python
parse_0100_register(body: bytes) -> JT808Register
```
Parse a 0x0100 terminal registration body.

```python
parse_0102_auth(body: bytes) -> JT808Auth
```
Parse a 0x0102 terminal authentication body.

```python
parse_8001_platform_response(body: bytes) -> JT808PlatformResponse
```
Parse a 0x8001 platform general response body.

#### Building

```python
build_jt808_frame(msg_id, body, phone, flow_id, encryption=0,
                  has_subpackage=False, total_subpackages=0, subpackage_seq=0) -> bytes
```
Build a complete, escaped JT808 frame ready to send.

```python
build_header(msg_id, body, phone, flow_id, ...) -> bytes
```
Build only the header bytes (useful when assembling frames manually).

#### Utilities

```python
unescape(data: bytes) -> bytes      # Remove JT808 byte stuffing
escape(data: bytes) -> bytes        # Apply JT808 byte stuffing
calc_checksum(data: bytes) -> int   # XOR checksum over all bytes
bcd_to_str(b: bytes) -> str        # Decode packed BCD to digit string
hexstr_to_bytes(s: str) -> bytes   # Parse hex string to bytes
bytes_to_hex(b: bytes) -> str      # Format bytes as hex string

decode_alarm_bits(alarm: int) -> list[str]   # Active alarm descriptions
decode_status_bits(status: int) -> list[str] # Active status descriptions
```

---

## Additional Info Items (0x0200 Extra)

Parsed automatically into `JT808Location.extra` as `{item_id: value}`:

| ID | Length | Value |
|----|--------|-------|
| `0x01` | 4 | Mileage (DWORD ÷ 10, km) |
| `0x02` | 2 | Fuel level (WORD ÷ 10, litres) |
| `0x03` | 2 | Tachograph speed (WORD ÷ 10, km/h) |
| others | variable | Raw `bytes` |

---

## Running the Tests

```bash
python tests.py
```

Or with pytest (if installed):

```bash
pip install pytest
pytest tests.py -v
```

---

## License

This project is licensed under the terms of the [LICENSE](LICENSE) file.

---

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/rootcastleco/jt808-python-parser).

