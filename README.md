# jt808-python-parser

A Python library for parsing and building [JT/T 808](https://en.wikipedia.org/wiki/JT808) GPS tracking protocol messages.

JT808 (JT/T 808-2019) is a Chinese national standard that defines the binary communication protocol between GPS vehicle tracking devices and platform servers.

## Features

- **Parse** raw JT808 frames into structured Python objects
- **Build** JT808 frames from Python dictionaries
- Handles **byte-stuffing** (escape/unescape of `0x7E` and `0x7D`)
- **Checksum** verification (XOR)
- **BCD** phone number encoding/decoding
- Supports **sub-packaged** (fragmented) messages
- Parses **location additional info** (extra items in `0x0200`)

## Supported Messages

| Message ID | Direction | Description |
|---|---|---|
| `0x0001` | Terminal → Platform | Terminal general reply |
| `0x0002` | Terminal → Platform | Terminal heartbeat |
| `0x0100` | Terminal → Platform | Terminal registration |
| `0x0102` | Terminal → Platform | Terminal authentication |
| `0x0200` | Terminal → Platform | Location information report |
| `0x0704` | Terminal → Platform | Location batch upload |
| `0x8001` | Platform → Terminal | Platform general reply |
| `0x8100` | Platform → Terminal | Terminal registration reply |

Unknown message IDs are parsed with an empty `body` dict; the raw bytes are available in `body_raw`.

## Installation

```bash
pip install jt808-python-parser
```

Or install from source:

```bash
git clone https://github.com/rootcastleco/jt808-python-parser.git
cd jt808-python-parser
pip install -e .
```

## Quick Start

### Parse a frame

```python
from jt808 import JT808Parser

parser = JT808Parser()

# raw_frame is bytes received from the terminal socket,
# e.g. b'\x7e\x02\x00\x00\x05\x01\x39\x12\x34\x56\x78\x00\x01\xca\x7e'
msg = parser.parse(raw_frame)

print(f"Message ID : 0x{msg.msg_id:04X}")
print(f"Phone      : {msg.phone}")
print(f"Serial No  : {msg.serial_no}")
print(f"Body       : {msg.body}")
```

### Parse a location report (`0x0200`)

```python
from jt808 import JT808Parser, MSG_LOCATION_REPORT

parser = JT808Parser()
msg = parser.parse(raw_frame)

if msg.msg_id == MSG_LOCATION_REPORT:
    b = msg.body
    print(f"Lat/Lng : {b['latitude']:.6f}, {b['longitude']:.6f}")
    print(f"Speed   : {b['speed']:.1f} km/h")
    print(f"Time    : {b['time']}")      # 'YYMMDDHHmmss'
    print(f"Alarm   : 0x{b['alarm']:08X}")
    print(f"Status  : 0x{b['status']:08X}")
```

### Build a platform general reply (`0x8001`)

```python
import struct
from jt808 import JT808Parser, MSG_PLATFORM_GENERAL_REPLY, RESULT_SUCCESS

parser = JT808Parser()

# Reply to the received message
body = struct.pack(">HHB", msg.serial_no, msg.msg_id, RESULT_SUCCESS)
frame = parser.build(
    msg_id=MSG_PLATFORM_GENERAL_REPLY,
    phone=msg.phone,
    serial_no=1,
    body=body,
)
# send `frame` back to the terminal
```

### Build a heartbeat acknowledgement

```python
import struct
from jt808 import JT808Parser, MSG_PLATFORM_GENERAL_REPLY, MSG_TERMINAL_HEARTBEAT, RESULT_SUCCESS

parser = JT808Parser()
body = struct.pack(">HHB", msg.serial_no, MSG_TERMINAL_HEARTBEAT, RESULT_SUCCESS)
frame = parser.build(MSG_PLATFORM_GENERAL_REPLY, phone=msg.phone, serial_no=42, body=body)
```

## API Reference

### `JT808Parser(strict=True)`

| Method | Description |
|---|---|
| `parse(frame: bytes) → JT808Message` | Parse a complete frame (including `0x7E` delimiters). Raises `ValueError` on framing/checksum errors when `strict=True`. |
| `build(msg_id, phone, serial_no, body=b"", encrypt=0, subpackage_total=None, subpackage_no=None) → bytes` | Build a complete framed message. |

### `JT808Message` (NamedTuple)

| Field | Type | Description |
|---|---|---|
| `msg_id` | `int` | 16-bit message identifier |
| `attributes` | `int` | Raw 16-bit attributes word |
| `phone` | `str` | Terminal phone number (12-digit BCD-decoded string) |
| `serial_no` | `int` | Message serial number |
| `subpackage_total` | `int \| None` | Total sub-packets (`None` if not sub-packaged) |
| `subpackage_no` | `int \| None` | Current sub-packet index (`None` if not sub-packaged) |
| `body` | `dict` | Parsed message body |
| `body_raw` | `bytes` | Raw (unescaped) body bytes |

### Utility functions

```python
from jt808 import escape, unescape, checksum, bcd_encode, bcd_decode
```

| Function | Description |
|---|---|
| `escape(data: bytes) → bytes` | Apply JT808 byte-stuffing |
| `unescape(data: bytes) → bytes` | Reverse byte-stuffing |
| `checksum(data: bytes) → int` | XOR checksum |
| `bcd_encode(digits: str) → bytes` | Encode decimal string to BCD |
| `bcd_decode(data: bytes) → str` | Decode BCD bytes to decimal string |

## Frame Structure

```
+------+--------+------------------+------+------+
| 0x7E | Header | Body (escaped)   |  CS  | 0x7E |
+------+--------+------------------+------+------+
```

**Header** (12 bytes, or 16 bytes with sub-packet flag):

```
+----------+--------------+---------------+-----------+
| Msg ID   | Attributes   | Phone (BCD)   | Serial No |
| 2 bytes  | 2 bytes      | 6 bytes       | 2 bytes   |
+----------+--------------+---------------+-----------+
```

**Message Attributes** (16 bits):
- Bits 0–9: Body length
- Bits 10–12: Encryption type
- Bit 13: Sub-packet flag
- Bit 14: Reserved

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT – see [LICENSE](LICENSE).
