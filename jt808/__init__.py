"""jt808 – Python parser for the JT/T 808 GPS tracking protocol.

Basic usage::

    from jt808 import JT808Parser

    parser = JT808Parser()

    # Parse a raw frame received from a terminal
    msg = parser.parse(raw_bytes)
    print(msg.msg_id, msg.phone, msg.body)

    # Build a platform general reply
    import struct
    body = struct.pack(">HHB", msg.serial_no, msg.msg_id, 0)  # result=success
    frame = parser.build(0x8001, "000000000000", serial_no=1, body=body)
"""

from .constants import (
    ALARM_COLLISION,
    ALARM_EMERGENCY,
    ALARM_OVERSPEED,
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
from .parser import JT808Message, JT808Parser
from .utils import bcd_decode, bcd_encode, checksum, escape, unescape

__all__ = [
    # Core classes
    "JT808Parser",
    "JT808Message",
    # Utilities
    "escape",
    "unescape",
    "checksum",
    "bcd_encode",
    "bcd_decode",
    # Constants – message IDs
    "MSG_TERMINAL_GENERAL_REPLY",
    "MSG_TERMINAL_HEARTBEAT",
    "MSG_TERMINAL_REGISTER",
    "MSG_TERMINAL_REGISTER_AUTH",
    "MSG_LOCATION_REPORT",
    "MSG_PLATFORM_GENERAL_REPLY",
    "MSG_REGISTER_REPLY",
    # Constants – status / alarm
    "STATUS_ACC_ON",
    "STATUS_LOCATED",
    "ALARM_EMERGENCY",
    "ALARM_OVERSPEED",
    "ALARM_COLLISION",
    # Constants – extra info IDs
    "EXTRA_MILEAGE",
    # Constants – result codes
    "RESULT_SUCCESS",
    "REGISTER_RESULT_SUCCESS",
    # Framing
    "FRAME_DELIMITER",
]
