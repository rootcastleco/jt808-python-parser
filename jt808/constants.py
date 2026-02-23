"""JT808 protocol constants: message IDs, flags, and result codes."""

# ---------------------------------------------------------------------------
# Message IDs – terminal → platform
# ---------------------------------------------------------------------------

MSG_TERMINAL_GENERAL_REPLY = 0x0001
"""Terminal general response."""

MSG_TERMINAL_HEARTBEAT = 0x0002
"""Terminal heartbeat."""

MSG_TERMINAL_REGISTER = 0x0100
"""Terminal registration."""

MSG_TERMINAL_REGISTER_AUTH = 0x0102
"""Terminal authentication."""

MSG_LOCATION_REPORT = 0x0200
"""Location information report."""

MSG_LOCATION_BATCH_UPLOAD = 0x0704
"""Location information batch upload."""

MSG_DRIVER_ID_REPORT = 0x0702
"""Driver identity information collection and reporting."""

# ---------------------------------------------------------------------------
# Message IDs – platform → terminal
# ---------------------------------------------------------------------------

MSG_PLATFORM_GENERAL_REPLY = 0x8001
"""Platform general response."""

MSG_REGISTER_REPLY = 0x8100
"""Terminal registration reply."""

MSG_SET_TERMINAL_PARAMS = 0x8103
"""Set terminal parameters."""

MSG_QUERY_TERMINAL_PARAMS = 0x8104
"""Query terminal parameters."""

MSG_TERMINAL_CONTROL = 0x8105
"""Terminal control."""

MSG_QUERY_TERMINAL_ATTRIBUTES = 0x8107
"""Query terminal attributes."""

MSG_QUERY_TERMINAL_ATTRIBUTES_REPLY = 0x0107
"""Terminal attributes reply."""

MSG_SET_TERMINAL_PARAMS_REPLY = 0x0104
"""Terminal parameters query reply."""

MSG_LOCATION_INFO_QUERY = 0x8201
"""Location information query."""

MSG_LOCATION_INFO_QUERY_REPLY = 0x0201
"""Location information query reply."""

MSG_TEMP_LOCATION_TRACK = 0x8202
"""Temporary position tracking control."""

MSG_TEXT_MESSAGE = 0x8300
"""Text message delivery."""

# ---------------------------------------------------------------------------
# Registration result codes (0x8100)
# ---------------------------------------------------------------------------

REGISTER_RESULT_SUCCESS = 0x00
REGISTER_RESULT_VEHICLE_REGISTERED = 0x01
REGISTER_RESULT_NO_VEHICLE = 0x02
REGISTER_RESULT_TERMINAL_REGISTERED = 0x03
REGISTER_RESULT_NO_TERMINAL = 0x04

# ---------------------------------------------------------------------------
# General reply result codes (0x0001 / 0x8001)
# ---------------------------------------------------------------------------

RESULT_SUCCESS = 0x00
RESULT_FAILURE = 0x01
RESULT_MSG_ERROR = 0x02
RESULT_UNSUPPORTED = 0x03
RESULT_ALARM_ACK = 0x04

# ---------------------------------------------------------------------------
# Location status bits (status word in 0x0200)
# ---------------------------------------------------------------------------

STATUS_ACC_ON = 1 << 0
"""ACC ignition status: 1 = on."""

STATUS_LOCATED = 1 << 1
"""Positioning status: 1 = located."""

STATUS_LATITUDE_SOUTH = 1 << 2
"""Latitude: 0 = north, 1 = south."""

STATUS_LONGITUDE_WEST = 1 << 3
"""Longitude: 0 = east, 1 = west."""

STATUS_OPERATION_MODE = 1 << 4
"""Operating status: 0 = operating, 1 = stop."""

STATUS_LAT_LNG_ENCRYPTED = 1 << 5
"""Latitude/longitude encrypted: 1 = encrypted."""

STATUS_LOAD_HALF = 1 << 8
STATUS_LOAD_FULL = 1 << 9
STATUS_OIL_CUTOFF = 1 << 10
STATUS_CIRCUIT_DISCONNECTED = 1 << 11
STATUS_DOOR_LOCKED = 1 << 12

# ---------------------------------------------------------------------------
# Location alarm bits (alarm word in 0x0200)
# ---------------------------------------------------------------------------

ALARM_EMERGENCY = 1 << 0
ALARM_OVERSPEED = 1 << 1
ALARM_FATIGUE_DRIVING = 1 << 2
ALARM_DANGEROUS_DRIVING = 1 << 3
ALARM_GNSS_FAULT = 1 << 4
ALARM_GNSS_ANTENNA_SHORT = 1 << 5
ALARM_GNSS_ANTENNA_DISCONNECTED = 1 << 6
ALARM_POWER_LOW = 1 << 7
ALARM_POWER_CUTOFF = 1 << 8
ALARM_LCD_FAULT = 1 << 9
ALARM_TTS_FAULT = 1 << 10
ALARM_CAMERA_FAULT = 1 << 11
ALARM_IC_CARD_FAULT = 1 << 12
ALARM_OVERSPEED_WARNING = 1 << 13
ALARM_FATIGUE_WARNING = 1 << 14
ALARM_ILLEGAL_IGNITION = 1 << 18
ALARM_ILLEGAL_DISPLACEMENT = 1 << 19
ALARM_COLLISION = 1 << 20
ALARM_ROLLOVER = 1 << 21

# ---------------------------------------------------------------------------
# Additional information (附加信息) item IDs in location messages
# ---------------------------------------------------------------------------

EXTRA_MILEAGE = 0x01
EXTRA_FUEL = 0x02
EXTRA_SPEED = 0x03
EXTRA_ALARM_EVENT_ID = 0x04
EXTRA_TYRE_PRESSURE = 0x05
EXTRA_TEMPERATURE = 0x06
EXTRA_OVERSPEED_EXTRA = 0x11
EXTRA_IN_OUT_AREA = 0x12
EXTRA_IN_OUT_ROUTE = 0x13
EXTRA_ROUTE_DRIVE_DURATION = 0x14
EXTRA_DRIVER_SIGNAL = 0x25
EXTRA_IO_STATUS = 0x2A
EXTRA_ANALOG = 0x2B
EXTRA_WIFI_SIGNAL = 0x2C
EXTRA_GNSS_SATELLITES = 0x30
EXTRA_GNSS_SIGNAL = 0x31
EXTRA_CUSTOM_INFO = 0xE0

# ---------------------------------------------------------------------------
# Framing constants
# ---------------------------------------------------------------------------

FRAME_DELIMITER = 0x7E
ESCAPE_CHAR = 0x7D
ESCAPE_7E = 0x02  # 0x7E → 0x7D 0x02
ESCAPE_7D = 0x01  # 0x7D → 0x7D 0x01

HEADER_SIZE = 12
SUBPACKAGE_HEADER_EXTRA = 4  # extra bytes when subpackage flag is set
