# SPDX-License-Identifier: Apache-2.0
"""Protocol constants (spec §4.5, §7.1, §7.2, §11.3)."""

VERSION = 0x01
VERSION_STRING = b"montauk-v1"
SESSION_INFO = b"montauk-v1-session"
ADDRESS_INFO = b"montauk-v1-address"
BUCKET_DURATION = 300
PORT_MIN = 1024
PORT_RANGE = 64511
BROKER_SERVICE_ID = bytes(16)

NOISE_PROTOCOL_NAME = b"Noise_IKpsk2_25519_ChaChaPoly_SHA256"
BROKER_PROLOGUE = b"montauk-broker-v1"  # prologue for the client<->broker link handshake (§8.3)

FIRST_PACKET_HEADER_LEN = 25  # version(1) + timestamp(8) + nonce(16), §7.2
MAX_FRAME_BODY = 65535  # UINT16 frame length, §7.1
TIMESTAMP_TOLERANCE = 30  # seconds, RECOMMENDED default, §11.3
HANDSHAKE_TIMEOUT = 5  # seconds to complete a handshake before dropping, §11.6
