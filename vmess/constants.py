from typing import NamedTuple
from enum import IntFlag, IntEnum


class KDFSaltConstants(NamedTuple):
    AuthIDEncryptionKey = b"AES Auth ID Encryption"
    AEADRespHeaderLenKey = b"AEAD Resp Header Len Key"
    AEADRespHeaderLenIV = b"AEAD Resp Header Len IV"
    AEADRespHeaderPayloadKey = b"AEAD Resp Header Key"
    AEADRespHeaderPayloadIV = b"AEAD Resp Header IV"
    VMessAEADKDF = b"VMess AEAD KDF"
    VMessHeaderPayloadAEADKey = b"VMess Header AEAD Key"
    VMessHeaderPayloadAEADIV = b"VMess Header AEAD Nonce"
    VMessHeaderPayloadLengthAEADKey = b"VMess Header AEAD Key_Length"
    VMessHeaderPayloadLengthAEADIV = b"VMess Header AEAD Nonce_Length"


VMESS_CMD_KEY_SALT = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
VMESS_SHAKE_MAX_STORAGE = 2**8
VMESS_BODY_OPTIONS = [
    "ChunkStream(0x01)",
    "ConnectionReuse(0x02)",
    "ChunkMasking(0x04)",
    "GlobalPadding(0x08)",
    "AuthenticatedLength(0x10)",
]


class VMessBodyOptions(IntFlag):
    CHUNK_STREAM = 0x01
    CONNECTION_REUSE = 0x02
    CHUNK_MASKING = 0x04
    GLOBAL_PADDING = 0x08
    AUTHENTICATED_LENGTH = 0x10


VMESS_BODY_SECURITY = [
    "Unknown",
    "AES-128-CFB",
    "Auto",
    "AES-128-GCM",
    "ChaCha20-Poly1305",
    "None",
    "Zero",
]


class VMessBodySecurity(IntEnum):
    UNKNOWN = 0x00
    AES_128_CFB = 0x01
    AUTO = 0x02
    AES_128_GCM = 0x03
    CHACHA20_POLY1305 = 0x04
    NONE = 0x05
    ZERO = 0x06


VMESS_BODY_COMMAND = ["Unknown", "TCP", "UDP", "Mux"]


class VMessBodyCommand(IntFlag):
    UNKNOWN = 0x00
    TCP = 0x01
    UDP = 0x02
    MUX = 0x03


VMESS_BODY_ADDRESS_TYPE = ["Unknown", "IPv4", "Domain", "IPv6"]


class VMessBodyAddressType(IntFlag):
    UNKNOWN = 0x00
    IPV4 = 0x01
    DOMAIN = 0x02
    IPV6 = 0x03
