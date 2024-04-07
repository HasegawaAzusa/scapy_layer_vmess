from dataclasses import dataclass
from uuid import UUID
import hashlib


@dataclass
class VMessID:
    """
    VMess ID

    Returns:
        uuid: 16 bytes, user uuid which used vmess key
        cmd_key: 16 bytes, command key generated by `uuid`
    """

    KEY_SALT = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"

    uuid: UUID

    cmd_key: bytes

    def __init__(self, uuid: UUID):
        self.uuid = uuid
        self.cmd_key = hashlib.md5(uuid.bytes + VMessID.KEY_SALT).digest()