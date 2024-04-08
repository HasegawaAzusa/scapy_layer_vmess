from uuid import UUID, uuid4
import hashlib


class VMessID:
    KEY_SALT = b"c48619fe-8f02-49e0-b9e9-edf763e17e21"
    uuid: UUID = uuid4()
    cmd_key: bytes = b""

    def __init__(self):
        """
        Single instance

        Raises:
            NotImplementedError
        """
        raise NotImplementedError

    @classmethod
    def set(cls, uuid: UUID):
        cls.uuid = uuid
        cls.cmd_key = hashlib.md5(uuid.bytes + VMessID.KEY_SALT).digest()


# This is default config uuid
VMessID.set(UUID("b831381d-6324-4d53-ad4f-8cda48b30811"))
