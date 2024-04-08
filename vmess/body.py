from scapy.fields import *
from scapy.packet import Packet
from .constants import *
from .crypt import *
from .session import VMessSessionManager, VMessSessionData


class VMessBody(Packet):
    name = "VMess Body"

    fields_desc: list[Field] = [
        ShortField("Length", 0),
        StrField("Data", b""),
        XStrField("Padding", b""),
    ]

    @classmethod
    def decrypt_body_length(cls, encrypted_body_length: bytes, mask: bytes):
        return bytes(i ^ j for i, j in zip(encrypted_body_length, mask))

    def do_dissect(self, s: bytes) -> bytes:
        body_length_field, body_data_field, body_padding_field = self.fields_desc
        # self.parent is VMessRequest or VMessResponse
        session_id = VMessSessionManager.extract_session_id(self.parent)
        vmess_session: VMessSessionData = VMessSessionManager.get(session_id)

        ### Body Length
        body_padding_length = 0
        if vmess_session.is_padding:
            padding_mask = vmess_session.masker.next()
            body_padding_length = int.from_bytes(padding_mask, "big") % 64

        encrypted_body_length = s[:2]
        decrypted_body_length = VMessBody.decrypt_body_length(
            encrypted_body_length, vmess_session.masker.next()
        )
        _, body_length = body_length_field.getfield(self, decrypted_body_length)
        self.setfieldval(body_length_field.name, body_length)
        s = s[2:]

        ### Body Data
        body_data_length = body_length - body_padding_length
        encrypted_body_data = s[:body_data_length]
        padding = s[body_data_length:body_length]
        decrypted_body_data = vmess_session.auth.decrypt(encrypted_body_data)
        s = s[body_length:]
        self.setfieldval(body_data_field.name, decrypted_body_data)
        self.setfieldval(body_padding_field.name, padding)

        return s
