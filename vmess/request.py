from scapy.fields import *
from scapy.packet import Packet
from scapy.layers.inet import TCP
from .body import VMessBody
from .constants import *
from .crypt import *
from .header import VMessAEADHeader
from .session import VMessSessionManager


class VMessRequest(Packet):
    name = "VMess Request"

    fields_desc: list[Field] = [
        PacketField("Header", None, VMessAEADHeader),
        PacketField("Body", None, VMessBody),
    ]

    def pre_dissect(self, s: bytes) -> bytes:
        if not self.underlayer.haslayer(TCP):
            raise ValueError("Must underlayer has TCP")
        return super().pre_dissect(s)

    def do_dissect(self, s: bytes) -> bytes:
        header_field, body_field = self.fields_desc
        session_id = VMessSessionManager.extract_request_session_id(self)
        if not VMessSessionManager.has(session_id):
            s, header = header_field.getfield(self, s)
            self.setfieldval(header_field.name, header)
        s, body = body_field.getfield(self, s)
        self.setfieldval(body_field.name, body)
        return s
