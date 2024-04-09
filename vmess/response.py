from scapy.fields import Field, PacketField
from scapy.packet import Packet
from .body import VMessBody
from .header import VMessResponseHeader


class VMessResponse(Packet):
    name = "VMess Response"

    fields_desc: list[Field] = [
        PacketField("Header", None, VMessResponseHeader),
        PacketField("Body", None, VMessBody),
    ]

    def do_dissect(self, s: bytes) -> bytes:
        header_field, body_field = self.fields_desc
        header = None
        try:
            tmp_s, header = header_field.getfield(self, s)
        except:
            ...
        if header:
            self.setfieldval(header_field.name, header)
            s = tmp_s
        try:
            s, body = body_field.getfield(self, s)
            self.setfieldval(body_field.name, body)
        except:
            ...
        return super().do_dissect(s)