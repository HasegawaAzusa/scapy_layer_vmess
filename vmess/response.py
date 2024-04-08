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
