from uuid import UUID
from scapy.packet import bind_layers
from scapy.layers.inet import TCP
from .identity import VMessID

__vmess_id = VMessID(UUID("b831381d-6324-4d53-ad4f-8cda48b30811"))


def set_id(uuid: UUID):
    global __vmess_id
    __vmess_id = VMessID(uuid)


def vmess_id():
    return __vmess_id


from .request import VMessRequest
from .response import VMessResponse


def bind(port: int):
    """
    Bind layers between TCP and VMess

    Args:
        port (int): Proxy server port
    """
    bind_layers(TCP, VMessRequest, dport=port)
    bind_layers(TCP, VMessResponse, sport=port)
