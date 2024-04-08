from .identity import VMessID
from .request import VMessRequest
from .response import VMessResponse


def bind(port: int):
    """
    Bind layers between TCP and VMess

    Args:
        port (int): Proxy server port
    """
    from scapy.packet import bind_layers
    from scapy.layers.inet import TCP

    bind_layers(TCP, VMessRequest, dport=port)
    bind_layers(TCP, VMessResponse, sport=port)
