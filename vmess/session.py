from scapy.packet import Packet
from typing import NamedTuple
from .constants import *
from .crypt import MaskerProtocol, AEADAuthenticatorProtocol


class VMessSessionData(NamedTuple):
    is_padding: bool
    masker: MaskerProtocol
    auth: AEADAuthenticatorProtocol


class VMessSessionManager:
    vmess_sessions: dict[str, VMessSessionData] = dict()

    def __init__(self) -> None:
        raise NotImplementedError

    @classmethod
    def extract_tcp(cls, pkt: Packet):
        # For Packet
        while pkt:
            if pkt.haslayer("TCP"):
                return pkt["TCP"]
            pkt = pkt.underlayer
        else:
            raise ValueError("Could not found TCP layer")

    @classmethod
    def extract_session_id(cls, pkt: Packet):
        tcp_pkt: Packet = cls.extract_tcp(pkt)
        sport = int(tcp_pkt.getfieldval("sport"))
        dport = int(tcp_pkt.getfieldval("dport"))
        return f"{sport}=>{dport}"

    @classmethod
    def extract_request_session_id(cls, pkt: Packet):
        return cls.extract_session_id(pkt)

    @classmethod
    def extract_response_session_id(cls, pkt: Packet):
        tcp_pkt: Packet = cls.extract_tcp(pkt)
        sport = int(tcp_pkt.getfieldval("sport"))
        dport = int(tcp_pkt.getfieldval("dport"))
        return f"{dport}=>{sport}"

    @classmethod
    def new(cls, session_id: str, session: VMessSessionData):
        cls.vmess_sessions[session_id] = session

    @classmethod
    def has(cls, session_id: str):
        return session_id in cls.vmess_sessions

    @classmethod
    def get(cls, session_id: str) -> VMessSessionData:
        return cls.vmess_sessions[session_id]
