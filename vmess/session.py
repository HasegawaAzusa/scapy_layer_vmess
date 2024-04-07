from dataclasses import dataclass, field
import itertools
from .constants import *
from .crypt import Shake128Masker
from .header import VMessPlainHeader

vmess_sessions: dict[str, 'VMessSession'] = dict()
@dataclass
class VMessSession:
    header: VMessPlainHeader
    counter: itertools.count
    masker: Shake128Masker

    @classmethod
    def new(cls, session_id: str, header: VMessPlainHeader):
        global vmess_sessions
        masker = None
        if header.getfieldval("Option") & VMessBodyOptions.CHUNK_MASKING:
            masker = Shake128Masker(header.getfieldval("BodyIV"))
        vmess_sessions[session_id] = VMessSession(header, itertools.count(), masker)
    
    @classmethod
    def has(cls, session_id: str):
        global vmess_sessions
        return session_id in vmess_sessions

    @classmethod
    def get(cls, session_id: str):
        global vmess_sessions
        return vmess_sessions[session_id]