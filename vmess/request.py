from typing import NamedTuple
from scapy.fields import *
from scapy.packet import Packet, Raw
from scapy.layers.inet import TCP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dataclasses import dataclass
from .header import VMessAEADHeader, VMessPlainHeader, VMessAEADAuthID
from .constants import *
from .crypt import *
from .session import VMessSession
import hashlib
import itertools

class VMessRequestBody(Packet):
    name = "VMess Request Body"

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
        session_id = VMessRequest.extract_seesion_id(self.parent.underlayer)
        vmess_session: VMessSession = VMessSession.get(session_id)

        ### Body Length
        body_padding_length = 0
        option = vmess_session.header.getfieldval("Option")
        if vmess_session.masker and option & VMessBodyOptions.GLOBAL_PADDING:
            body_padding_length = vmess_session.masker.next_short() % 64

        encrypted_body_length = s[:2]
        if vmess_session.masker and option & VMessBodyOptions.CHUNK_MASKING:
            decrypted_body_length = VMessRequestBody.decrypt_body_length(
                encrypted_body_length, vmess_session.masker.next()
            )
        else:
            decrypted_body_length = encrypted_body_length
        _, body_length = body_length_field.getfield(self, decrypted_body_length)
        self.setfieldval(body_length_field.name, body_length)
        s = s[2:]

        ### Body Data
        body_data_length = body_length - body_padding_length
        encrypted_body_data = s[:body_data_length]
        padding = s[body_data_length:body_length]
        key = vmess_session.header.getfieldval("BodyKey")
        iv = vmess_session.header.getfieldval("BodyIV")
        security = vmess_session.header.getfieldval("Security")
        match security:
            case VMessBodySecurity.NONE:
                decrypted_body_data = encrypted_body_data
            case VMessBodySecurity.AES_128_CFB:
                raise NotImplementedError
                checksum = int.from_bytes(encrypted_body_data[:4], "big")
                real_encrypted_body_data = encrypted_body_data[4:]
                if fnv1a32(real_encrypted_body_data) != checksum:
                    return s
                # TODO: decrypt AES-128-CFB
            case VMessBodySecurity.AES_128_GCM:
                try:
                    aead = AESGCM(key)
                    count: int = next(vmess_session.counter)
                    nonce = (
                        count.to_bytes(2, "big")
                        + iv[2:12]
                    )
                    decrypted_body_data = aead.decrypt(nonce, encrypted_body_data, None)
                except:
                    decrypted_body_data = b"GCM Failed: " + encrypted_body_data
            case VMessBodySecurity.CHACHA20_POLY1305:
                raise NotImplementedError
            case _:
                return s
        s = s[body_length:]
        self.setfieldval(body_data_field.name, decrypted_body_data)
        self.setfieldval(body_padding_field.name, padding)

        return s

class VMessRequest(Packet):
    name = "VMess Request"

    fields_desc: list[Field] = [
        PacketField("Header", None, VMessAEADHeader),
        PacketField("Body", None, VMessRequestBody),
    ]

    @classmethod
    def extract_seesion_id(cls, pkt: TCP):
        sport = pkt.getfieldval("sport")
        dport = pkt.getfieldval("dport")
        return f'{sport}'
    
    def pre_dissect(self, s: bytes) -> bytes:
        if not self.underlayer.haslayer(TCP):
            raise ValueError("Must underlayer has TCP")
        return super().pre_dissect(s)
    
    def do_dissect(self, s: bytes) -> bytes:
        header_field, body_field = self.fields_desc
        session_id = VMessRequest.extract_seesion_id(self.underlayer)
        if not VMessSession.has(session_id):
            s, header = header_field.getfield(self, s)
            eheader: VMessPlainHeader = header.getfieldval("EHeader")
            VMessSession.new(session_id, eheader)
            self.setfieldval(header_field.name, header)
        s, body = body_field.getfield(self, s)
        self.setfieldval(body_field.name, body)
        return s

    # def do_dissect(self, s: bytes) -> bytes:
    #     global vmess_sessions
    #     header_field, session_field = self.fields_desc
    #     session_id = VMessRequest.extract_seesion_id(self.underlayer)
    #     # Create Session
    #     if session_id not in vmess_sessions:
    #         s, header = header_field.getfield(self, s)
    #         self.setfieldval(header_field.name, header)
    #         eheader: VMessPlainHeader = header.getfieldval("EHeader")
    #         vmess_session = VMessSession()
    #         vmess_session.setfieldval("RequestBodyKey", eheader.getfieldval("BodyKey"))
    #         vmess_session.setfieldval("RequestBodyIV", eheader.getfieldval("BodyIV"))
    #         vmess_session.setfieldval("Option", eheader.getfieldval("Option"))
    #         vmess_session.setfieldval("Security", eheader.getfieldval("Security"))
    #         masker = None
    #         if eheader.getfieldval("Option") & VMessBodyOptions.CHUNK_MASKING:
    #             masker = Shake128Masker(eheader.getfieldval("BodyIV"))
    #         new_session = VMessSessionTuple(vmess_session, masker, itertools.count())
    #         vmess_sessions[session_id] = new_session
        
    #     session_tuple = vmess_sessions[session_id]
    #     vmess_session: VMessSession = session_tuple.session.copy()
    #     body_data = s
    #     if session_tuple.masker is not None:
    #         if vmess_session.getfieldval("Option") & VMessBodyOptions.GLOBAL_PADDING:
    #             vmess_session.setfieldval("PaddingMask", session_tuple.masker.next())
    #         if vmess_session.getfieldval("Option") & VMessBodyOptions.CHUNK_MASKING:
    #             vmess_session.setfieldval("LengthMask", session_tuple.masker.next())
    #     vmess_session.setfieldval("AEADCount", next(session_tuple.counter))
    #     vmess_session.add_payload(body_data)
    #     vmess_session.decode_payload_as(VMessRequestBody)
    #     self.setfieldval(session_field.name, vmess_session)
    #     # vmess_session.show()
    #     # return vmess_session
    #     return b""