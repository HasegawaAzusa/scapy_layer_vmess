from scapy.compat import List, Tuple
from scapy.fields import *
from scapy.fields import Field
from scapy.packet import Packet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
import itertools
from scapy.error import warning
from .constants import *
from .crypt import *
from . import vmess_id, next_count, reset_count

class VMessAEADPlainAuthID(Packet):
    name = "VMess AEAD Auth ID"
    fields_desc: list[Field] = [
        LongField("Timestamp", 0),
        IntField("Rand", 0),
        IntField("CRC", 0),
    ]

    def extract_padding(self, s):
        return "", s

class VMessAEADPlainHeader(Packet):
    name = "VMess AEAD Header"
    fields_desc: list[Field] = [
        ByteField("Version", 1),
        XStrFixedLenField("BodyIV", b"", 16),
        XStrFixedLenField("BodyKey", b"", 16),
        ByteField("ResponseVerify", 0),
        FlagsField("Option", 0x01, 8, VMESS_BODY_OPTIONS),
        BitFixedLenField("PaddingLength", 0, lambda _: 4),
        BitEnumField("Security", 0, 4, VMESS_BODY_SECURITY),
        ByteField("Reversed", 0),
        BitEnumField("Command", 0, 8, VMESS_BODY_COMMAND),
        ShortField("Port", 0),
        BitEnumField("AddressType", 0, 8, VMESS_BODY_ADDRESS_TYPE),
        ConditionalField(IPField("IPv4", 0), lambda pkt: pkt.AddressType == 0x01),
        ConditionalField(
            ByteField("DomainLength", 0), lambda pkt: pkt.AddressType == 0x02
        ),
        ConditionalField(
            StrFixedLenField("Domain", 0, length_from=lambda pkt: pkt.DomainLength),
            lambda pkt: pkt.AddressType == 0x02,
        ),
        ConditionalField(IP6Field("IPv6", 0), lambda pkt: pkt.AddressType == 0x03),
        XStrFixedLenField("Padding", b"", length_from=lambda pkt: pkt.PaddingLength),
        IntField("CheckSum", 0),
    ]

    def extract_padding(self, s):
        return "", s


class VMessAEADRequest(Packet):

    name = "VMess Request Header"

    fields_desc: list[Field] = [
        PacketField("AuthID", None, VMessAEADPlainAuthID),
        ShortField("HeaderLength", 0),
        XStrFixedLenField("Nonce", b"", 8),
        PacketField("Header", None, VMessAEADPlainHeader),
        ShortField("BodyLength", 0),
        StrField("BodyData", b""),
        XStrField("BodyPadding", b"")
    ]

    @classmethod
    def decrypt_auth_id(cls, encrypted_auth_id: bytes):
        assert len(encrypted_auth_id) == 16
        key = kdf16(vmess_id().cmd_key, [KDFSaltConstants.AuthIDEncryptionKey])
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        auth_id = decryptor.update(encrypted_auth_id) + decryptor.finalize()

        checksum = binascii.crc32(auth_id[:12])
        if checksum == int.from_bytes(auth_id[-4:]):
            return auth_id
        return None

    @classmethod
    def decrypt_header_length(
        cls, encrypted_header_length: bytes, encrypted_auth_id: bytes, nonce: bytes
    ):
        assert len(encrypted_header_length) == 18
        header_length_key = kdf16(
            vmess_id().cmd_key,
            [
                KDFSaltConstants.VMessHeaderPayloadLengthAEADKey,
                encrypted_auth_id,
                nonce,
            ],
        )
        header_length_nonce = kdf12(
            vmess_id().cmd_key,
            [KDFSaltConstants.VMessHeaderPayloadLengthAEADIV, encrypted_auth_id, nonce],
        )
        aesgcm = AESGCM(header_length_key)
        decrypted_header_length = aesgcm.decrypt(
            header_length_nonce, encrypted_header_length, encrypted_auth_id
        )
        return decrypted_header_length

    @classmethod
    def decrypt_header(
        cls, encrypted_header: bytes, encrypted_auth_id: bytes, nonce: bytes
    ):
        assert len(encrypted_header) > 16
        header_key = kdf16(
            vmess_id().cmd_key,
            [KDFSaltConstants.VMessHeaderPayloadAEADKey, encrypted_auth_id, nonce],
        )
        header_nonce = kdf12(
            vmess_id().cmd_key,
            [KDFSaltConstants.VMessHeaderPayloadAEADIV, encrypted_auth_id, nonce],
        )
        aesgcm = AESGCM(header_key)
        decrypted_header = aesgcm.decrypt(
            header_nonce, encrypted_header, encrypted_auth_id
        )
        return decrypted_header

    @classmethod
    def check_header(cls, decrypted_header: bytes):
        checksum = int.from_bytes(decrypted_header[-4:], "big")
        return fnv1a32(decrypted_header[:-4]) == checksum

    def do_dissect(self, s: bytes) -> bytes:
        reset_count()
        if len(s) < 16:
            raise ValueError("Request header length should not less than 16")
        ### EAuID
        encrypted_auth_id = s[:16]
        auth_id = VMessAEADRequest.decrypt_auth_id(encrypted_auth_id)
        if auth_id is None:
            raise ValueError("Could not parse auth id")

        _, fval = self.get_field("AuthID").getfield(self, auth_id)
        self.setfieldval("AuthID", fval)
        s = s[16:]

        ### ELength
        encrypted_header_length = s[:18]
        nonce = s[18 : 18 + 8]
        _, fval = self.get_field("Nonce").getfield(self, nonce)
        self.setfieldval("Nonce", fval)
        decrypted_header_length = VMessAEADRequest.decrypt_header_length(
            encrypted_header_length, encrypted_auth_id, nonce
        )
        header_length = int.from_bytes(decrypted_header_length, "big")
        self.setfieldval("HeaderLength", header_length)
        s = s[18 + 8 :]

        ### EHeader
        encrypted_header = s[: 16 + header_length]
        decrypted_header = VMessAEADRequest.decrypt_header(
            encrypted_header, encrypted_auth_id, nonce
        )
        if not VMessAEADRequest.check_header(decrypted_header):
            return s
        _, fval = self.get_field("Header").getfield(self, decrypted_header)
        self.setfieldval("Header", fval)
        s = s[16 + header_length :]


        ### BodyLength & BodyPaddingLength
        masker = None
        body_padding_length = 0
        if self.Header.Option & VMessBodyOptions.CHUNK_MASKING:
            masker = Shake128Masker(self.Header.BodyIV)
        
        if masker is not None and self.Header.Option & VMessBodyOptions.GLOBAL_PADDING:
            body_padding_length = masker.next_short() % 64
        
        encrypted_body_length = s[:2]
        if masker is None:
            decrypted_body_length = encrypted_body_length
        else:
            decrypted_body_length = bytes(i ^ j for i, j in zip(encrypted_body_length, masker.next()))
        _, body_length = self.get_field("BodyLength").getfield(self, decrypted_body_length)
        self.setfieldval("BodyLength", body_length)
        s = s[2:]

        ### Body = Data + Padding
        body_data_length = body_length - body_padding_length
        encrypted_body_data = s[:body_data_length]
        padding = s[body_data_length:body_length]
        match self.Header.Security:
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
                    aead = AESGCM(self.Header.BodyKey)
                    nonce = next_count().to_bytes(2, "big") + self.Header.BodyIV[2:12]
                    decrypted_body_data = aead.decrypt(nonce, encrypted_body_data, None)
                except:
                    warning("AES-128-GCM decrypt error")
            case VMessBodySecurity.CHACHA20_POLY1305:
                raise NotImplementedError
            case _:
                return s
        s = s[body_length:]
        self.setfieldval("BodyData", decrypted_body_data)
        self.setfieldval("BodyPadding", padding)
        return s

    def extract_padding(self, s):
        return s, ""

