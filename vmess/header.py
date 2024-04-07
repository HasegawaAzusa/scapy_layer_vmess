import itertools
from scapy.fields import *
from scapy.packet import Packet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .constants import *
from .crypt import *
from . import vmess_id
import binascii


class VMessAEADAuthID(Packet):
    name = "VMess AEAD Auth ID"
    fields_desc: list[Field] = [
        LongField("Timestamp", 0),
        IntField("Rand", 0),
        IntField("CRC", 0),
    ]

    @classmethod
    def decrypt_auid(cls, encrypted_auid: bytes):
        assert len(encrypted_auid) == 16
        key = kdf16(vmess_id().cmd_key, [KDFSaltConstants.AuthIDEncryptionKey])
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted_auid = decryptor.update(encrypted_auid) + decryptor.finalize()

        checksum = binascii.crc32(decrypted_auid[:12])
        if checksum != int.from_bytes(decrypted_auid[-4:]):
            raise ValueError("Auth ID checksum failed")
        return decrypted_auid

    def pre_dissect(self, s: bytes) -> bytes:
        assert len(s) >= 16, "Auth ID must be greater than or equal 16"
        ### EAuID
        encrypted_auth_id = s[:16]
        decrypted_auth_id = VMessAEADAuthID.decrypt_auid(encrypted_auth_id)
        checksum = binascii.crc32(decrypted_auth_id[:12])

        # checksum
        if checksum != int.from_bytes(decrypted_auth_id[-4:]):
            raise ValueError("Could not parse auth id")
        return decrypted_auth_id + s[16:]

    def extract_padding(self, s):
        return b"", s

    def do_build(self) -> bytes:
        key = kdf16(vmess_id().cmd_key, [KDFSaltConstants.AuthIDEncryptionKey])
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        decrypted_auth_id = super().do_build()
        encrypted_auth_id = encryptor.update(decrypted_auth_id) + encryptor.finalize()
        return encrypted_auth_id


class VMessPlainHeader(Packet):
    name = "VMess Header"
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


class VMessAEADHeader(Packet):
    name = "VMess AEAD Header"
    fields_desc: list[Field] = [
        PacketField("EAuID", None, VMessAEADAuthID),
        ShortField("ELength", 0),
        XStrFixedLenField("Nonce", b"", 8),
        PacketField("EHeader", None, VMessPlainHeader),
    ]

    @classmethod
    def decrypt_length(
        cls, encrypted_length: bytes, encrypted_auth_id: bytes, nonce: bytes
    ):
        assert len(encrypted_length) == 18
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
            header_length_nonce, encrypted_length, encrypted_auth_id
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

    def pre_dissect(self, s: bytes) -> bytes:
        assert len(s) >= 42, "AEAD Header must be greater than or equal 42"
        return super().pre_dissect(s)

    def do_dissect(self, s: bytes) -> bytes:
        auid_field, length_field, nonce_field, header_field = self.fields_desc
        ### EAuID
        encrypted_auid = s[:16]
        _, auid = auid_field.getfield(self, encrypted_auid)
        self.setfieldval(auid_field.name, auid)
        s = s[16:]

        ### ELength
        masked_length = s[:18]
        nonce = s[18 : 18 + 8]
        _, Nonce = nonce_field.getfield(self, nonce)
        self.setfieldval(nonce_field.name, Nonce)
        decrypted_length = VMessAEADHeader.decrypt_length(
            masked_length, encrypted_auid, nonce
        )
        _, length = length_field.getfield(self, decrypted_length)
        self.setfieldval(length_field.name, length)
        s = s[18 + 8 :]

        ### EHeader
        encrypted_header = s[: 16 + length]
        decrypted_header = VMessAEADHeader.decrypt_header(
            encrypted_header, encrypted_auid, nonce
        )
        if not VMessAEADHeader.check_header(decrypted_header):
            return s
        _, header = header_field.getfield(self, decrypted_header)
        self.setfieldval(header_field.name, header)
        s = s[16 + length :]

        return s

    def extract_padding(self, s):
        return b"", s
