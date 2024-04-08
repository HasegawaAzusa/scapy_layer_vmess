from scapy.fields import *
from scapy.packet import Packet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .constants import *
from .session import VMessSessionManager, VMessSessionData
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

    def create_request_session(self) -> VMessSessionData:
        """
        Create VMessSessionData from header(header.Option, header.Security, header.BodyKey, header.BodyIV)

        Returns:
            VMessSessionData: VMess Session Data
        """
        option = self.getfieldval("Option")
        security = self.getfieldval("Security")
        body_key = self.getfieldval("BodyKey")
        body_iv = self.getfieldval("BodyIV")
        is_padding = bool(option & VMessBodyOptions.GLOBAL_PADDING)
        masker = EmptyMasker()
        if option & VMessBodyOptions.CHUNK_MASKING:
            masker = Shake128Masker(body_iv)
        auth = None
        match security:
            case VMessBodySecurity.AES_128_GCM:
                auth = GCMAuthenticator(body_key, body_iv)
            case _:
                raise NotImplementedError
        return VMessSessionData(is_padding, masker, auth)
    
    def create_response_session(self) -> VMessSessionData:
        """
        Create VMessSessionData from header(header.Option, header.Security, header.BodyKey, header.BodyIV)

        Returns:
            VMessSessionData: VMess Session Data
        """
        option = self.getfieldval("Option")
        security = self.getfieldval("Security")
        body_key = self.getfieldval("BodyKey")
        body_iv = self.getfieldval("BodyIV")
        resp_key = gen_resp_key(body_key)
        resp_iv = gen_resp_iv(body_iv)
        is_padding = bool(option & VMessBodyOptions.GLOBAL_PADDING)
        masker = EmptyMasker()
        if option & VMessBodyOptions.CHUNK_MASKING:
            masker = Shake128Masker(resp_iv)
        auth = None
        match security:
            case VMessBodySecurity.AES_128_GCM:
                auth = GCMAuthenticator(resp_key, resp_iv)
            case _:
                raise NotImplementedError
        return VMessSessionData(is_padding, masker, auth)

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

    @classmethod
    def create_response_auth_from_header(
        self, header: VMessPlainHeader
    ) -> AEADAuthenticatorProtocol:
        """
        Create Response Authenticator from header(header.Security, header.BodyKey, header.BodyIV)


        Args:
            header (VMessPlainHeader): VMess Header.EHeader

        Returns:
            AEADAuthenticatorProtocol: Authenticator
        """
        security = header.getfieldval("Security")
        body_key = header.getfieldval("BodyKey")
        body_iv = header.getfieldval("BodyIV")
        resp_key = VMessAEADHeader.gen_resp_key(body_key)
        resp_iv = VMessAEADHeader.gen_resp_iv(body_iv)
        match security:
            case VMessBodySecurity.AES_128_GCM:
                return GCMAuthenticator(resp_key, resp_iv)
            case _:
                raise NotImplementedError

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

        ### Init Session
        header: VMessPlainHeader
        client_session = header.create_request_session()
        server_session = header.create_response_session()
        client_session_id = VMessSessionManager.extract_request_session_id(self.parent)
        server_session_id = VMessSessionManager.extract_response_session_id(self.parent)
        VMessSessionManager.new(client_session_id, client_session)
        VMessSessionManager.new(server_session_id, server_session)

        return s

    def extract_padding(self, s):
        return b"", s


class VMessResponseHeader(Packet):
    name = "VMess Response Header"

    fields_desc: list[Field] = [
        ByteField("ResponseVerify", 0),
        ByteField("Option", 0),
        ByteField("Command", 0),
        ByteField("CommandLength", 0),
        XStrFixedLenField(
            "CommandData", b"", length_from=lambda pkt: pkt.CommandLength
        ),
    ]

    @classmethod
    def decrypt_length(
        cls, encrypted_header_length: bytes, resp_key: bytes, resp_iv: bytes
    ) -> bytes:
        assert len(encrypted_header_length) == 18
        header_length_key = kdf16(resp_key, [KDFSaltConstants.AEADRespHeaderLenKey])
        header_length_nonce = kdf12(resp_iv, [KDFSaltConstants.AEADRespHeaderLenIV])
        decrypted_header_length = AESGCM(header_length_key).decrypt(
            header_length_nonce,
            encrypted_header_length,
            None,
        )
        return decrypted_header_length

    @classmethod
    def decrypt_header(
        cls, encrypted_header: bytes, resp_key: bytes, resp_iv: bytes
    ) -> bytes:
        assert len(encrypted_header) >= 16
        header_key = kdf16(resp_key, [KDFSaltConstants.AEADRespHeaderPayloadKey])
        header_nonce = kdf12(resp_iv, [KDFSaltConstants.AEADRespHeaderPayloadIV])
        decrypted_header = AESGCM(header_key).decrypt(
            header_nonce,
            encrypted_header,
            None,
        )
        return decrypted_header

    def pre_dissect(self, s: bytes) -> bytes:
        session_id = VMessSessionManager.extract_session_id(self.parent)
        vmess_session = VMessSessionManager.get(session_id)
        body_key = vmess_session.auth.body_key
        body_iv = vmess_session.auth.body_iv

        ### Header Length
        encrypted_header_length = s[:18]
        decrypted_header_length = VMessResponseHeader.decrypt_length(
            encrypted_header_length,
            body_key,
            body_iv,
        )
        header_length = int.from_bytes(decrypted_header_length, "big")
        s = s[18:]

        ### Header
        encrypted_header = s[:header_length + 16]
        decrypted_header = VMessResponseHeader.decrypt_header(encrypted_header, body_key, body_iv)
        s = s[header_length+16:]
        return decrypted_header + s

    def extract_padding(self, s):
        return b"", s
