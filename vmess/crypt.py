import hashlib
import hmac
import itertools
from typing import Protocol
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .constants import KDFSaltConstants, VMESS_SHAKE_MAX_STORAGE


class VMessHMAC(hmac.HMAC):
    block_size = 64

    # Equal to `new()`
    def __call__(self, msg: bytes = b""):
        copy = self.copy()
        copy.update(msg)
        return copy


def kdf(key: bytes, path: list[bytes] = None):
    if path is None:
        path = []
    h = VMessHMAC(KDFSaltConstants.VMessAEADKDF, digestmod=hashlib.sha256)
    for v in path:
        h = VMessHMAC(v, digestmod=h)
    return h(key).digest()


def kdf16(key: bytes, path: list[bytes] = None):
    return kdf(key, path)[:16]


def kdf12(key: bytes, path: list[bytes] = None):
    return kdf(key, path)[:12]


def fnv1a32(data: bytes) -> int:
    hash_ = 0x811C9DC5
    for byte in data:
        hash_ = 0x01000193 * (hash_ ^ byte) & 0xFFFFFFFF
    return hash_

def gen_resp_key(body_key: bytes):
    """
    Generate response body key

    Args:
        body_key (bytes): request body key

    Returns:
        bytes: response body key
    """
    return hashlib.sha256(body_key).digest()[0:16]

def gen_resp_iv(body_iv: bytes):
    """
    Generate response body iv

    Args:
        body_iv (bytes): request body iv

    Returns:
        bytes: response body iv
    """
    return hashlib.sha256(body_iv).digest()[0:16]

class MaskerProtocol(Protocol):
    def next(self) -> bytes:
        """
        Return the next mask, 2 bytes

        Returns:
            bytes: mask
        """
        ...


class EmptyMasker(MaskerProtocol):
    def next(self) -> bytes:
        return b"\x00\x00"


class Shake128Masker:
    mask_storage: bytes
    index: int = 0

    def __init__(self, nonce: bytes):
        shake = hashes.Hash(hashes.SHAKE128(VMESS_SHAKE_MAX_STORAGE))
        shake.update(nonce)
        self.mask_storage = shake.finalize()

    def next(self):
        mask = self.mask_storage[self.index : self.index + 2]
        self.index += 2
        return mask


class AEADAuthenticatorProtocol(Protocol):
    body_key: bytes
    body_iv: bytes
    cipher: Cipher

    def decrypt(self, data: bytes):
        """
        Decrypt data

        Args:
            data (bytes): need to decrypt
        """
        ...


class GCMAuthenticator(AEADAuthenticatorProtocol):
    def __init__(self, body_key: bytes, body_iv: bytes):
        self.body_key = body_key
        self.body_iv = body_iv
        self.cipher = AESGCM(body_key)
        self.counter = itertools.count()

    def decrypt(self, data: bytes):
        nonce = next(self.counter).to_bytes(2, "big") + self.body_iv[2:12]
        return self.cipher.decrypt(nonce, data, None)
