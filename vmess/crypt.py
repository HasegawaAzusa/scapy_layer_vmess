import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
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

class Shake128Masker:
    mask_storage: bytes
    index: int = 0

    def __init__(self, nonce: bytes):
        shake = hashes.Hash(hashes.SHAKE128(VMESS_SHAKE_MAX_STORAGE))
        shake.update(nonce)
        self.mask_storage = shake.finalize()
    
    def next(self):
        mask = self.mask_storage[self.index:self.index+2]
        self.index += 2
        return mask
    
    def next_short(self):
        return int.from_bytes(self.next())