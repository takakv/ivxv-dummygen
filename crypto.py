import secrets

from fastecdsa.curve import P384
from fastecdsa.point import Point

from ciphertext import ElGamalCiphertext
from utils import decode_from_point, encode_to_point

ENCODING_MAX_TRIES = 10


class EGPublicKey:
    def __init__(self, H: Point):
        self.H = H

    def encrypt(self, M: Point) -> ElGamalCiphertext:
        r = secrets.randbelow(self.H.curve.q)
        return ElGamalCiphertext(self.H.curve.G * r, M + (self.H * r))

    def encode_and_encrypt(self, m: str, shift=ENCODING_MAX_TRIES) -> ElGamalCiphertext:
        encoded = encode_to_point(m.encode("ascii"), self.H, shift)
        return self.encrypt(encoded)


class EGPrivateKey(EGPublicKey):
    def __init__(self, x: int, curve=P384):
        self.x = x
        super().__init__(curve.G * x)

    def decrypt(self, ct: ElGamalCiphertext) -> Point:
        D = self.x * ct.U
        M = ct.V - D
        return M

    def decrypt_and_decode(self, ct: ElGamalCiphertext, shift=ENCODING_MAX_TRIES) -> str:
        M = self.decrypt(ct)
        m_bytes = decode_from_point(M, self.H, shift)
        return m_bytes.decode("ascii")
