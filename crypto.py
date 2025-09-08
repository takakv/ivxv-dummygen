import secrets

from fastecdsa.point import Point
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_modules import rfc5280

from asn1 import ProofSeed, EncryptedBallot
from ciphertext import ElGamalCiphertext
from key import PublicKey, PrivateKey
from utils import decode_from_point, encode_to_point

ENCODING_MAX_TRIES = 10


def encrypt(M: Point, pk: PublicKey) -> ElGamalCiphertext:
    r = secrets.randbelow(pk.curve.q)
    return ElGamalCiphertext(pk.curve.G * r, M + (pk.H * r))


def encode_and_encrypt(m: str, pk: PublicKey, shift=ENCODING_MAX_TRIES) -> ElGamalCiphertext:
    encoded = encode_to_point(m.encode("ascii"), pk.curve, shift)
    return encrypt(encoded, pk)


def decrypt(ct: ElGamalCiphertext, sk: PrivateKey) -> Point:
    D = sk.x * ct.U
    M = ct.V - D
    return M


def decrypt_and_decode(ct: ElGamalCiphertext, sk: PrivateKey, shift=ENCODING_MAX_TRIES) -> str:
    M = decrypt(ct, sk)
    m_bytes = decode_from_point(M, sk.curve, shift)
    return m_bytes.decode("ascii")


def derive_seed(pub: rfc5280.SubjectPublicKeyInfo, enc: EncryptedBallot, dec: bytes,
                msg_commitment: bytes, key_commitment: bytes) -> bytes:
    seed = ProofSeed()
    seed["niProofDomain"] = "DECRYPTION"
    seed["publicKey"] = pub
    seed["ciphertext"] = enc
    seed["decrypted"] = dec
    seed["msgCommitment"] = msg_commitment
    seed["keyCommitment"] = key_commitment

    return der_encoder.encode(seed)
