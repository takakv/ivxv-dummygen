import secrets

from fastecdsa.point import Point
from pyasn1.codec.der import encoder as der_encoder
from pyasn1_modules import rfc5280

from asn1 import ProofSeed, EncryptedBallot
from ciphertext import ElGamalCiphertext, DecryptionProof
from drbg import randbelow
from key import PublicKey, PrivateKey
from parsing import point_to_bytes
from utils import decode_from_point, encode_to_point

ENCODING_MAX_TRIES = 10


def encrypt(M: Point, pk: PublicKey) -> ElGamalCiphertext:
    r = secrets.randbelow(pk.curve.q)
    return ElGamalCiphertext(pk.curve.G * r, M + (pk.H * r))


def encode_and_encrypt(m: str, pk: PublicKey, shift=ENCODING_MAX_TRIES) -> ElGamalCiphertext:
    encoded = encode_to_point(m.encode(), pk.curve, shift)
    return encrypt(encoded, pk)


def decrypt(ct: ElGamalCiphertext, sk: PrivateKey) -> Point:
    D = sk.x * ct.U
    M = ct.V - D
    return M


def provably_decrypt(ct: ElGamalCiphertext, sk: PrivateKey) -> tuple[Point, DecryptionProof]:
    M = decrypt(ct, sk)

    t = secrets.randbelow(sk.curve.q)
    message_commitment = ct.U * t
    key_commitment = sk.curve.G * t

    message_bytes = point_to_bytes(M)
    mc_bytes = point_to_bytes(message_commitment)
    kc_bytes = point_to_bytes(key_commitment)

    seed = derive_seed(sk.public_key.spki, ct.to_asn1(), message_bytes, mc_bytes, kc_bytes)
    challenge = randbelow(seed, sk.curve.q)

    response = (challenge * sk.x + t) % sk.curve.q

    return M, DecryptionProof(message_commitment, key_commitment, response)


def decrypt_and_decode(ct: ElGamalCiphertext, sk: PrivateKey, shift=ENCODING_MAX_TRIES) -> str:
    M = decrypt(ct, sk)
    m_bytes = decode_from_point(M, sk.curve, shift)
    return m_bytes.decode()


def verify_proof(M: Point, ct: ElGamalCiphertext, pk: PublicKey, proof: DecryptionProof) -> bool:
    message_bytes = point_to_bytes(M)
    mc_bytes = point_to_bytes(proof.mComm)
    kc_bytes = point_to_bytes(proof.kComm)

    seed = derive_seed(pk.spki, ct.to_asn1(), message_bytes, mc_bytes, kc_bytes)
    challenge = randbelow(seed, pk.curve.q)

    proof_ok = True

    lhs1 = proof.response * ct.U
    rhs1 = proof.mComm + (ct.V - M) * challenge
    if lhs1 != rhs1:
        print("[-] Proof component 'message commitment' failed to verify.")
        proof_ok = False

    lhs2 = proof.response * pk.curve.G
    rhs2 = proof.kComm + pk.H * challenge
    if lhs2 != rhs2:
        print("[-] Proof component 'key commitment' failed to verify.")
        proof_ok = False

    return proof_ok


def derive_seed(pub: rfc5280.SubjectPublicKeyInfo, enc: EncryptedBallot, dec: bytes,
                msg_commitment: bytes, key_commitment: bytes) -> bytes:
    assert pub is not None
    assert enc is not None

    seed = ProofSeed()
    seed["niProofDomain"] = "DECRYPTION"
    seed["publicKey"] = pub
    seed["ciphertext"] = enc
    seed["decrypted"] = dec
    seed["msgCommitment"] = msg_commitment
    seed["keyCommitment"] = key_commitment

    return der_encoder.encode(seed)
