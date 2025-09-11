from pyasn1.type.char import GeneralString
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import ObjectIdentifier, Sequence, OctetString, Integer
from pyasn1_modules import rfc5280

ivxv_ecc_oid = ObjectIdentifier("1.3.6.1.4.1.99999.1")


class IVXVPublicKeyParameters(Sequence):
    componentType = NamedTypes(
        NamedType("curveName", GeneralString()),
        NamedType("electionId", GeneralString())
    )


class IVXVPublicKey(Sequence):
    componentType = NamedTypes(NamedType("ecPoint", OctetString()))


class ElGamalEncryptedMessage(Sequence):
    componentType = NamedTypes(
        NamedType("u", OctetString()),
        NamedType("v", OctetString())
    )


class EncryptedBallot(Sequence):
    componentType = NamedTypes(
        NamedType("algorithm", rfc5280.AlgorithmIdentifier()),
        NamedType("cipher", ElGamalEncryptedMessage())
    )


class ProofSeed(Sequence):
    componentType = NamedTypes(
        NamedType("niProofDomain", GeneralString()),
        NamedType("publicKey", rfc5280.SubjectPublicKeyInfo()),
        NamedType("ciphertext", EncryptedBallot()),
        NamedType("decrypted", OctetString()),
        NamedType("msgCommitment", OctetString()),
        NamedType("keyCommitment", OctetString())
    )


class DecryptionProof(Sequence):
    componentType = NamedTypes(
        NamedType("msgCommitment", OctetString()),
        NamedType("keyCommitment", OctetString()),
        NamedType("response", Integer())
    )
