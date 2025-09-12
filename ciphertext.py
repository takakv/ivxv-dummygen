from fastecdsa.point import Point
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
from pyasn1_modules.rfc5280 import AlgorithmIdentifier

from asn1 import ElGamalEncryptedMessage, EncryptedBallot, ivxv_ecc_oid, ASNDecryptionProof
from parsing import point_from_bytes, point_to_bytes


class ElGamalCiphertext:
    U: Point
    V: Point

    def __init__(self, U: Point, V: Point):
        if not (U is None and V is None):
            self.U = U
            self.V = V

    def to_asn1(self) -> EncryptedBallot:
        eem = ElGamalEncryptedMessage()
        eem["u"] = point_to_bytes(self.U)
        eem["v"] = point_to_bytes(self.V)

        ai = AlgorithmIdentifier()
        ai["algorithm"] = ivxv_ecc_oid

        eb = EncryptedBallot()
        eb["algorithm"] = ai
        eb["cipher"] = eem

        return eb

    def to_bytes(self) -> bytes:
        return der_encoder.encode(self.to_asn1())

    @classmethod
    def from_bytes(cls, data: bytes):
        eb, _ = der_decoder.decode(data, asn1Spec=EncryptedBallot())
        eem = eb["cipher"]
        return cls(point_from_bytes(eem["u"]), point_from_bytes(eem["v"]))


class DecryptionProof:
    mComm: Point
    kComm: Point
    response: int

    def __init__(self, mc: Point, kc: Point, res: int):
        self.mComm = mc
        self.kComm = kc
        self.response = res

    def to_bytes(self) -> bytes:
        adp = ASNDecryptionProof()
        adp["msgCommitment"] = point_to_bytes(self.mComm)
        adp["keyCommitment"] = point_to_bytes(self.kComm)
        adp["response"] = self.response
        return der_encoder.encode(adp)

    @classmethod
    def from_bytes(cls, data: bytes):
        dp, _ = der_decoder.decode(data, asn1Spec=ASNDecryptionProof())
        mComm = point_from_bytes(dp["msgCommitment"])
        kComm = point_from_bytes(dp["keyCommitment"])
        response = int(dp["response"])
        return cls(mComm, kComm, response)
