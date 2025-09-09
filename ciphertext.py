from fastecdsa.point import Point
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
from pyasn1_modules.rfc5280 import AlgorithmIdentifier

from asn1 import ElGamalEncryptedMessage, EncryptedBallot, ivxv_ecc_oid
from parsing import point_from_der, point_to_der


class ElGamalCiphertext:
    U: Point
    V: Point

    def __init__(self, U: Point = None, V: Point = None):
        if not (U is None and V is None):
            self.U = U
            self.V = V

    def to_asn1(self) -> bytes:
        eem = ElGamalEncryptedMessage()
        eem["u"] = point_to_der(self.U)
        eem["v"] = point_to_der(self.V)

        ai = AlgorithmIdentifier()
        ai["algorithm"] = ivxv_ecc_oid

        eb = EncryptedBallot()
        eb["algorithm"] = ai
        eb["cipher"] = eem

        return der_encoder.encode(eb)

    def from_asn1(self, data: bytes):
        eb, _ = der_decoder.decode(data, asn1Spec=EncryptedBallot())
        eem = eb["cipher"]
        self.U = point_from_der(eem["u"])
        self.V = point_from_der(eem["v"])
