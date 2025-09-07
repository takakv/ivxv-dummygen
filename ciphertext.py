from fastecdsa.point import Point
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
from pyasn1_modules.rfc5280 import AlgorithmIdentifier

from asn1 import ElGamalEncryptedMessage, EncryptedBallot, ivxv_ecc_oid
from parsing import extract_point_from_der


class ElGamalCiphertext:
    U: Point
    V: Point

    def __init__(self, U: Point = None, V: Point = None):
        if not (U is None and V is None):
            self.U = U
            self.V = V

    def to_asn1(self):
        bl = (self.U.curve.p.bit_length() + 7) // 8

        eem = ElGamalEncryptedMessage()
        ux_bytes = self.U.x.to_bytes(bl, "big")
        uy_bytes = self.U.y.to_bytes(bl, "big")
        vx_bytes = self.V.x.to_bytes(bl, "big")
        vy_bytes = self.V.y.to_bytes(bl, "big")
        # Uncompressed EC points.
        eem["u"] = b"\x04" + ux_bytes + uy_bytes
        eem["v"] = b"\x04" + vx_bytes + vy_bytes

        ai = AlgorithmIdentifier()
        ai["algorithm"] = ivxv_ecc_oid

        eb = EncryptedBallot()
        eb["algorithm"] = ai
        eb["cipher"] = eem
        return der_encoder.encode(eb)

    def from_asn1(self, data: bytes):
        eb, _ = der_decoder.decode(data, asn1Spec=EncryptedBallot())
        eem = eb["cipher"]
        u_bytes: bytes = eem["u"].asOctets()
        v_bytes: bytes = eem["v"].asOctets()
        self.U = extract_point_from_der(u_bytes)
        self.V = extract_point_from_der(v_bytes)
