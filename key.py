import base64
from textwrap import wrap
from typing import Literal

from fastecdsa.curve import P384
from fastecdsa.encoding.pem import PEMEncoder
from fastecdsa.point import Point
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from pyasn1.type.univ import BitString
from pyasn1_modules import rfc5280

from asn1 import IVXVPublicKey, IVXVPublicKeyParameters, ivxv_ecc_oid
from parsing import pem_to_der, point_from_der


class PublicKey:
    def __init__(self, H: Point, election_id: str, spki: rfc5280.SubjectPublicKeyInfo | None = None):
        self.H = H
        self.election_id = election_id

        if spki is None:
            spki = self._to_asn1()

        self.spki = spki

    @classmethod
    def from_asn1(cls, data: bytes):
        spki, _ = der_decoder.decode(pem_to_der(data), asn1Spec=rfc5280.SubjectPublicKeyInfo())
        pkey, _ = der_decoder.decode(spki["subjectPublicKey"].asOctets(), asn1Spec=IVXVPublicKey())
        params, _ = der_decoder.decode(spki["algorithm"]["parameters"].asOctets(), asn1Spec=IVXVPublicKeyParameters())
        return cls(point_from_der(pkey["ecPoint"]), params["electionId"], spki)

    def public_bytes(self, encoding: Literal["DER", "PEM"] = "DER") -> bytes:
        if encoding != "DER" and encoding != "PEM":
            raise ValueError("Unsupported encoding")

        der = der_encoder.encode(self.spki)
        if encoding == "DER":
            return der

        b64 = base64.b64encode(der).decode("ascii")
        pem_lines = wrap(b64, 64)
        pem_lines = ["-----BEGIN PUBLIC KEY-----"] + pem_lines + ["-----END PUBLIC KEY-----"]
        pem_bytes = "\n".join(pem_lines).encode("ascii")
        return pem_bytes

    def _to_asn1(self) -> rfc5280.SubjectPublicKeyInfo:
        params = IVXVPublicKeyParameters()
        params["curveName"] = "P-384"
        params["electionId"] = self.election_id

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = ivxv_ecc_oid
        spki["algorithm"]["parameters"] = params

        x_bytes = self.H.x.to_bytes(48, "big")
        y_bytes = self.H.y.to_bytes(48, "big")
        ec_point = b"\x04" + x_bytes + y_bytes

        pk = IVXVPublicKey()
        pk["ecPoint"] = ec_point
        pk_der = der_encoder.encode(pk)

        spki["subjectPublicKey"] = BitString.fromOctetString(pk_der)
        return spki

    @property
    def curve(self):
        return self.H.curve


class PrivateKey:
    def __init__(self, x: int, election_id: str, curve=P384):
        self.x = x
        self.election_id = election_id
        self.curve = curve
        self.public_key = PublicKey(self.x * self.curve.G, self.election_id)

    @classmethod
    def from_asn1(cls, data: bytes, election_id: str, curve=P384):
        x = PEMEncoder().decode_private_key(data)
        return cls(x, election_id, curve)
