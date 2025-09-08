from fastecdsa.curve import P384
from fastecdsa.encoding.pem import PEMEncoder
from fastecdsa.point import Point
from pyasn1.codec.der import decoder as der_decoder
from pyasn1_modules import rfc5280

from asn1 import IVXVPublicKey
from parsing import pem_to_der, extract_point_from_der


class PublicKey:
    def __init__(self, H: Point, spki: rfc5280.SubjectPublicKeyInfo | None = None):
        self.H = H
        self.asn1 = spki

    @classmethod
    def from_asn1(cls, data: bytes):
        spki, _ = der_decoder.decode(pem_to_der(data), asn1Spec=rfc5280.SubjectPublicKeyInfo())
        pkey, _ = der_decoder.decode(spki["subjectPublicKey"].asOctets(), asn1Spec=IVXVPublicKey())
        ec_point: bytes = pkey["ecPoint"].asOctets()
        return cls(extract_point_from_der(ec_point), spki)

    @property
    def curve(self):
        return self.H.curve


class PrivateKey(PublicKey):
    def __init__(self, x: int, curve=P384):
        self.x = x
        super().__init__(curve.G * x)

    @classmethod
    def from_asn1(cls, data: bytes):
        x = PEMEncoder().decode_private_key(data)
        return cls(x)
