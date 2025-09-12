import base64

from fastecdsa.curve import P384
from fastecdsa.point import Point
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from pyasn1.type.univ import OctetString


def pem_to_der(data: bytes) -> bytes:
    if data[:2] == b"--":
        start = data.find(b'\n') + 1
        end = data.rfind(b'\n')
        data = base64.b64decode(data[start:end])
    return data


def point_from_bytes(der: bytes | OctetString) -> Point:
    """Recover a curve point from its SEC 1 uncompressed byte representation."""
    if isinstance(der, OctetString):
        der = der.asOctets()

    # The first byte indicates whether the point is compressed.
    # In IVXV, no compression is used (0x04).
    concatenated = der[1:]
    half_len = len(concatenated) // 2
    assert half_len == 48, "Public key is not P-384"
    x = int.from_bytes(concatenated[:half_len], "big")
    y = int.from_bytes(concatenated[half_len:], "big")
    return Point(x, y, curve=P384)


def point_to_bytes(P: Point) -> bytes:
    """Get the SEC 1 uncompressed byte representation of the curve point."""
    bl = (P.curve.p.bit_length() + 7) // 8
    x_bytes = P.x.to_bytes(bl, "big")
    y_bytes = P.y.to_bytes(bl, "big")
    return b"\x04" + x_bytes + y_bytes


def point_from_der(der: bytes | OctetString) -> Point:
    """Extract a curve point from its DER-encoded SEC 1 byte representation.

    Use this method only if the point bytes are prefixed with the
    OCTET STRING type. Otherwise, use `point_from_bytes()`.
    """
    if isinstance(der, OctetString):
        der = der.asOctets()

    point_bytes, _ = der_decoder.decode(der, asn1Spec=OctetString())
    return point_from_bytes(point_bytes)


def point_to_der(point: Point) -> bytes:
    """Get the DER-encoded SEC 1 uncompressed byte representation of the curve point.

    Use this method only if you need the point bytes as a valid ASN1 DER object,
    i.e. prefixed with the OCTET STRING type. Otherwise, use `point_to_bytes()`.
    """
    ecp = OctetString(point_to_bytes(point))
    return der_encoder.encode(ecp)
