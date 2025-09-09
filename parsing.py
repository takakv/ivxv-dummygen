import base64

from fastecdsa.curve import P384
from fastecdsa.point import Point
from pyasn1.type.univ import OctetString


def pem_to_der(data: bytes) -> bytes:
    if data[:2] == b"--":
        start = data.find(b'\n') + 1
        end = data.rfind(b'\n')
        data = base64.b64decode(data[start:end])
    return data


def point_from_der(der: bytes | OctetString) -> Point:
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


def point_to_der(P: Point) -> bytes:
    bl = (P.curve.p.bit_length() + 7) // 8
    x_bytes = P.x.to_bytes(bl, "big")
    y_bytes = P.y.to_bytes(bl, "big")
    return b"\x04" + x_bytes + y_bytes
