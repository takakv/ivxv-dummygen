import base64
import secrets
from textwrap import wrap

from fastecdsa import keys
from fastecdsa.curve import P384
from fastecdsa.encoding.pem import PEMEncoder
from fastecdsa.keys import export_private_key, import_private_key
from fastecdsa.point import Point
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
from pyasn1.type.char import GeneralString
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Sequence, OctetString, ObjectIdentifier, BitString
from pyasn1_modules import rfc5280


def pem_to_der(data: bytes) -> bytes:
    if data[:2] == b"--":
        start = data.find(b'\n') + 1
        end = data.rfind(b'\n')
        data = base64.b64decode(data[start:end])
    return data


ivxv_ecc_oid = ObjectIdentifier("1.3.6.1.4.1.99999.1")


class IVXVPublicKeyParameters(Sequence):
    componentType = NamedTypes(
        NamedType("curveName", GeneralString()),
        NamedType("electionId", GeneralString()),
    )


class IVXVPublicKey(Sequence):
    componentType = NamedTypes(NamedType("ecPoint", OctetString()))


def extract_point_from_der(der: bytes) -> Point:
    # The first byte indicates whether the point is compressed.
    # In IVXV, no compression is used (0x04).
    concatenated = der[1:]
    half_len = len(concatenated) // 2
    assert half_len == 48, "Public key is not P-384"
    x = int.from_bytes(concatenated[:half_len], "big")
    y = int.from_bytes(concatenated[half_len:], "big")
    return Point(x, y, curve=P384)


def extract_public_key_from_asn1(data: bytes) -> Point:
    spki, _ = der_decoder.decode(pem_to_der(data), asn1Spec=rfc5280.SubjectPublicKeyInfo())
    pkey, _ = der_decoder.decode(spki["subjectPublicKey"].asOctets(), asn1Spec=IVXVPublicKey())
    ec_point: bytes = pkey["ecPoint"].asOctets()
    return extract_point_from_der(ec_point)


def export_ivxv_public_key(key: Point, filepath: str):
    params = IVXVPublicKeyParameters()
    params["curveName"] = "P-384"
    params["electionId"] = "DEMO-" + secrets.token_hex(3).upper()

    spki = rfc5280.SubjectPublicKeyInfo()
    spki["algorithm"]["algorithm"] = ivxv_ecc_oid
    spki["algorithm"]["parameters"] = params

    x_bytes = key.x.to_bytes(48, "big")
    y_bytes = key.y.to_bytes(48, "big")
    ec_point = b"\x04" + x_bytes + y_bytes

    pk = IVXVPublicKey()
    pk["ecPoint"] = ec_point
    pk_der = der_encoder.encode(pk)

    spki["subjectPublicKey"] = BitString.fromOctetString(pk_der)
    der_bytes = der_encoder.encode(spki)

    b64 = base64.b64encode(der_bytes).decode("ascii")
    pem_lines = wrap(b64, 64)
    pem_lines = ["-----BEGIN PUBLIC KEY-----"] + pem_lines + ["-----END PUBLIC KEY-----"]
    pem_bytes = "\n".join(pem_lines).encode("ascii")

    with open(filepath, "wb") as f:
        f.write(pem_bytes)


def import_ivxv_public_key(filepath: str):
    with open(filepath, "rb") as f:
        data = f.read()
    return extract_public_key_from_asn1(data)


def keygen():
    x, H = keys.gen_keypair(P384)
    export_private_key(x, curve=P384, encoder=PEMEncoder(), filepath="./demo.key")
    export_ivxv_public_key(H, filepath="./demo.pem")
    return x, H


def fetch_keys():
    x = import_private_key("./demo.key", PEMEncoder())
    H = import_ivxv_public_key("./demo.pem")
    return x, H


def legendre(a, p):
    return pow(a, (p - 1) // 2, p)


# https://www.ctfrecipes.com/cryptography/general-knowledge/maths/modular-arithmetic/tonelli-shanks
def tonelli(a, p):
    assert legendre(a, p) == 1, "not a quadratic-residue"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(a, (p + 1) // 4, p)

    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break

    c = pow(z, q, p)
    r = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)

    m = s

    t2 = 0

    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r


PADDING_HEAD = [
    [0x00],
    [0b00111111],
    [0b00011111],
    [0b00001111],
    [0b00000111],
    [0b00000011],
    [0b00000001],
    [0b00000000, 0b11111111],
    [0b00000000, 0b01111111],
    [0b00000000, 0b00111111],
    [0b00000000, 0b00011111]
]
PADDING_FILL = b"\xFF"
PADDING_END = b"\xFE"


def encode_to_point(message: bytes, H: Point, max_tries=10) -> Point:
    curve_byte_len = (H.curve.p.bit_length() + 7) // 8

    padding_head = PADDING_HEAD[max_tries]
    padding_len = curve_byte_len - len(padding_head) - len(message) - 1
    padded = bytes(padding_head) + (PADDING_FILL * padding_len) + PADDING_END + message

    candidate = int.from_bytes(padded, "big") << max_tries
    for _ in range(max_tries):
        # y^2 = x^3 + ax + b
        rhs = (pow(candidate, 3, H.curve.p) + H.curve.a * candidate + H.curve.b) % H.curve.p
        if legendre(rhs, H.curve.p) == 1:
            y = tonelli(rhs, H.curve.p)
            return Point(candidate, y, H.curve)
        candidate += 1

    raise RuntimeError("could not encode the data as a curve point")


def main():
    # x, H = keygen()
    x, H = fetch_keys()

    choice = "0000.103"
    encoded = encode_to_point(choice.encode("ascii"), H)
    print(encoded)


if __name__ == "__main__":
    main()
