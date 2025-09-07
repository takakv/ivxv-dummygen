import base64
import secrets
from textwrap import wrap

from fastecdsa import keys
from fastecdsa.encoding.pem import PEMEncoder
from fastecdsa.point import Point
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from pyasn1.type.univ import BitString
from pyasn1_modules import rfc5280

from asn1 import IVXVPublicKeyParameters, ivxv_ecc_oid, IVXVPublicKey
from crypto import EGPublicKey, EGPrivateKey
from parsing import pem_to_der, extract_point_from_der


def extract_public_key_from_asn1(data: bytes) -> Point:
    spki, _ = der_decoder.decode(pem_to_der(data), asn1Spec=rfc5280.SubjectPublicKeyInfo())
    pkey, _ = der_decoder.decode(spki["subjectPublicKey"].asOctets(), asn1Spec=IVXVPublicKey())
    ec_point: bytes = pkey["ecPoint"].asOctets()
    return extract_point_from_der(ec_point)


def export_public_key(key: Point, filepath: str):
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


def import_private_key(filepath: str) -> EGPrivateKey:
    x = keys.import_private_key(filepath, PEMEncoder())
    return EGPrivateKey(x)


def import_public_key(filepath: str) -> EGPublicKey:
    with open(filepath, "rb") as f:
        data = f.read()
    H = extract_public_key_from_asn1(data)
    return EGPublicKey(H)
