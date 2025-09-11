import secrets

from fastecdsa.point import Point

from key import PrivateKey, PublicKey


def export_public_key(key: Point, filepath: str):
    election_id = "DEMO-" + secrets.token_hex(3).upper()
    public_key = PublicKey(key, election_id)

    with open(filepath, "wb") as f:
        f.write(public_key.public_bytes())


def import_private_key(filepath: str, election_id: str):
    with open(filepath, "rb") as f:
        data = f.read()
    return PrivateKey.from_asn1(data, election_id)


def import_public_key(filepath: str):
    with open(filepath, "rb") as f:
        data = f.read()
    return PublicKey.from_asn1(data)
