from fastecdsa import keys
from fastecdsa.curve import P384
from fastecdsa.encoding.pem import PEMEncoder

from ciphertext import ElGamalCiphertext
from crypto import encode_and_encrypt, decrypt_and_decode
from keyio import import_public_key, export_public_key, import_private_key


def keygen():
    x, H = keys.gen_keypair(P384)
    keys.export_private_key(x, curve=P384, encoder=PEMEncoder(), filepath="./demo.key")
    export_public_key(H, filepath="./demo.pem")


def fetch_keys():
    pk = import_public_key("./demo.pem")
    sk = import_private_key("./demo.key", pk.election_id)
    return sk, pk


def main():
    # keygen()
    sk, pk = fetch_keys()

    choice = "0000.103"
    ct = encode_and_encrypt(choice, pk)

    with open("./ct.bin", "wb") as f:
        f.write(ct.to_asn1())

    with open("./ct.bin", "rb") as f:
        ct = ElGamalCiphertext()
        ct.from_asn1(f.read())

    dec = decrypt_and_decode(ct, sk)
    assert dec == choice


if __name__ == "__main__":
    main()
