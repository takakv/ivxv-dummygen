from fastecdsa import keys
from fastecdsa.curve import P384
from fastecdsa.encoding.pem import PEMEncoder

from crypto import ElGamalCiphertext
from parsing import import_public_key, export_public_key, import_private_key


def keygen():
    x, H = keys.gen_keypair(P384)
    keys.export_private_key(x, curve=P384, encoder=PEMEncoder(), filepath="./demo.key")
    export_public_key(H, filepath="./demo.pem")
    return x, H


def fetch_keys():
    sk = import_private_key("./demo.key")
    pk = import_public_key("./demo.pem")
    return sk, pk


def serialise_ballot(ct: ElGamalCiphertext):
    pass


def main():
    # x, H = keygen()
    sk, pk = fetch_keys()

    choice = "0000.103"
    ct = pk.encode_and_encrypt(choice)
    dec = sk.decrypt_and_decode(ct)

    assert dec == choice


if __name__ == "__main__":
    main()
