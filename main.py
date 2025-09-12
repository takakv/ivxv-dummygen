import base64
import json
import secrets

from fastecdsa import keys
from fastecdsa.curve import P384
from fastecdsa.encoding.pem import PEMEncoder

from ciphertext import ElGamalCiphertext, DecryptionProof
from crypto import encode_and_encrypt, decrypt_and_decode, provably_decrypt, verify_proof
from keyio import import_public_key, export_public_key, import_private_key
from parsing import point_to_der, point_from_der
from utils import decode_from_point


def keygen(election_id: str = None) -> str:
    if election_id is None:
        election_id = "DEMO_" + secrets.token_hex(3).upper()

    x, H = keys.gen_keypair(P384)
    keys.export_private_key(x, curve=P384, encoder=PEMEncoder(), filepath=f"./{election_id}.key")
    export_public_key(H, f"./{election_id}-pub.pem", election_id)
    return election_id


def fetch_keys(election_id: str):
    pk = import_public_key(f"./{election_id}-pub.pem")
    sk = import_private_key(f"./{election_id}.key", pk.election_id)
    return sk, pk


def test():
    election_id = keygen()
    sk, pk = fetch_keys(election_id)

    choice = "0000.103"
    ct = encode_and_encrypt(choice, pk)

    with open("./ct.bin", "wb") as f:
        f.write(ct.to_bytes())

    with open("./ct.bin", "rb") as f:
        ct = ElGamalCiphertext.from_bytes(f.read())

    dec = decrypt_and_decode(ct, sk)
    assert dec == choice

    M, proof = provably_decrypt(ct, sk)
    assert choice == decode_from_point(M, pk.curve).decode()

    with open("./proof.bin", "wb") as f:
        f.write(proof.to_bytes())

    with open("./proof.bin", "rb") as f:
        proof = DecryptionProof.from_bytes(f.read())

    assert verify_proof(M, ct, pk, proof)


def gen_data(election_id: str, gen_proofs=True):
    sk, pk = fetch_keys(election_id)

    # Ciphertexts are all kept in memory before writing, so keep the number reasonable.
    # Because of the JSON dictionary, the memory requirement is doubled.
    # If the decryption proofs are generated, two more lists (and a dict of those + ciphertexts) are created. Beware!
    question_id = 1
    choices = [f"0000.{c}" for c in ["101", "102", "103"]]
    proofs_per_choice = 2

    ciphertexts: list[str] = []
    decrypted: list[str] = []
    proofs: list[str] = []

    for choice in choices:
        for _ in range(proofs_per_choice):
            ct = encode_and_encrypt(choice, pk)
            ciphertexts.append(base64.b64encode(ct.to_bytes()).decode())

            if gen_proofs:
                dec_value, dec_proof = provably_decrypt(ct, sk)
                dec_value_asn1 = point_to_der(dec_value)
                decrypted.append(base64.b64encode(dec_value_asn1).decode())
                proofs.append(base64.b64encode(dec_proof.to_bytes()).decode())

    ballots_dict = {f"{election_id}.question-{question_id}": ciphertexts}
    districts_dict = {"0000.1": {"0000": ballots_dict}}
    ballotbox_dict = {"election": election_id, "districts": districts_dict}

    with open(f"./{election_id}-bb-4.json", "w") as f:
        f.write(json.dumps(ballotbox_dict, indent=2))

    if not gen_proofs:
        return

    verification_data: list[dict[str, str]] = []

    # We can get rid of this loop if performance becomes a concern.
    # However, the code is probably more readable with this approach.
    for i in range(len(ciphertexts)):
        verification_data.append({"ciphertext": ciphertexts[i], "message": decrypted[i], "proof": proofs[i]})

    proofs_dict = {"election": election_id, "proofs": verification_data}

    with open(f"./{election_id}-proof", "w") as f:
        f.write(json.dumps(proofs_dict, indent=2))


# NB! This only verifies the NIZKPs in the proofs file.
# This does NOT verify everything needed to verify the integrity of the tallying process, e.g.:
# - that the decryption proofs are consistent with the input ballotbox
# - the integrity of the proofs and ballotbox files
# - the validity of the decrypted results (voter choices)
# - that the final tally corresponds to the decrypted results
def verify_proofs(election_id: str):
    pk = import_public_key(f"./{election_id}-pub.pem")

    with open(f"./{election_id}-proof", "r") as f:
        proofs_dict = json.loads(f.read())

    verification_data = proofs_dict["proofs"]
    for i in range(len(verification_data)):
        data = verification_data[i]

        ct_bytes = base64.b64decode(data["ciphertext"])
        dec_bytes = base64.b64decode(data["message"])
        proof_bytes = base64.b64decode(data["proof"])

        ct = ElGamalCiphertext.from_bytes(ct_bytes)
        M = point_from_der(dec_bytes)
        proof = DecryptionProof.from_bytes(proof_bytes)

        if not verify_proof(M, ct, pk, proof):
            print("[-] Proof verification failed for index:", i)
            print()


def main():
    # test()

    election_id = "DUMMYGEN_01"
    # keygen(election_id)

    gen_data(election_id)
    # verify_proofs(election_id)


if __name__ == "__main__":
    main()
