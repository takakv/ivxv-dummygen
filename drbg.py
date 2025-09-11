import hashlib
import math

HASH_ALGO = hashlib.sha256


def randbelow(seed: bytes, n: int) -> int:
    """Return a pseudorandom int in the range [0, n)."""
    bound_size = (n.bit_length() + 7) // 8
    mask_len = n.bit_length() % 8
    if mask_len == 0:
        mask_len = 8

    block_len = HASH_ALGO().digest_size
    blocks_needed = math.ceil(bound_size / block_len)

    counter = 0
    rand = n
    while not (rand < n):
        buf = b""

        for i in range(blocks_needed):
            counter += 1
            buf += HASH_ALGO(counter.to_bytes(8, "big") + seed).digest()

        high_byte = buf[0] & ((1 << mask_len) - 1)
        rand_buf = bytes([high_byte]) + buf[1:]
        rand = int.from_bytes(rand_buf, "big", signed=False)

    return rand
