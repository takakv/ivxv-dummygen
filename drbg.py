import hashlib
import math

HASH_ALGO = hashlib.sha256


# https://github.com/valimised/ivxv/blob/published/common/java/src/main/java/ee/ivxv/common/crypto/rnd/DPRNG.java
# https://github.com/valimised/ivxv/blob/published/common/java/src/main/java/ee/ivxv/common/math/IntegerConstructor.java#L20
def randbelow(seed: bytes, n: int) -> int:
    """Return a pseudorandom int in the range [0, n)."""
    bound_size = (n.bit_length() + 7) // 8
    mask_len = n.bit_length() % 8
    if mask_len == 0:
        mask_len = 8

    block_len = HASH_ALGO().digest_size

    counter = 0
    buffer = b""

    rand = n
    while not (rand < n):
        # Compute the minimum number of hash outputs needed to meet the required byte-count.
        blocks_needed = math.ceil((bound_size - len(buffer)) / block_len)

        for i in range(blocks_needed):
            counter += 1
            buffer += HASH_ALGO(counter.to_bytes(8, "big") + seed).digest()

        # Mask off the highest byte in order to salvage some bits.
        # See also 'Bitmask with rejection (Unbiased)' in
        # https://www.pcg-random.org/posts/bounded-rands.html
        high_byte = buffer[0] & ((1 << mask_len) - 1)
        tmp_buffer = bytes([high_byte]) + buffer[1:bound_size]
        rand = int.from_bytes(tmp_buffer, "big", signed=False)

        # Clear the consumed bytes form the buffer.
        buffer = buffer[bound_size:]

    return rand
