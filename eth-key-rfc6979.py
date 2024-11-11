from eth_keys import keys
from eth_keys.backends.native.ecdsa import ecdsa_raw_sign
from eth_keys.backends.native.ecdsa import deterministic_generate_k, fast_multiply
from eth_keys.constants import SECPK1_G as G, SECPK1_N as N
from eth_keys.backends.native.jacobian import inv


def sign_message(message: bytes, private_key_scalar: bytes) -> tuple[int, int]:
    # Create private key from scalar
    private_key = keys.PrivateKey(private_key_scalar)

    # Get r, s, v values from raw signature
    # ecdsa_raw_sign uses RFC6979 deterministic k generation
    v, r, s = ecdsa_raw_sign(message, private_key.to_bytes())

    return r, s


test_vectors = [
    {
        "private_key": "0000000000000000000000000000000000000000000000000000000000000001",
        "message": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    },
    {
        "private_key": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "message": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    },
    {
        "private_key": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "message": "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    },
]

for test in test_vectors:
    print(f"\nTest vector: {test}")
    private_key_scalar = bytes.fromhex(test["private_key"])
    message = bytes.fromhex(test["message"])

    k = deterministic_generate_k(message, private_key_scalar)
    print(f"k: {hex(k)}")

    k_inv = inv(k, N)
    print(f"k_inv: {hex(k_inv)}")

    R = fast_multiply(G, k)
    print(f"Rx: {hex(R[0])}")

    r, s = sign_message(message, private_key_scalar)
    print(f"r: {hex(r)}")
    print(f"s: {hex(s)}")
