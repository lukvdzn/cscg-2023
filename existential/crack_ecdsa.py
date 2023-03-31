# Author: torukmagto

import ecdsa
import ecdsa.curves
import olll
import hashlib
import libnum


HASHFUNC = hashlib.sha1
GEN = ecdsa.BRAINPOOLP256r1
ORDER = GEN.order
B = 2 ** 128


# Flag for CSCG Challenge: "CSCG{OwNowHowDidYouDoThat}"


""" ############################## EXTRACTED AND MODIFIED FROM ECDSA LIB ############################################"""


def transform_digest(digest):
    digest = ecdsa.keys.normalise_bytes(digest)

    digest = digest[: GEN.baselen]
    number = ecdsa.keys.string_to_number(digest)

    max_length = ecdsa.keys.bit_length(GEN.order)
    length = len(digest) * 8
    number >>= max(0, length - max_length)
    return number


def transform_msg(msg):
    data = ecdsa.keys.normalise_bytes(msg)
    digest = HASHFUNC(data).digest()
    number = transform_digest(digest)
    return number


""" ################################################################################################################ """


# Inspired by https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
def crack_signatures(signatures, msg="0111"):
    rs = [ecdsa.util.sigdecode_string(sig, ORDER) for sig in signatures]

    msg_bytes = bytes.fromhex(msg)
    msg = transform_msg(msg_bytes)

    # one of the two is actual public key
    possible_pub_keys = ecdsa.keys.VerifyingKey.from_public_key_recovery(signatures[0], msg_bytes, GEN)

    # PREPARE MATRIX

    matrix_size = len(signatures) + 1
    matrix = [[0 for _ in range(matrix_size)] for _ in range(matrix_size)]
    for i in range(matrix_size):
        matrix[i][i] = ORDER if i != (matrix_size - 2) else B / ORDER

    matrix[-1][-1] = B

    r_n, s_n = rs[-1]
    s_n_inv = libnum.invmod(s_n, ORDER)

    for i in range(len(rs) - 1):
        r_i, s_i = rs[i]
        s_i_inv = libnum.invmod(s_i, ORDER)

        matrix[-2][i] = (r_i * s_i_inv) - (r_n * s_n_inv)
        matrix[-1][i] = (msg * s_i_inv) - (msg * s_n_inv)

    ###################################################################################################################

    new_matrix = olll.reduction(matrix, 0.75)

    for row in new_matrix:
        potential_nonce_diff = row[0]

        r_1, s_1 = rs[0]
        potential_priv_key = (s_n * msg) - (s_1 * msg) - (s_1 * s_n * potential_nonce_diff)
        potential_priv_key *= libnum.invmod((r_n * s_1) - (r_1 * s_n), ORDER)

        potential_pub_key = ecdsa.ecdsa.Public_key(GEN.generator, GEN.generator * potential_priv_key)

        if potential_pub_key == possible_pub_keys[0].pubkey or potential_pub_key == possible_pub_keys[1].pubkey:
            sig_key = ecdsa.SigningKey.from_secret_exponent(potential_priv_key % ORDER, curve=GEN)
            print(f"FOUND!\nPrivate Key: {sig_key.to_string().hex()}")
            print("\nPayload containing 'flag' message:")
            print(f"Message: {b'flag'.hex()}")
            print(f"Signature: {sig_key.sign(b'flag').hex()}")
            return


def main():
    signatures = None
    with open("signatures.txt", "r") as wp:
        signatures = [s.strip() for s in wp.readlines()]
        signatures = [bytes.fromhex(s) for s in signatures]

    crack_signatures(signatures)


if __name__ == '__main__':
    main()
