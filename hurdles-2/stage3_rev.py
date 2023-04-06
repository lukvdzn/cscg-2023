
# string must be at least 33 bytes
STAGE2_INPUT = "1_kn0w_h0w_2448_abcdefghijklmnopqr"
RCX_COMPARE_FLAG = 0x197c13b9bb82c978


# Reverse engineered computation of select input bytes
def cmpute_(buff):
    b = 0x99
    h = 0xcc

    rxx = 0x1234567812345678 \
          + (buff[18] ^ 0x66) \
          + ((buff[23] ^ 0x44) << 8) \
          + ((~((~buff[15]) ^ 0x11)) << 16) \
          + ((((buff[16] & ~b) | (b & ~buff[16])) & 0xFF) << 24) \
          + ((buff[21] ^ 0x22) << 32) \
          + ((buff[32] ^ 0x88) << 40) \
          + ((buff[25] ^ 0x77) << 48) \
          + ((((buff[22] & h) | (~buff[22] & ~h)) & 0xFF) << 56) \
          + 0x3d77d3e81545bddd

    rax = ((rxx & 0xa6c4f78aa6b6e1bf) << 1) + (rxx ^ 0xa6c4f78aa6b6e1bf) + 0x1bc3348d44036064
    rax &= 0xFFFFFFFFFFFFFFFF

    return rax



def main():
    buff = bytearray(STAGE2_INPUT.encode('ascii'))

    indxs = [18, 23, 15, 16, 21, 32, 25, 22]

    # find chars starting with least significant byte
    for j, i in enumerate(indxs):
        for byt in list(range(33, 127)):
            buff[i] = byt
            rax = cmpute_(buff)

            mask = (j + 1) * 'ff'
            mask = int(mask, 16)

            if (rax & mask) == (RCX_COMPARE_FLAG & mask):
                print(f"Found [{j + 1}]: {buff[i].to_bytes(1, 'big').decode('ascii')}")
                break

    print(f"Stage 3 interim input: {buff.decode('ascii')}")


if __name__ == '__main__':
    main()
