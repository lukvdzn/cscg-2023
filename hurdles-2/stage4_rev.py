import pwnlib.gdb
from pwn import *


# all readable characters, first [a-z], [0-9] to speed up process
CHARS = [97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
         117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71,
         72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 32, 33, 34, 35, 36,
         37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 94, 95, 96,
         123, 124, 125, 126]


# Input from stage 3
INPUT = bytearray('1_kn0w_h0w_2448_0bfdec47i0klmnop5r'.encode('ascii'))
INDICES_ALREADY_FOUND = list(range(0, 17)) + [18, 21, 22, 23, 25, 32]


# Slow due to gdb process attach overhead, took about 45 minutes

def main():
    with context.local(log_level='error'):
        # input should be 34 characters
        for i in range(34):
            if i in INDICES_ALREADY_FOUND:
                continue

            for char in CHARS:
                INPUT[i] = char
                p = gdb.debug(['./challenge-files/hurdles', INPUT.copy().decode('ascii')],
                              api=True,
                              gdbscript=f"b *0x489604\n")
                gdb_: pwnlib.gdb.Gdb = p.gdb

                # traverse loop until it is INPUT[i]'s turn
                for _ in range(i + 1):
                    gdb_.continue_and_wait()

                # character is found if al = 1
                s: str = gdb_.execute(f'p/x $al', to_string=True)
                s = s[s.find(' = ') + len(' = '):].strip()
                if s == '0x1':
                    print(f"Found [{i}]: {char.to_bytes(1, 'big').decode('ascii')}")

                gdb_.quit()
                p.kill()

    print(INPUT.decode('ascii'))


if __name__ == '__main__':
    main()
