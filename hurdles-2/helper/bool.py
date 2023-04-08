from sympy import symbols
from sympy.logic import simplify_logic


def main():
    g, h = symbols('g h')
    a, b, c = symbols('a b c')
    s = simplify_logic((~(~(a) & (~(b)) | ((b) ^ (a)))))
    print(f'( {s} )')

    g = 0x67
    h = 0xcc
    a = 0x61
    b = 0x99

    z = eval(str(s))
    z = z & 0xff
    print(f'0x{z:x}')


if __name__ == '__main__':
    main()
