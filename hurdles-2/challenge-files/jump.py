import pwnlib.gdb
from pwn import *

inp = '1_kn0w_h0w_2448_aedee6789abcdefgh'
p = gdb.debug(['./hurdles', inp], api=True, gdbscript="""
    b *0x004028ef
    continue
""")

gdb_: pwnlib.gdb.Gdb = p.gdb

r12 = gdb_.execute('p/x $r12', to_string=True)
print(r12.replace('$1', 'R12').strip() + f' ,{inp}')

gdb_.quit()
p.kill()