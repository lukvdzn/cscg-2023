from pwn import *
from qiling import *
from qiling.extensions import pipe
from qiling.const import QL_VERBOSE
from z3 import *


DAT_0x4019c6 = [
    0x7f, 0x5c, 0xde, 0x53, 0x82, 0x86, 0x84, 0x87, 0x83, 0x83, 0x87, 0x86, 0x85,
    0x84, 0x85, 0x81, 0x82, 0x81, 0x81, 0x84, 0x4b
]

DAT_0x401915 = [
    0x4b77d34ec5485884,	0x48baad88fd1a5009, 0xb4072a146dd78ed7,	0x52114b49c7ee3d78,
    0xe5502117ef8b0527,	0x092b5aa44e3c709c, 0x3a3f1a95a68984b9,	0x42e17041996414f8,
    0x0653b817546ef146,	0x3817ecc7821c2dfe, 0x5dbea3cafc5165ea,	0x112586462aed09dd,
    0xe3c7a18f941275b6,	0x9e8ac071d1413e17, 0x2149a56e413a98a2,	0x938f0a1786110803,
    0x1fada05c327cacf3,	0xf4b1b977a0be94b8, 0x4617bbf3914c1e3f,	0x1e83af0034a79386
]


class QlStub:
    def __init__(self, ql: Qiling, flag: bytes):
        self.dat_0x4019db = 0x4019db

        self.loop_counter = 0
        self.dat_0x4019db_index = 0

        # arbitrary flag
        ql.os.stdin = pipe.SimpleInStream(0)
        ql.os.stdin.write(flag)

        # hook into SIGSTOP and INT3
        ql.os.set_syscall('tgkill', self.hook_sigstop)
        ql.hook_intno(self.hook_int3, 0x3)

        self.dyn_code_inj_base_addr = 0x7fffb7dd6000
        # this map will contain the operands used at each of the 16 stages with their respective 'match' dword
        self.dynamic_operands = dict()

        ql.hook_address(self.extract_operands, self.dyn_code_inj_base_addr + 0x9f)


    @staticmethod
    def hook_sigstop(ql: Qiling, *_):
        ql.log.info(f'Encountered SIGSTOP at 0x{ql.arch.regs.arch_pc:x}!')


    # the parent process injects code to the child process during interrupts in the original binary, we
    # will simulate this by hooking all INT 3 instructions
    def hook_int3(self, ql: Qiling, *_):
        ql.log.info(f'Encountered INT 3 at 0x{ql.arch.regs.arch_pc:x}, injecting code!')
        
        if self.loop_counter < len(DAT_0x4019c6):
            dat_0x401915_q = DAT_0x401915[self.loop_counter]
            dat_0x4019c6_b = DAT_0x4019c6[self.loop_counter]

            # modify registers (PTRACE_SETREGS)
            rip = ql.arch.regs.arch_pc
            ql.arch.regs.write('RSI', dat_0x4019c6_b)
            ql.arch.regs.write('RDI', dat_0x401915_q)

            addr = rip + 0x86

            if (dat_0x4019c6_b >> 3) != 0:
                j = 0

                while True:
                    # write new instructions (PTRACE_POKETEXT)
                    dat = ql.mem.read(self.dat_0x4019db + j * 8 + self.dat_0x4019db_index, 8)
                    ql.mem.write(addr, bytes(dat))
                    # ql.log.info(f'*0x{addr:x} = 0x{int.from_bytes(dat, "little"):x}')

                    j += 1
                    addr += 8

                    if j == (dat_0x4019c6_b >> 3):
                        break

            self.dat_0x4019db_index += dat_0x4019c6_b

        self.loop_counter += 1


    # extract the injected operands during validation
    def extract_operands(self, ql: Qiling, *_):
        rip = f'{ql.arch.regs.arch_pc:x}'
        operand = ql.arch.regs.read('eax')

        dump = disasm(ql.mem.read(self.dyn_code_inj_base_addr, 800),
                      arch='amd64',
                      vma=self.dyn_code_inj_base_addr,
                      byte=False)

        instr = [x for x in dump.split('\n') if rip in x and 'imul' in x]

        if instr:
            # this will be the match dword which will be compared to the transformed input
            match = ql.mem.read(self.dyn_code_inj_base_addr + 0x102, 4)
            match = int.from_bytes(match, 'little')

            if match in self.dynamic_operands:
                self.dynamic_operands[match].append(operand)
            else:
                self.dynamic_operands[match] = [operand]


class ZSolv:
    def __init__(self, op_map):
        self.op_map = op_map


    def retrieve_flag(self):
        z3s = Solver()

        # our unknowns
        flag_dwords = [BitVec(f'{i}', 32) for i in range(16)]

        for match, operands in self.op_map.items():
            sum_ = BitVecVal(0, 32)
            for i, operand in enumerate(operands):
                oprnd_dword = BitVecVal(operand, 32)
                xor_flag_dword = flag_dwords[i]
                sum_ += oprnd_dword * xor_flag_dword

            z3s.add(sum_ == BitVecVal(match, 32))

        if not z3s.check():
            return 'Unsatisfiable'
        else:
            m = z3s.model()
            m = sorted([(int(str(flag_dw)), m[flag_dw]) for flag_dw in m], key=lambda x: x[0])
            m = [str(x[1]) for x in m]
            flag = b''.join([int(str(x)).to_bytes(4, 'little') for x in m])
            # input was xor'ed before validations
            return bytes([x ^ 0xd for x in flag])


def main():
    ql = Qiling(["./helper-files/traps_patched"],
                rootfs="/",
                archtype='x8664',
                ostype='Linux',
                multithread=False,
                verbose=QL_VERBOSE.OFF)

    # we know flag is 64 characters
    flag = 64 * b'a' + b'\n'
    qls = QlStub(ql, flag)
    ql.run()

    # fetch the operands map and feed it into z3
    op_map = qls.dynamic_operands
    z3s = ZSolv(op_map)

    print(f'FLAG: {z3s.retrieve_flag().decode()}')

    # ql.debugger = True


if __name__ == '__main__':
    main()
