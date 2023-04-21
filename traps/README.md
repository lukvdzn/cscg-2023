### ID: torukmagto

# Dynamic Analysis and Ptrace

## Traps

### An Unwelcome Trap
The executable [traps](./challenge-files/traps) is a statically linked
x86-64 binary, the main functions begins as follows 
(Ghidra decompiled, additional function signatures loaded):

```C
undefined8 main(void)

{
    /* LOCALS */
    uint32 pid;
    ...
  
    pid = __getpid();
    FUN_welcome(pid);
    pid = fork();
    
    ...
} 
```

Firstly, the pid is determined and `FUN_welcome()` is called, 
which presents the first trap; Regardless of struct_regs the function prints `NO :(` and exits.
Here is the revised decompilation with comments: 

```C
void FUN_welcome(int edi_parent_pid)
{
    int iVar1;
    long lVar2;
    ulong uVar3;
    ulong extraout_RDX;
    uint wstatus;
    int64 struct_regs [27];
    
    iVar1 = fork();
    if (iVar1 == 0) 
    {
        /* PTRACE_ATTACH */
        if (ptrace(PTRACE_ATTACH, edi_parent_pid,(void *)0x0, (void *)0x0) < 0)
            goto LAB_00402698;
        
        iVar1 = _waitpid(edi_parent_pid, (int *)&wstatus, __WALL);
        uVar3 = (ulong)wstatus;
        
        if (((iVar1 < 0) || ('\x01' < (char)(((byte)wstatus & 0x7f) + 1))) || ((wstatus & 0x7f) == 0))
            goto LAB_004026cd;
                        
        /* PTRACE_GETREGS: stores register values of parent process in `struct_regs` as
                       `struct user_regs_struct`. */
        if (ptrace(PTRACE_GETREGS, edi_parent_pid, (void *)0x0, struct_regs) < 0)
LAB_00402698:        
            /* WARNING: Subroutine does not return */
            exit_with_additions(0xffffffff);
    
        struct_regs[0] = 0;
        
        /* PTRACE_SETREGS: Set registers of parent process, in this case set `r15 = 0` */
        lVar2 = ptrace(PTRACE_SETREGS, edi_parent_pid, (void *)0x0, struct_regs);
        
        /* PTRACE_DETACH: detach from parent process */
        if (lVar2 < 0 || ptrace(PTRACE_DETACH, edi_parent_pid, (void *)0x0, (void *)0x0) < 0)
            goto LAB_00402698;

        exit_group(0);
    }
    
    __wait(0);
    
    print_("Welcome to your average flag checker! Please give me a flag:");
    IO_fgets((char *)struct_regs, 0x40, (int64_t)&DAT_004a9520);
    No_smiley((char *)struct_regs);
    
LAB_004026cd:
    /* WARNING: Subroutine does not return */
    exit_with_additions(uVar3 >> 8 & 0xff);
}
```

Here we can see why debugging(tracing) fails on the parent process:
A child process is created, which then attaches to the parent via `ptrace`;
Since only one process is allowed to trace another process and debuggers
use _Tracing_ internally, the child process cannot attach to the parent
process and thus exits with failure.
Conversely, the parent process first waits for the child to terminate
and awaits user input, only to discard and print `No :(`. It then exits
with failure as well. But let us focus on 
what the child would do in the normal case:
1. attach to parent
2. set `r15` of parent to 0
3. detach and exit gracefully

The non-deobfuscated checks for the `wstatus` such as 
```C
if ('\x01' < (char)(((byte)wstatus & 0x7f) + 1))) || ((wstatus & 0x7f) == 0)
```
verify whether the parent has stopped and not exited.

But why does the parent exit with failure and not return to `main`?
In this case the decompiler fails; the disassembly explains why:

```assembly  
0x402678    MOV     R15, 0x1
0x40267f    XOR     edi, edi
0x402681    CALL    __wait
0x402686    MOV     RAX, R15
0x402689    TEST    RAX, RAX
0x40268c    JNZ     CONTINUE_WITH_PRINT 
0x40268e    ADD     RSP, 0xf8
0x402695    POP     RBX
0x402696    POP     RBP
0x402697    RET
```

Before calling wait, the parent process initializes `r15 = 1`; Once the child
has exited it checks whether it is 0, if not it jumps to the undesired continuation.
This is where Ghidra fails, it assumes `r15` to remain constant (callee-saved) 
throughout the `__wait` function and disregards the return path.
It is therefore important to always keep in mind that decompiled code is not 100% correct.


### Main
After taking the first trap into account, we can come back to the `main` function:

```C
undefined8 main(void)

{
    int extraout_EAX;
    int pid_child;
    int iVar1;
    long lVar2;
    byte bVar3;
    void *addr;
    ulong uVar4;
    byte *pbVar5;
    long local_148;
    int64_t *local_140;
    uint child_wstatus;
    int64_t regs_struct [27];
    int64_t rip_child;
    
    pid_child = __getpid();
    FUN_welcome(pid_child);
    pid_child = fork();
    
    if (pid_child == 0) 
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) 
            goto LAB_004017d3;
        
        _sigstop(0x13);
        jump_table_with_int3();
    }
    
    iVar1 = _waitpid(pid_child, (int *) &child_wstatus, __WALL);
    uVar4 = (ulong)child_wstatus;
    
    if (((-1 < iVar1) && ((child_wstatus & 0x7f) == 0 || (char)(((byte)child_wstatus & 0x7f) + 1) < '\x01')) && ((child_wstatus & 0x7f) != 0)) 
    {
        if (ptrace(PTRACE_SETOPTIONS, pid_child, NULL, PTRACE_O_EXITKILL) || (lVar2 = ptrace(PTRACE_CONT, pid_child, NULL, SIGCONT < 0) 
        {
LAB_004017d3:
            /* WARNING: Subroutine does not return */
            exit_(-1);
        }
    
        bVar3 = 0x7f;
        pbVar5 = &DAT_004019c6;
        local_140 = int64_t_ARRAY_00401915;
        local_148 = 0;
        
        do {
            iVar1 = _waitpid(pid_child, (int *) &child_wstatus, _WALL);
              
            if (((iVar1 < 0) || ('\x01' < (char)(((byte)child_wstatus & 0x7f) + 1))) || ((child_wstatus & 0x7f) == 0)) 
                goto LAB_004017db;
            
            if (ptrace(PTRACE_GETREGS, pid_child, NULL, regs_struct) < 0) 
                goto LAB_004017d3;
            
            rip_child = regs_struct[16];
            /* RDI = 14, RSI = 13 */
            regs_struct[14] = *local_140;
            regs_struct[13] = (ulong)bVar3;

            if (ptrace(PTRACE_SETREGS, pid_child, NULL, regs_struct) < 0) 
                goto LAB_004017d3;
          
            addr = (void *)(rip_child + 0x86);
            uVar4 = 0;

            if (bVar3 >> 3 != 0) 
            {
                do {
                    if (ptrace(PTRACE_POKETEXT, pid_child, addr, *(void **)(&DAT_004019db + uVar4 * 8 + local_148)) < 0) 
                        goto LAB_004017d3;
                    uVar4 = uVar4 + 1;
                    addr = (void *)((long)addr + 8);
                } while (uVar4 != bVar3 >> 3);
            }
          
            local_148 = local_148 + (ulong)bVar3;
          
            if (ptrace(PTRACE_CONT, pid_child, NULL, SIGCONT) < 0) 
                goto LAB_004017d3;
            
            bVar3 = *pbVar5;
            local_140 = local_140 + 1;
            pbVar5 = pbVar5 + 1;
        
        } while (bVar3 != 0);
        
        pid_child = _waitpid(pid_child, (int *)&child_wstatus, _WALL);
        if (((-1 < pid_child) && ((char)(((byte)child_wstatus & 0x7f) + 1) < '\x02')) && ((child_wstatus & 0x7f) != 0)) 
            return 0;
    }
    
LAB_004017db:
    exit_(child_wstatus >> 8 & 0xff);
}
```

Again, we are met with the same ptrace mess as before; However, this time the roles are reversed:
1. Child forks from parent and indicates that it can be traced by its parent
2. Child sends **SIGSTOP** to itself and waits for a continue signal
3. Meanwhile, parent waits until child is stopped and then sets the _PTRACE_O_KILL_ option (tracee (child)
    will be sent **SIGKILL** if tracer (parent) exits) and then resumes child process via _PTRACE_CONT_
4. Child then executes `jump_table_with_int3()`, which looks as follows:

```C
void jump_table_with_int3(void)
{
    code *CODE_INJECT;
    long lVar1;
    
    CODE_INJECT = (code *) mmap_rwx_private_0x1000();
    if (CODE_INJECT == -1)
        exit_(-1);
    
    for (i = 0; i < 0x87; ++i)
        CODE_INJECT[i] = (code)(&DAT_0040246f)[i];
       
    (*CODE_INJECT)();
    return;
}
```

The child process first request a new address mapping with size 0x1000,
`RWX` permissions and private-anonymous flags, such that the mapping is not
backed by any file and not 
visible to other processes, making it harder to inspect the
injected code that will be explained below.

5. Here is where the actual magic happens: the parent executes the main `do-while` loop
    where it waits for the child to stop to modify the `RDI`, `RSI` registers and inject
    new code just a few instructions ahead of the child `RIP`; the loop is executed 21 
    times, this can be inferred by inspecting the data `DAT_0x4019c6` bytes.


### Approach
Since the code is injected into the non-visible memory mapping of the child,
we cannot directly determine what actually is executed at each loop stage.
However, we can patch the binary to not fork and only execute the child program 
flow; we can simulate the `ptrace` calls by emulating the patched binary
and hooking into all addresses where the child is interrupted, and inject code
directly via the emulator framework.

The patched binary [traps_patched](./helper-files/traps_patched) skips the unnecessary
`FUN_welcome()` function and only executes the child part. [Qiling](https://qiling.io/)
is used as the emulator framework. The good thing about it is that it can also
act as a gdb-server; debugging with gdb revealed that an `INT 3` instruction
is used to interrupt the child and inject code, furthermore, it also represents
the loop start address of the 21 stages, so we will hook into this instruction;
The folder [disasmdumps](./disasmdumps) contains the disassembly for each of the stages:
- The first stage uses syscalls to print the welcome message and read the users input
- The second stage validates that the input (located on the stack) is 64 characters, XOR's each byte with `0xd`
    and pushes the size `0x40` onto the stack
- The third stages prepares some internal stuff, possibly for the next stages
- The fourth stage uses another syscall to `ptrace` to again verify that the parent process
    is not being traced, eg. by a debugger
- The stages 5 through 20 do the actual input check, details below
- The last stage checks whether the top value on the stack matches `0x50`,
    if successful we get printed `YES`, if not `NO :(`

#### Input Validation
On each of the 16 stages from stage 5 through 20 the input is transformed
and validated as follows:

```C
[STAGE_i]

edi = 0;

for(int j = 0; j < 16; ++j)
    edi += ((int) *(CONST_DATA_ADDR + 4 * j)) * ((int) *(INPUT_XOR + 4 * j));

top_stack += edi == *(RIP + 0x4f);
```

As we can see, on each stage the input is subdivided into chunks of 4 bytes
which are converted to ints, multiplied by some constant ints and summed up.
Only if the sum equals another int constant, the top value on the stack
(initially the size of the input `0x40`) is incremented by 1. So the input
flag can only be correct if in all of those stages the top stack value
gets incremented. 

### Cracking the Code
We solve this system of linear equations modulo 32 with the theorem
solver [z3](https://github.com/Z3Prover/z3). 
In [qlz3_crack.py](./qlz3_crack.py), the constant operands and the 
to-match value at each stage are extracted and fed into z3,
which can then retrieve the flag.

## Flag
```
CSCG{4ND_4LL_0FF_TH1S_W0RK_JU5T_T0_G3T_TH1S_STUUUP1D_FL44G??!!1}
```
