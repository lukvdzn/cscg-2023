   0:   int3   
   1:   xor    rcx, rcx
   4:   inc    rcx
   7:   shl    rcx, 0x8
   b:   sub    rsp, rcx
   e:   mov    rdx, rsp
  11:   mov    BYTE PTR [rdx+rcx*1-0x1], cl
  15:   loop   0x11
  17:   inc    rcx
  1a:   shl    rcx, 0x8
  1e:   xor    rax, rax
  21:   xor    rbx, rbx
  24:   mov    bl, BYTE PTR [rdx+rcx*1-0x1]
  28:   add    al, bl
  2a:   mov    r8, rcx
  2d:   and    cl, 0x7
  30:   shl    cl, 0x3
  33:   mov    rbx, rdi
  36:   shr    rbx, cl
  39:   add    al, bl
  3b:   mov    rcx, r8
  3e:   mov    r8b, BYTE PTR [rdx+rcx*1-0x1]
  43:   xchg   BYTE PTR [rdx+rax*1], r8b
  47:   mov    BYTE PTR [rdx+rcx*1-0x1], r8b
  4c:   loop   0x24
  4e:   mov    al, 0x0
  50:   xor    rbx, rbx
  53:   lea    rdi, [rip+0x2d]        # 0x87
  5a:   inc    rcx
  5d:   mov    bl, cl
  5f:   add    al, BYTE PTR [rdx+rbx*1]
  62:   mov    r8b, BYTE PTR [rdx+rbx*1]
  66:   xchg   BYTE PTR [rdx+rax*1], r8b
  6a:   mov    BYTE PTR [rdx+rbx*1], r8b
  6e:   mov    bl, BYTE PTR [rdx+rax*1]
  71:   add    bl, r8b
  74:   mov    bl, BYTE PTR [rdx+rbx*1]
  77:   xor    BYTE PTR [rdi+rcx*1-0x1], bl
  7b:   cmp    rsi, rcx
  7e:   jne    0x5a
  80:   add    rsp, 0x100
  87:   mov    rcx, QWORD PTR [rsp]
  8b:   mov    rax, 0x40
  92:   cmp    rax, rcx
  95:   je     0xbe
  97:   mov    rax, 0x1
  9e:   mov    rdi, 0x1
  a5:   lea    rsi, [rip+0x29]        # 0xd5
  ac:   mov    rdx, 0x7
  b3:   syscall 
  b5:   mov    rax, 0x3c
  bc:   syscall 
  be:   lea    rdx, [rsp+0x8]
  c3:   mov    rbx, 0xd
  ca:   xor    BYTE PTR [rdx+rcx*1-0x1], bl
  ce:   loop   0xca
  d0:   jmp    0x0
  d5:   rex.WRX
  d6:   rex.WRXB and BYTE PTR [r10], r15b
  d9:   sub    BYTE PTR [rdx], cl
  db:   add    BYTE PTR [rbx+0x754466ef], ah
  e1:   rex.RX (bad) 
  e3:   jb     0x106
  e5:   and    BYTE PTR [rax+0x6c], dl
  e8:   gs (bad) 
  ea:   jae    0x151
  ec:   and    BYTE PTR [rdi+0x69], ah
  ef:   jbe    0x156
  f1:   and    BYTE PTR [rbp+0x65], ch
  f4:   and    BYTE PTR [rcx+0x20], ah
  f7:   data16 ins BYTE PTR es:[rdi], dx
  f9:   (bad)  
  fa:   cmp    cl, BYTE PTR [edx]
  fd:   add    BYTE PTR [rcx], dh
  ff:   jmp    0xffffffff9ac7ac6b
 104:   mov    ds, WORD PTR [rsi]
        ...
