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
  87:   mov    rdx, QWORD PTR [rsp+0x50]
  8c:   movabs rbx, 0xd39fc7066b8bda5c
  96:   mov    rax, QWORD PTR [rdx]
  99:   cmp    rbx, rax
  9c:   je     0xa3
  9e:   inc    rdx
  a1:   jmp    0x96
  a3:   add    rdx, 0x8
  a7:   mov    r15, rdx
  aa:   xor    rcx, rcx
  ad:   xor    rax, rax
  b0:   movzx  rbx, BYTE PTR [rdx+rcx*1]
  b5:   add    rax, rbx
  b8:   inc    rcx
  bb:   cmp    rcx, 0x4
  bf:   jne    0xb0
  c1:   add    rdx, rcx
  c4:   xor    rcx, rcx
  c7:   mov    bl, BYTE PTR [rdx+rcx*1]
  ca:   sub    r15, 0x8
  ce:   inc    rcx
  d1:   test   bl, bl
  d3:   jne    0xc7
  d5:   mov    r13, rdx
  d8:   mov    r14, rax
  db:   mov    rcx, 0x61
  e2:   lea    rsi, [rip+0xe]        # 0xf7
  e9:   lea    rdi, [rip+0x96]        # 0x186
  f0:   rep movs BYTE PTR es:[rdi], BYTE PTR ds:[rsi]
  f2:   jmp    0x0
  f7:   lea    rdx, [rip+0x0]        # 0xfe
  fe:   sub    rdx, 0x18d
 105:   mov    al, 0x90
 107:   mov    BYTE PTR [rdx], al
 109:   add    rdx, 0x4f
 10d:   mov    BYTE PTR [rdx], al
 10f:   xor    rcx, rcx
 112:   mov    rsi, r13
 115:   mov    cl, BYTE PTR [rsi]
 117:   test   rcx, rcx
 11a:   je     0x14c
 11c:   inc    rsi
 11f:   mov    bl, BYTE PTR [rsi]
 121:   test   bl, bl
 123:   jne    0x11c
 125:   inc    rsi
 128:   add    rsi, r14
 12b:   lea    rdi, [rip+0xfffffffffffffec6]        # 0xfffffffffffffff8
 132:   mov    rax, rcx
 135:   rep movs BYTE PTR es:[rdi], BYTE PTR ds:[rsi]
 137:   mov    rsi, rax
 13a:   add    r14, rax
 13d:   mov    rdi, QWORD PTR [r15]
 140:   add    r15, 0x8
 144:   inc    r13
 147:   jmp    0xffffffffffffff71
 14c:   xor    rdi, rdi
 14f:   mov    rax, 0x3c
 156:   syscall 
 158:   leave  
 159:   test   bl, al
 15b:   out    dx, eax
 15c:   pop    rdi
 15d:   rex.XB add r15d, ebp
 160:   ror    DWORD PTR [rbx-0x2e], 0x51
 164:   sbb    BYTE PTR [rax], al
        ...
