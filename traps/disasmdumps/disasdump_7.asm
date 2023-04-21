   0:   nop
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
  4e:   mov    al, 0x90
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
  87:   lea    rbx, [rsp+0x8]
  8c:   lea    rdx, [rip+0x2f]        # 0xc2
  93:   xor    rdi, rdi
  96:   xor    rax, rax
  99:   xor    rcx, rcx
  9c:   mov    eax, DWORD PTR [rdx+rcx*4]
  9f:   imul   eax, DWORD PTR [rbx+rcx*4]
  a3:   add    edi, eax
  a5:   inc    cl
  a7:   cmp    rcx, 0x10
  ab:   jb     0x9c
  ad:   sub    edi, DWORD PTR [rip+0x4f]        # 0x102
  b3:   neg    edi
  b5:   sbb    edi, edi
  b7:   inc    edi
  b9:   pop    rax
  ba:   add    eax, edi
  bc:   push   rax
  bd:   jmp    0x186
  c2:   rex.WRXB je 0x114
  c5:   rex.WRX adc rax, 0x272f062
  cb:   call   0x3dd2a228
  d0:   mov    cs, WORD PTR [rsi]
  d2:   mov    ecx, 0xa2da501b
  d7:   or     ecx, esp
  d9:   xor    eax, 0x497172f0
  de:   (bad)  
  df:   push   rax
  e0:   mov    al, 0xc2
  e2:   push   rdx
  e3:   (bad)  
  e4:   lods   al, BYTE PTR ds:[rsi]
  e5:   mov    ch, 0x18
  e7:   (bad)  
  e8:   (bad)  
  e9:   out    dx, eax
  ea:   jnp    0xbe
  ec:   (bad)  
  ed:   popf   
  ee:   rex.R mov bpl, 0x25
  f1:   mov    BYTE PTR [rbx-0x3e502c71], bl
  f7:   rex.WRB call 0xffffffffda452188
  fd:   or     bl, BYTE PTR [rip+0xffffffffcd141a6e]        # 0xffffffffcd141b71
 103:   rex.WXB scas al, BYTE PTR es:[rdi]
 105:   push   rdi
 106:   nop
 107:   (bad)  
 108:   sahf   
 109:   pushf  
 10a:   and    al, 0xc
 10c:   ror    BYTE PTR [rax-0x36ceb7fe], 0x4c
 113:   mov    esi, ebp
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
 186:   lea    rdx, [rip+0x0]        # 0x18d
 18d:   sub    rdx, 0x18d
 194:   mov    al, 0x90
 196:   mov    BYTE PTR [rdx], al
 198:   add    rdx, 0x4f
 19c:   mov    BYTE PTR [rdx], al
 19e:   xor    rcx, rcx
 1a1:   mov    rsi, r13
 1a4:   mov    cl, BYTE PTR [rsi]
 1a6:   test   rcx, rcx
 1a9:   je     0x1db
 1ab:   inc    rsi
 1ae:   mov    bl, BYTE PTR [rsi]
 1b0:   test   bl, bl
 1b2:   jne    0x1ab
 1b4:   inc    rsi
 1b7:   add    rsi, r14
 1ba:   lea    rdi, [rip+0xfffffffffffffec6]        # 0x87
 1c1:   mov    rax, rcx
 1c4:   rep movs BYTE PTR es:[rdi], BYTE PTR ds:[rsi]
 1c6:   mov    rsi, rax
 1c9:   add    r14, rax
 1cc:   mov    rdi, QWORD PTR [r15]
 1cf:   add    r15, 0x8
 1d3:   inc    r13
 1d6:   jmp    0x0
 1db:   xor    rdi, rdi
 1de:   mov    rax, 0x3c
 1e5:   syscall 
        ...
