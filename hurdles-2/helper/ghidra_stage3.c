wulong stage3(void)

{
  long lVar1;
  byte bVar3;
  ulong slen;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;

  byte bVar9;
  byte bVar10;
  byte bVar11;
  byte bVar12;
  byte local_41;
  
  undefined7 uStack_3f;
  
  char* argv_1 = *(long *)(in_RSI + 8);
  int slen = strlen_helper2();
  char* argv_1_copy = argv_1;

  if (slen < 33)
  {
    return 0;
  }

  // payload has at least 33 characters
  // 1_kn0w_h0w_2448_123456789abcdefgh


  RDI = &argv_1[18];

  char stack_8 = RDI[0] ^ 0x66;


  // to inspect
  lVar1 = CONCAT71(uStack_3f, stack_8);
  
  stack_8 = RDI[23];

  bVar3 = stack_8 ^ 0x44;


  char bVar6 = ~argv_1_copy[15] & 0x11;
  // bVar5 = bVar6 & 0x11;

  char bVar8 = argv_1_copy[15] ^ 0xee;
  char bVar7 = ~(bVar6 ^ bVar8 | bVar8 & bVar6);
  
  bVar6 = argv_1_copy[16];

  char bVar11 = ~bVar6;
  char bVar9 = ~(~(~(bVar6 & 0x66 | bVar11 ^ 0x99) | bVar6 & 0x99 ^ bVar11 & 0x66) | bVar11 ^ 0x99);
  
  char bVar10 = bVar6 & 0x99 ^ bVar11 & 0x66;

  bVar11 = bVar11 & 0x99;
  
  
  bVar12 = ~bVar11 & bVar10;
  bVar8 = ~(bVar10 ^ bVar11) & bVar12;
  bVar6 = ~(bVar10 ^ bVar11) ^ bVar12;
  bVar6 = ~(bVar6 ^ bVar8 | bVar8 & bVar6);
  bVar6 = bVar6 ^ bVar12 | bVar6 & bVar12;

  bVar10 = ~(bVar6 ^ bVar10 & bVar11 | bVar10 & bVar11 & bVar6);
  
  
  bVar8 = argv_1_copy[21];
  bVar6 = argv_1_copy[32];


  // b 0x000000000040339b
  
  // stack8 will be transformed to 64bit
  int64 stack_8 = (argv_1[25] ^ 0x77) << 0x30;
  RSI = stack_8;
  
  
  FUN_004038e0(lVar1 + 0x1234567812345678 + (ulong)bVar3 * 0x100 +
                (ulong)(byte)(bVar7 ^ bVar5 | bVar5 & bVar7) * 0x10000 +
                (ulong)(byte)(bVar10 ^ bVar9 | bVar9 & bVar10) * 0x1000000 +
                (((ulong)bVar8 ^ 0x22) << 0x20) + ((ulong)(bVar6 ^ 0x88) << 0x28),
                CONCAT71(uStack_3f,stack_8),argv_1_copy,&stack_8,&local_41,0xe7f798d);
  
  
  bVar6 = ~(~local_41 ^ 0xff);
  bVar6 = ~(local_41 | bVar6) | bVar6;
  bVar8 = ~bVar6;
  bVar6 = bVar6 & 0xcc | bVar8 & 0x33;
  bVar8 = bVar8 & 0xcc;
  bVar3 = ~(bVar6 ^ bVar8);
  bVar5 = bVar3 & bVar8;
  bVar6 = ~bVar8 & bVar6;
  bVar6 = ~(bVar3 | bVar6) | bVar6;
  bVar8 = ~(bVar6 ^ bVar5 | bVar5 & bVar6);
  bVar6 = (~(~(~local_41 ^ 0xcc) | local_41 & 0xcc) & 0xcc | local_41 & 0xcc) ^ bVar8;
  bVar8 = ~bVar6 & bVar8;


  slen = CONCAT71(uStack_3f,stack_8) + ((ulong)(byte)(bVar8 ^ bVar6 | bVar8 & bVar6) << 0x38) +
          0x3d77d3e81545bddd;

  slen = (slen ^ 0xa6c4f78aa6b6e1bf) + (slen & 0xa6c4f78aa6b6e1bf) * 2 + 0x1bc3348d44036064;
  slen = slen & 0xffffffffffffff00 | (ulong)(slen == 0x197c13b9bb82c978);
}

