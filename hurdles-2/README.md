### ID: torukmagto

# Hurdles - Part 2

## Reverse Engineering
As mentioned in [Hurdles Part 1](../hurdles-1/README.md),
the challenge is split into two parts. This is the second, much, much harder part
with stages {3,4}.

### Stage 3
The trimmed decompiled Ghidra code with edited variable/function signatures looks
as follows:

```c
ulong stage3(void)

{
  long lVar1;
  long lVar2;
  byte bVar3;
  ulong uVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte bVar9;
  byte bVar10;
  byte bVar11;
  byte bVar12;
  byte local_41;
  byte local_40;
  undefined7 uStack_3f;
  long local_38;
  
  local_38 = argv[1];
  uVar4 = strlen_helper2();
  lVar2 = local_38;
  
  // input string must be > 33, we know from stage 2 that it also must be < 35.
  // therefore, input length = 34.
  switch(uVar4 < 0x21) {
  case false:
    set_argpointer2val_to_argpointer1val_xor0x66();
    lVar1 = CONCAT71(uStack_3f,local_40);
    set_argpointer2val_to_argpointer1val();
    bVar3 = local_40 ^ 0x44;
    bVar6 = ~*(byte *)(lVar2 + 0xf);
    bVar5 = bVar6 & 0x11;
    bVar8 = *(byte *)(lVar2 + 0xf) ^ 0xee;
    bVar6 = bVar6 & 0x11;
    bVar7 = ~(bVar6 ^ bVar8 | bVar8 & bVar6);
    bVar6 = *(byte *)(lVar2 + 0x10);
    bVar11 = ~bVar6;
    bVar9 = ~(~(~(bVar6 & 0x66 | bVar11 ^ 0x99) | bVar6 & 0x99 ^ bVar11 & 0x66) | bVar11 ^ 0x99);
    bVar10 = bVar6 & 0x99 ^ bVar11 & 0x66;
    bVar11 = bVar11 & 0x99;
    bVar12 = ~bVar11 & bVar10;
    bVar8 = ~(bVar10 ^ bVar11) & bVar12;
    bVar6 = ~(bVar10 ^ bVar11) ^ bVar12;
    bVar6 = ~(bVar6 ^ bVar8 | bVar8 & bVar6);
    bVar6 = bVar6 ^ bVar12 | bVar6 & bVar12;
    bVar10 = ~(bVar6 ^ bVar10 & bVar11 | bVar10 & bVar11 & bVar6);
    bVar8 = *(byte *)(lVar2 + 0x15);
    bVar6 = *(byte *)(lVar2 + 0x20);
    xor_0x77_lshift_0x30();
    FUN_004038e0(lVar1 + 0x1234567812345678 + (ulong)bVar3 * 0x100 +
                 (ulong)(byte)(bVar7 ^ bVar5 | bVar5 & bVar7) * 0x10000 +
                 (ulong)(byte)(bVar10 ^ bVar9 | bVar9 & bVar10) * 0x1000000 +
                 (((ulong)bVar8 ^ 0x22) << 0x20) + ((ulong)(bVar6 ^ 0x88) << 0x28),
                 CONCAT71(uStack_3f,local_40),lVar2,&local_40,&local_41,0xe7f798d);
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
    uVar4 = CONCAT71(uStack_3f,local_40) + ((ulong)(byte)(bVar8 ^ bVar6 | bVar8 & bVar6) << 0x38) +
            0x3d77d3e81545bddd;
    uVar4 = (uVar4 ^ 0xa6c4f78aa6b6e1bf) + (uVar4 & 0xa6c4f78aa6b6e1bf) * 2 + 0x1bc3348d44036064;
    uVar4 = uVar4 & 0xffffffffffffff00 | (ulong)(uVar4 == 0x197c13b9bb82c978);
    break;
  case true:
    uVar4 = 0;
  }
  return uVar4;
}
```

First, the length of the input is checked again, which must be > 33, 
and we know from stage 2 that it also must be < 35. 

The variable `uVar4` holds our return value, we work our way backwards.
However, as we can see the decompiled code presents a giant mess of 
arithmetic and logical operations, which is why manual debugging
is needed. Keeping track of the relevant registers proved to be a major 
headache as multiple operations were combined, but luckily for us,
mostly logical operations were used up until the very end; Bitwise functions,
as the name implies, have the nice property that they only have 1 or 0
as values and do not propagate its result to other bits.
With the help of Boolean Algebra we can simplify some terms at each step,
for example:

```logic
// a, b, c = registers or constants

 ~(~(a) & (~(b)) | ((b) ^ (a))) = (a & b)
```

The `logic` module of the [sympy](https://docs.sympy.org/latest/modules/logic.html)
package was used for the boolean simplifications. The 
file [stage3_step_by_step](./helper/stage3_step_by_step_dump)
contains the register contents at several checkpoints.

#### Simplified Final Operation
```python
def stage3_deobf():
    b = 0x99
    h = 0xcc
    
    rxx = 0x1234567812345678 \
          + (input[18] ^ 0x66) \
          + ((input[23] ^ 0x44) << 8) \
          + ((~((~input[15]) ^ 0x11)) << 16) \
          + ((((input[16] & ~b) | (b & ~input[16])) & 0xFF) << 24) \
          + ((input[21] ^ 0x22) << 32) \
          + ((input[32] ^ 0x88) << 40) \
          + ((input[25] ^ 0x77) << 48) \
          + ((((input[22] & h) | (~input[22] & ~h)) & 0xFF) << 56) \
          + 0x3d77d3e81545bddd
    
    rax = ((rxx & 0xa6c4f78aa6b6e1bf) << 1) + (rxx ^ 0xa6c4f78aa6b6e1bf) + 0x1bc3348d44036064
    rax &= 0xFFFFFFFFFFFFFFFF
    
    # result in al
    return rax == 0x197c13b9bb82c978
```
The next 8 characters that are checked
are not the actual 8 next characters of the input. Bruteforcing
seems futile, assuming the search space for each input character
contains 95 readable ascii characters in the worst case.
However, we notice that the transformed bytes are encoded in a steplike 
manner, indicated by the left shifts of multiplicity 8.
We can therefore try to start to enumerate all possible characters 
for the least significant byte (`input[18]`)
and work our way up. Indeed, by doing so yielded the next 8 valid 
characters at their respective indices. 10 characters to find remain
for the last stage.

## Flag
```
// First four letters in uppercase
Flag: CSCG{1_kn0w_h0w_2448_0bfu5c4710n_w0rk5!}
```