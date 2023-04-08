### ID: torukmagto

# Hurdles - Part 1
#### Preface
Reverse engineering is one of my favorite categories; however, as this is my first time coming into contact with CTFs and binary cracking in general, it was an extremely daunting yet fulfilling experience. Staring at assembly code for hours to find patterns at such a low level can truly drive someone crazy. Persistence is key.



## Reverse Engineering
The [binary](./challenge-files/hurdles) 
is subdivided into two parts. The first part is made up of stage{1, 2},
after which we would receive an interim flag, whereas stage{3, 4} constitue part 2 
, and upon solving them we would receive the final flag. Here is the 
main function decompiled by Ghidra:
```c
int8 main(int param_1,char** param_2)
{
  // check input length < 35 
  char cVar1 = FUN_004008c0();
  
  if (cVar1 != 0)
  {
      cVar1 = FUN_stage1(param_1,param_2);
      
      if (cVar1 != 0)
      {
          puts("You have completed stage 1");
          cVar1 = FUN_stage2(param_1,param_2);
      
          if (cVar1 != 0)
          {
              puts("You have completed stage 2");
          
              // print interim flag
              FUN_0048ab10(param_1,param_2);
          
              // Part 2
              // ...
          }
      }
  }

  puts("Bad input");
  return 0xffffffff;
}
```

We need an input that is less than 35 characters long.

### Stage 1

The first stage function seems fairly easy once you have mapped the decompiled Ghidra stack
variables to the function parameters and removed the bloat; Here is the trimmed down version:
```c
uint FUN_stage1(undefined8 _,char** argv)
{
  // our input string
  char *pcVar1 = argv[1];
  uint uVar2;
  ulong uVar3;
  
  // check string length >= 11 
  uVar3 = FUN_00400bc0(pcVar1);
  if (uVar3 < 0xb) 
      return 0;

  if (pcVar1[0] != '1')
    return 0;

  if (pcVar1[1] != '_')
    return 0;

  if (pcVar1[2] != 'k')
    return 0;

  do {
    do {
      if (((DAT_006eeef4 - 1) * DAT_006eeef4 & 1) == 0) {
        if (pcVar1[3] != 'n') {
          return 0;
        }
        if (pcVar1[4] != '0') {
          return 0;
        }
        if (pcVar1[5] != 'w') {
          return 0;
        }
        goto LAB_00400a7b;
      }

LAB_00400a2c:
    } while ((int)DAT_006eeef8 < 0x27);
  } while( true );

  
  uVar2 = 0;
  if (pcVar1[6] == '_' && pcVar1[7] == 'h') {
    
    if (pcVar1[8] == '0') {
      
      if (pcVar1[9] == 'w')
        uVar2 = uVar2 & 0xffffff00 | (uint)(pcVar1[10] == '_');
    }
  }
  return uVar2;
}
```

We can directly read out the first 11 characters of the correct 
input string: `1_kn0w_h0w_`.


### Stage 2
The second stage definitely needed more trimming and multiple debug runs
to correctly identify the involved variables:
```c
undefined8 stage_2(void)
{
  int uVar3;
  
  char bVar4;
  char cVar5;
  char bVar6;
  char bVar7;

  // represents argv
  char* in_RSI;
  char* argv_1 = in_rsi[1];
  
  int uVar2 = return_argv_length();
  
  
  switch(uVar2 < 15) {
    case false:
        bVar4 = -argv_1[11];

        cVar5 = 2 * (bVar4 & 0x67) + (bVar4 ^ 0xe7);
        bVar4 = -cVar5 - 0x19;
        bVar6 = cVar5 + 0x18;
        
        switch( (char)( 2 * (bVar4 & 0xd0) + (((bVar6 & bVar4 | bVar6) ^ bVar4) & 0xd0 ^ bVar4)) < 10 ) {
            case false:
                uVar3 = 0;
                break;

            case true:
                bVar6 = - argv_1[12];
                bVar4 = bVar6 ^ 0x30;

                switch((char)-((~bVar4 & bVar6) * '\x02' + bVar4) < 10) {
                    case false:
                        uVar3 = 0;
                        break;
                    
                    case true:
                        bVar4 = argv_1[13] - 0x39;
                        bVar6 = ~bVar4;
                        
                        switch((char)(~(~(bVar4 ^ 0x2f) & ~(bVar6 ^ bVar4 ^ 0x2f) | bVar6) * 2 + (bVar4 & 0x2f | bVar6 & 0xd0) + 0x39) < 10) {
                            case false:
                                uVar3 = 0;
                                break;
                            case true:
                                bVar4 = argv_1[14];
                                bVar7 = ~bVar4;
                                bVar6 = ~(~(bVar4 & 0xd0 | bVar7 ^ 0x2f) | bVar7 & (bVar7 ^ 0x2f) | bVar4 & 0x2f) * '\x02';

                                bVar7 = (bVar7 & 0xd0 ^ bVar4 & 0x2f) + 0x5f;
          
                                switch((char)((bVar7 & bVar6) * '\x02' + (bVar7 ^ bVar6) + 0xa1) < 10) {
                                    case false:
                                        uVar3 = 0;
                                        break;


                                    // Last sanity check
                                    case true:
                                        uVar3 = CONCAT71(0xa6e3a29dbfb830,
                                                    *(short *) ( 2 * (0x2c8e2eb120231781 + 
                                                                  (ulong) argv_1[11] * 1000 + 
                                                                  (ulong) argv_1[12] * 100 +
                                                                  (ulong) argv_1[13] * 10 + 
                                                                  (ulong)argv_1[14])  
                                                                  + 0x48b7c0) == 0x3419);
                                    }
                            }
                    }
            }
        
        break;
  
    case true:
        uVar3 = 0;
    }
    return uVar3;
}
```

Unlike in stage 1, the next 4 input characters `argv[11 - 14]` are now transformed before undergoing checks.
After the initial checks are done, we can see that the final check compares a transformed `uint64` number
to `0x3419`. I just created a crude [gen_stage2.c](./gen_stage2.c) program which uses 4 loops to enumerate
all possible ASCII characters. It correctly finds the intermediate input string: `1_kn0w_h0w_2448`.

## Flag
// First four letters in Uppercase
``CSCG{y4y_1_50lv3d_7h3_f1r57_h4lf}``
