
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

undefined8 stage_2(void)
{
  undefined8 uVar3;
  
  byte bVar4;
  
  char cVar5;
  byte bVar6;
  byte bVar7;

  // represents argv
  char* in_RSI;
  char* argv_1 = in_rsi[1];
  
  int uVar2 = return_argv_length();
  
  
  switch(uVar2 < 15) {
    case false:
        bVar4 = -argv_1[11];

        cVar5 = (bVar4 & 0x67) * '\x02' + (bVar4 ^ 0xe7);
        bVar4 = -cVar5 - 0x19;
        bVar6 = cVar5 + 0x18;
        
        switch( (byte)( (bVar4 & 0xd0) * '\x02' + (((bVar6 & bVar4 | bVar6) ^ bVar4) & 0xd0 ^ bVar4)) < 10 ) {
            case false:
                uVar3 = 0;
                break;
            case true:
                bVar6 = -*(byte *)(argv_1 + 0xc);
                bVar4 = bVar6 ^ 0x30;

                switch((byte)-((~bVar4 & bVar6) * '\x02' + bVar4) < 10) {
                    case false:
                        uVar3 = 0;
                        break;
                    
                    case true:
                        bVar4 = *(byte *)(argv_1 + 0xd) - 0x39;
                        bVar6 = ~bVar4;
                        
                        switch((byte)(~(~(bVar4 ^ 0x2f) & ~(bVar6 ^ bVar4 ^ 0x2f) | bVar6) * '\x02' + (bVar4 & 0x2f | bVar6 & 0xd0) + 0x39) < 10) {
                            case false:
                                uVar3 = 0;
                                break;
                            case true:
                                bVar4 = *(byte *)(argv_1 + 0xe);
                                bVar7 = ~bVar4;
                                bVar6 = ~(~(bVar4 & 0xd0 | bVar7 ^ 0x2f) | bVar7 & (bVar7 ^ 0x2f) | bVar4 & 0x2f) * '\x02';

                                bVar7 = (bVar7 & 0xd0 ^ bVar4 & 0x2f) + 0x5f;
          
                                switch((byte)((bVar7 & bVar6) * '\x02' + (bVar7 ^ bVar6) + 0xa1) < 10) {
                                    case false:
                                        uVar3 = 0;
                                        break;

                                    case true:
                                        uVar3 = CONCAT71(0xa6e3a29dbfb830,
                                                    *(short *)(((ulong)*(byte *)(argv_1 + 0xb) * 1000 + 0x2c8e2eb120231781 +
                                                    (ulong)*(byte *)(argv_1 + 0xc) * 100 +
                                                    (ulong)*(byte *)(argv_1 + 0xd) * 10 + (ulong)bVar4) * 2 +
                                                    -0x591c5d623fff17e2) == 0x3419);
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