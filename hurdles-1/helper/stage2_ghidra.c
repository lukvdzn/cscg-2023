
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

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

                                    case true:
                                        uVar3 = CONCAT71(0xa6e3a29dbfb830,
                                                    
                                                    
                                                    *(short *) ( 2 * (0x2c8e2eb120231781 + 
                                                                  (ulong) argv_1[11] * 1000 + 
                                                                  (ulong) argv_1[12] * 100 +
                                                                  (ulong) argv_1[13] * 10 + 
                                                                  (ulong)argv_1[14]
                                                                  )  + 0x48b7c0) == 0x3419);
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