#include <stdio.h>


char START = 48;


int main(int argc, char** argv)
{
    //unsigned long long x = 0xa6e3a29dbfb8305e + 2 * 0x2c8e2eb120240ee0 + 0x48b7c0;
    //printf("%llu\n", x);

    //return 0;
    
    
    for(char i = START; i < 127; ++i)
    {
        char ib = -i;

        char ic5 = 2 * (ib & 0x67) + (ib ^ 0xe7);
        ib = -ic5 - 0x19;
        char ic6 = ic5 + 0x18;

        if ( (char) ( 2 * (ib & 0xd0) + (( (ic6 & ib | ic6) ^ ib ) & 0xd0 ^ ib) ) >= 10 )
            continue;


        // Second nested
        for(char j = START; j < 127; ++j)
        {
            char jb = -j;
            char jb4 = jb ^ 0x30;

            if ( (char) -(2 * (~jb4 & jb) + jb4) >= 10 )
                continue;


            // Third nested
            for(char k = START; k < 127; ++k)
            {
                char kb = k - 0x39;
                char kc6 = ~kb;

                if ( (char)(~(~(kb ^ 0x2f) & ~(kc6 ^ kb ^ 0x2f) | kc6) * 2 + (kb & 0x2f | kc6 & 0xd0) + 0x39) >= 10 )
                    continue;

                // Fourth nested
                for(char l = START; l < 127; ++l)
                {
                    char lb = l;
                    char lb7 = ~lb;
                    char lb6 = ~(~(lb & 0xd0 | lb7 ^ 0x2f) | lb7 & (lb7 ^ 0x2f) | lb & 0x2f) * 2;

                    lb7 = (lb7 & 0xd0 ^ lb & 0x2f) + 0x5f;

                    if ( (char)((lb7 & lb6) * 2 + (lb7 ^ lb6) + 0xa1) >= 10 )
                        continue;

                    
                    
                    unsigned long tmp = (unsigned long long) i * 1000 + 
                                        (unsigned long long) j * 100 +
                                        (unsigned long long) k * 10 + 
                                        (unsigned long long) l;
                    
                    tmp -= 0xd371d14edfdce87f;
                    tmp *= 2;
                    tmp += 0xa6e3a29dbfb8305e + 0x48b7c0;

		     
                    if ( tmp == 0x48cae0 || tmp == 0x48ea27 )
                        // Final input found
			printf("1_kn0w_h0w_%c%c%c%c\n", i, j, k, l);
                }

            }
        }
    }

    return 0;
}
