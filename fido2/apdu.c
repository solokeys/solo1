// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// iso7816:2013. 5.3.2 Decoding conventions for command bodies

#include "apdu.h"

uint16_t apdu_decode(uint8_t *data, size_t len, APDU_STRUCT *apdu) 
{
    EXT_APDU_HEADER *hapdu = (EXT_APDU_HEADER *)data;
    
    apdu->cla = hapdu->cla & 0xef; // mask chaining bit if any
    apdu->ins = hapdu->ins;
    apdu->p1 = hapdu->p1;
    apdu->p2 = hapdu->p2;
    
    apdu->lc = 0;
    apdu->data = NULL;
    apdu->le = 0;
    apdu->extended_apdu = false;
    apdu->case_type = 0x00;
    
    uint8_t b0 = hapdu->lc[0];
    
    // case 1
    if (len == 4)
    {
        apdu->case_type = 0x01;
    }
    
     // case 2S (Le)
    if (len == 5)
    {
        apdu->case_type = 0x02;
        apdu->le = b0;
        if (!apdu->le)
            apdu->le = 0x100;
    }
   
    // case 3S (Lc + data)
    if (len == 5U + b0 && b0 != 0)
    {
        apdu->case_type = 0x03;
        apdu->lc = b0;
    }
    
    // case 4S (Lc + data + Le)
    if (len == 5U + b0 + 1U && b0 != 0)
    {
        apdu->case_type = 0x04;
        apdu->lc = b0;
        apdu->le = data[len - 1];
        if (!apdu->le)
            apdu->le = 0x100;
    }
    
    // extended length apdu
    if (len >= 7 && b0 == 0)
    {
        uint16_t extlen = (hapdu->lc[1] << 8) + hapdu->lc[2];

        if (len - 7 < extlen)
        {
            return SW_WRONG_LENGTH;
        }
        
         // case 2E (Le) - extended
        if (len == 7)
        {
            apdu->case_type = 0x12;
            apdu->extended_apdu = true;
            apdu->le = extlen;
            if (!apdu->le)
                apdu->le = 0x10000;
        }
        
       // case 3E (Lc + data) - extended
       if (len == 7U + extlen)
        {
            apdu->case_type = 0x13;
            apdu->extended_apdu = true;
            apdu->lc = extlen;
        }

       // case 4E (Lc + data + Le) - extended 2-byte Le
       if (len == 7U + extlen + 2U)
        {
            apdu->case_type = 0x14;
            apdu->extended_apdu = true;
            apdu->lc = extlen;
            apdu->le = (data[len - 2] << 8) + data[len - 1];
        if (!apdu->le)
            apdu->le = 0x10000;
        }

       // case 4E (Lc + data + Le) - extended 3-byte Le
       if (len == 7U + extlen + 3U && data[len - 3] == 0)
        {
            apdu->case_type = 0x24;
            apdu->extended_apdu = true;
            apdu->lc = extlen;
            apdu->le = (data[len - 2] << 8) + data[len - 1];
        if (!apdu->le)
            apdu->le = 0x10000;
        }
    }
    else
    {
        if ((len > 5) && (len - 5 < hapdu->lc[0]))
        {
            return SW_WRONG_LENGTH;
        }
    }
    
    if (!apdu->case_type)
    {
        return SW_COND_USE_NOT_SATISFIED;
    }
    
    if (apdu->lc)
    {
        if (apdu->extended_apdu)
        {
            apdu->data = data + 7;
        } else {
            apdu->data = data + 5;
        }
        
    }   
    
    return 0;
}
