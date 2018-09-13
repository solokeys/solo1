/*
   Copyright 2018 Conor Patrick

   Permission is hereby granted, free of charge, to any person obtaining a copy of
   this software and associated documentation files (the "Software"), to deal in
   the Software without restriction, including without limitation the rights to
   use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
   of the Software, and to permit persons to whom the Software is furnished to do
   so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/
#include <stdint.h>
#include "extensions.h"
#include "u2f.h"
#include "wallet.h"

#include "log.h"

int16_t extend_u2f(struct u2f_request_apdu* req, uint32_t len)
{

    struct u2f_authenticate_request * auth = (struct u2f_authenticate_request *) req->payload;
    uint16_t rcode;

    if (req->ins == U2F_AUTHENTICATE)
    {
        if (req->p1 == U2F_AUTHENTICATE_CHECK)
        {

            if (is_wallet_device((uint8_t *) &auth->kh, auth->khl))     // Pin requests
            {
                rcode =  U2F_SW_CONDITIONS_NOT_SATISFIED;
            }
            else
            {
                rcode =  U2F_SW_WRONG_DATA;
            }
            printf1(TAG_WALLET,"Ignoring U2F request\n");
            goto end;
        }
        else
        {
            if ( ! is_wallet_device((uint8_t *) &auth->kh, auth->khl))     // Pin requests
            {
                rcode = U2F_SW_WRONG_PAYLOAD;
                printf1(TAG_WALLET,"Ignoring U2F request\n");
                goto end;
            }
            rcode = bridge_u2f_to_wallet(auth->chal, auth->app, auth->khl, (uint8_t*)&auth->kh);
        }
    }
    else if (req->ins == U2F_VERSION)
    {
        printf1(TAG_U2F, "U2F_VERSION\n");
        if (len)
        {
            rcode = U2F_SW_WRONG_LENGTH;
        }
        else
        {
            rcode = u2f_version();
        }
    }
    else
    {
        rcode = U2F_SW_INS_NOT_SUPPORTED;
    }
end:
    return rcode;
}
