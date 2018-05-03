#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbor.h"

#include "ctap.h"
#include "util.h"



static void check_ret(CborError ret)
{
    if (ret != CborNoError)
    {
        printf("CborError: %d: %s\n", ret, cbor_error_string(ret));
        exit(1);
    }
}


void ctap_handle_packet(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    uint8_t cmd = *pkt_raw;
    int ret;
    pkt_raw++;


    uint8_t buf[100];
    memset(buf,0,sizeof(buf));

    resp->data = buf;
    resp->length = 0;

    CborEncoder encoder;
    CborEncoder array;

    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
            printf("CTAP_MAKE_CREDENTIAL\n");
            break;
        case CTAP_GET_ASSERTION:
            printf("CTAP_GET_ASSERTION\n");
            break;
        case CTAP_CANCEL:
            printf("CTAP_CANCEL\n");
            break;
        case CTAP_GET_INFO:
            printf("CTAP_GET_INFO\n");

            cbor_encoder_init(&encoder, buf, sizeof(buf), 0);

            ret = cbor_encoder_create_array(&encoder, &array, 2);
            check_ret(ret);

            ret = cbor_encode_text_stringz(&array, "1.0");
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "2.0");
            check_ret(ret);

            ret = cbor_encoder_close_container(&encoder, &array);
            check_ret(ret);

            dump_hex(buf, cbor_encoder_get_buffer_size(&encoder, buf));

            resp->length = cbor_encoder_get_buffer_size(&encoder, buf);

            break;
        case CTAP_CLIENT_PIN:
            printf("CTAP_CLIENT_PIN\n");
            break;
        case CTAP_RESET:
            printf("CTAP_RESET\n");
            break;
        case GET_NEXT_ASSERTION:
            printf("CTAP_NEXT_ASSERTION\n");
            break;
        default:
            printf("error, invalid cmd\n");
    }

    printf("cbor structure: %d bytes\n", length - 1);
}
