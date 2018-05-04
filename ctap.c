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

void ctap_get_info(CborEncoder * encoder)
{
    int ret;
    CborEncoder array;
    CborEncoder map;

    const int number_of_map_items = 2;
    const int number_of_versions = 2;

    ret = cbor_encoder_create_map(encoder, &map, number_of_map_items);
    check_ret(ret);
    {

        ret = cbor_encode_uint(&map, 0x01);     //  versions key
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, number_of_versions);
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "1.0");
            check_ret(ret);
            ret = cbor_encode_text_stringz(&array, "2.0");
            check_ret(ret);
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, 0x03);     //  aaguid key
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&map, CTAP_AAGUID, 16);
            check_ret(ret);
        }

    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);


}

uint8_t ctap_handle_packet(uint8_t * pkt_raw, int length, CTAP_RESPONSE * resp)
{
    uint8_t cmd = *pkt_raw;
    pkt_raw++;


    uint8_t buf[100];
    memset(buf,0,sizeof(buf));

    resp->data = buf;
    resp->length = 0;

    CborEncoder encoder;
    cbor_encoder_init(&encoder, buf, sizeof(buf), 0);


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
            ctap_get_info(&encoder);
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
    return 0;
}
