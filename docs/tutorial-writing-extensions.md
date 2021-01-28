# Tutorial: Writing an extension for the solo stick
A short overview about, where and how you should implement your extension into the solo stick code base. In this tutorial we will add a small extension, that will engage in a "ping"-"pong" exchange.

## Make it visible
We need to make it visible, that the key now supports a new extension.
This is done in the function _ctap_get_info_ in [ctap.c](https://github.com/solokeys/solo/blob/master/fido2/ctap.c). This function creates a map with all the information about the solo key. You should therefore add your extension identifier here, too.
```c
uint8_t ctap_get_info(CborEncoder * encoder){
//[...]
    ret = cbor_encode_uint(&map, RESP_extensions);
    check_ret(ret);
    {
        ret = cbor_encoder_create_array(&map, &array, 3);
        check_ret(ret);
        {
            ret = cbor_encode_text_stringz(&array, "hmac-secret");
            check_ret(ret);

            ret = cbor_encode_text_stringz(&array, "credProtect");
            check_ret(ret);

            //Add it here
        }
        ret = cbor_encoder_close_container(&map, &array);
        check_ret(ret);
    }
//[...]
}
```
After you have added your identifier it should look similiar to this:
```c
uint8_t ctap_get_info(CborEncoder * encoder){
//[...]
    ret = cbor_encode_uint(&map, RESP_extensions);
    check_ret(ret);
    {
        ret = cbor_encoder_create_array(&map, &array, 3); //This number should reflect the number of supported extensions
        check_ret(ret);
        {
            ret = cbor_encode_text_stringz(&array, "hmac-secret");
            check_ret(ret);

            ret = cbor_encode_text_stringz(&array, "credProtect");
            check_ret(ret);

            //Add it here
            ret = cbor_encode_text_stringz(&array, "ping-pong");
            check_ret(ret);
        }
        ret = cbor_encoder_close_container(&map, &array);
        check_ret(ret);
    }
//[...]
}

```
Important: make sure to change the size of the created array to the correct number of elements.

## Let's get our extension parsed
As with all incoming messages, the extension has to be parsed and depending on the incoming message the reply has to be constructed. For this the function _ctap_parse_extensions_ in [ctap_parse.c](https://github.com/solokeys/solo/blob/master/fido2/ctap_parse.c) is used.
In this function the extension identifier is checked. So, if we want to add our ping-pong extension, we need to compare the incoming identifier to our identifier "ping-pong".
```c
uint8_t ctap_parse_extensions(CborValue * val, CTAP_extensions * ext){
//[...]

                if (strncmp(key, "hmac-secret",11) == 0){
                    //[...]
                }else if (strncmp(key, "credProtect",11) == 0) {
                    //[...]
                else if (strncmp(key, "ping-pong",9) == 0) {
                    //Logic should be placed here
                }
//[...]
}
```
What happens then, depends on your extension. You should make sure, to check incoming values for correctness, though. As hmac-secret and credProtect are already implemented, you could have a look at their implementations for a kind of guideline.
At this stage we can use the extension struct, which can be found in [ctap.h](https://github.com/solokeys/solo/blob/master/fido2/ctap.h). 
```c
typedef struct
{
    uint8_t hmac_secret_present;
    CTAP_hmac_secret hmac_secret;

    uint32_t cred_protect;
} CTAP_extensions;
```
This struct already contains important values for the other extensions, so we are going to add two for our extension. The first "ping_pong_present" should indicate if the key received a message with a ping-pong extension. The response should then contain the correct response.
```c
typedef struct
{
    uint8_t hmac_secret_present;
    CTAP_hmac_secret hmac_secret;

    uint32_t cred_protect;

    uint8_t ping_pong_present;
    char  ping_pong_response[4];
} CTAP_extensions;
```
Now we have to parse our message accordingly.
```c
uint8_t ctap_parse_extensions(CborValue * val, CTAP_extensions * ext){
//[...]

                if (strncmp(key, "hmac-secret",11) == 0){
                    //[...]
                }else if (strncmp(key, "credProtect",11) == 0) {
                    //[...]
                else if (strncmp(key, "ping-pong",9) == 0) {
                    if (cbor_value_get_type(&map) == CborTextStringType)
                    {   
                        //Cop incoming message
                        uint8_t txt[5];
                        sz = sizeof(txt);
                        ret = cbor_value_copy_text_string(&map, (char *)txt, &sz, NULL);
                        check_ret(ret);

                        if(strcmp((const char*)txt, "ping") == 0) {
                                ext->ping_pong_present = 0x01;
                                strcpy((char *)ext->ping_pong_response, "pong");
                        }else if(strcmp((const char*)txt, "pong") == 0) {
                                ext->ping_pong_present = 0x01;
                                strcpy((char *)ext->ping_pong_response, "ping");
                        }else{
                            printf2(TAG_ERR, "Wrong parameter requested. Got %s.\r\n", txt);
                            return CTAP2_ERR_INVALID_OPTION;
                        }
                    }else{
                        printf1(TAG_RED, "warning: ping-pong request ignored for being wrong type\r\n");
                    }
                }
//[...]
}
```
Here we are doing the following:
1. Check if we got a message with either "ping" or "pong" 
2. Set the correct value, to note, that we received a message using the ping-pong extension
3. Set the correct response ("pong" for "ping" and vice versa)


## Create a reply
Now, that we have parsed the correct message, we have to construct the correct reply. That is done in the function _ctap_make_extensions_ in [ctap.c](https://github.com/solokeys/solo/blob/master/fido2/ctap.c). We will use the before filled _CTAP_extensions_ in here.
We have to do two things here: 
1. Check, if a message using the ping-pong extension
2. Set the correct response according to our parsed incoming message
```c
static int ctap_make_extensions(CTAP_extensions * ext, uint8_t * ext_encoder_buf, unsigned int * ext_encoder_buf_size){
    //[...]
   
    if (ext->hmac_secret_present == EXT_HMAC_SECRET_PARSED)
    {
        //[...]
    }
    else if (ext->hmac_secret_present == EXT_HMAC_SECRET_REQUESTED)
    {
        //[...]
    }
    if (ext->cred_protect != EXT_CRED_PROTECT_INVALID) {
        //[...]
    }

    if(ext->ping_pong_present){
        extensions_used += 1;
        ping_pong_is_valid = 1;
    }

    if (extensions_used > 0)
    {
        //[...]
            if (hmac_secret_output_is_valid) {
                {
                    //[...]
                }
            }
            if (hmac_secret_requested_is_valid) {
                {   
                    //[...]
                }
            }
            if (cred_protect_is_valid) {
                {   
                    //[...]
                }
            }
             if (ping_pong_is_valid) {
                {   
                    ret = cbor_encode_text_stringz(&extension_output_map, "ping-pong");
                    check_ret(ret);

                    //Set the response message
                    ret = cbor_encode_text_stringz(&extension_output_map, (const char*)ext->ping_pong_response);
                    check_ret(ret);
                }
            }
        //[...]
    }
    //[...]
}
```

## Recap
To create a new extension, you would have to take the following three steps:
- Make sure, that the new extension will be made visible through a call of get_info
- Parse incoming messages correctly
- Construct the correct reply