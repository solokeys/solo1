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
#ifndef _CTAP_PARSE_H
#define _CTAP_PARSE_H


#define check_ret(r)    _check_ret(r,__LINE__, __FILE__);\
                        if ((r) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

#define check_retr(r)    _check_ret(r,__LINE__, __FILE__);\
                        if ((r) != CborNoError) return r;


extern void _check_ret(CborError ret, int line, const char * filename);


const char * cbor_value_get_type_string(const CborValue *value);


uint8_t parse_user(CTAP_makeCredential * MC, CborValue * val);
uint8_t parse_pub_key_cred_param(CborValue * val, uint8_t * cred_type, int32_t * alg_type);
uint8_t parse_pub_key_cred_params(CTAP_makeCredential * MC, CborValue * val);
uint8_t parse_fixed_byte_string(CborValue * map, uint8_t * dst, int len);
uint8_t parse_rp_id(struct rpId * rp, CborValue * val);
uint8_t parse_rp(struct rpId * rp, CborValue * val);
uint8_t parse_options(CborValue * val, uint8_t * rk, uint8_t * uv, uint8_t * up);

uint8_t parse_allow_list(CTAP_getAssertion * GA, CborValue * it);
uint8_t parse_cose_key(CborValue * it, uint8_t * x, uint8_t * y, int * kty, int * crv);


uint8_t ctap_parse_make_credential(CTAP_makeCredential * MC, CborEncoder * encoder, uint8_t * request, int length);
uint8_t ctap_parse_get_assertion(CTAP_getAssertion * GA, uint8_t * request, int length);
uint8_t ctap_parse_client_pin(CTAP_clientPin * CP, uint8_t * request, int length);
uint8_t parse_credential_descriptor(CborValue * arr, CTAP_credentialDescriptor * cred);


#endif
