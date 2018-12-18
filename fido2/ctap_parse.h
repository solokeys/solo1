/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 * 
 * This file is part of Solo.
 * 
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 * 
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
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
