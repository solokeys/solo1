// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef EXTENSIONS_H_
#define EXTENSIONS_H_
#include "u2f.h"
#include "apdu.h"

int16_t bridge_u2f_to_extensions(uint8_t * chal, uint8_t * appid, uint8_t klen, uint8_t * keyh);

// return 1 if request is a wallet request
int is_extension_request(uint8_t * req, int len);

int16_t extend_u2f(APDU_HEADER * req, uint8_t * payload, uint32_t len);

int16_t extend_fido2(CredentialId * credid, uint8_t * output);

int bootloader_bridge(int klen, uint8_t * keyh);

int is_extension_request(uint8_t * kh, int len);


void extension_writeback_init(uint8_t * buffer, uint8_t size);
void extension_writeback(uint8_t * buf, uint8_t size);

#endif /* EXTENSIONS_H_ */
