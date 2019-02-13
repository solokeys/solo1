// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef EXTENSIONS_H_
#define EXTENSIONS_H_
#include "u2f.h"

int16_t extend_u2f(struct u2f_request_apdu* req, uint32_t len);

int bootloader_bridge(int klen, uint8_t * keyh);

#endif /* EXTENSIONS_H_ */
