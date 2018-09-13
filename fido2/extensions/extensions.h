
#ifndef EXTENSIONS_H_
#define EXTENSIONS_H_
#include "u2f.h"

int16_t extend_u2f(struct u2f_request_apdu* req, uint32_t len);

#endif /* EXTENSIONS_H_ */
