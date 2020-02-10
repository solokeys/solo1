#ifndef _SSH_AGENT_H
#define _SSH_AGENT_H

#include "ctap.h"

#define SSH_AGENT_LIST_PUBLIC_KEYS 11
#define SSH_AGENT_SIGN_REQUEST     13

void ssh_agent(int len, const uint8_t *ctap_buffer, CTAP_RESPONSE *ctap_resp);

#endif
