#include <string.h>

#include "u2f.h"
#include "ssh_agent.h"
#include "crypto.h"
#include "ctap_errors.h"
#include "device.h"

void ssh_agent(int len, const uint8_t *ctap_buffer, CTAP_RESPONSE *ctap_resp) {
  const char ssh_agent_name[] = "solo-ssh-agent";

  uint8_t x[32], y[32], sign[64];
  memset(x,0,sizeof(x));
  memset(y,0,sizeof(y));
  memset(sign,0,sizeof(sign));

  if(len < 1) {
    ctap_resp->data[0] = CTAP2_ERR_MISSING_PARAMETER;
    ctap_resp->length = 1;
    return;
  }

  switch(ctap_buffer[0]) {
    case SSH_AGENT_LIST_PUBLIC_KEYS:
      crypto_ecc256_derive_public_key((const uint8_t *)ssh_agent_name, sizeof(ssh_agent_name), x, y);

      ctap_resp->data[0] = CTAP1_ERR_SUCCESS;
      ctap_resp->data[1] = U2F_EC_FMT_UNCOMPRESSED; // uECC library skips this flag
      memmove(ctap_resp->data + 2, x, 32);
      memmove(ctap_resp->data + 34, y, 32);
      ctap_resp->length = 66;

      return;
      break;

    case SSH_AGENT_SIGN_REQUEST:
      if(len > 32+1) {
        ctap_resp->data[0] = CTAP1_ERR_INVALID_LENGTH;
        ctap_resp->length = 1;
        return;
      }

      int ret = ctap_user_presence_test(5000);
      if (ret < 1) {
        ctap_resp->data[0] = CTAP2_ERR_ACTION_TIMEOUT;
        ctap_resp->length = 1;
        return;
      }

      crypto_ecc256_load_key((const uint8_t *)ssh_agent_name, sizeof(ssh_agent_name), NULL, 0);

      crypto_ecc256_sign(ctap_buffer+1, len-1, sign);

      ctap_resp->data[0] = CTAP1_ERR_SUCCESS;
      memmove(ctap_resp->data + 1, sign, 64);
      ctap_resp->length = 65;
      return;
      break;

    default:
      ctap_resp->data[0] = CTAP1_ERR_INVALID_PARAMETER;
      ctap_resp->length = 1;
      return;
      break;
  }

}
