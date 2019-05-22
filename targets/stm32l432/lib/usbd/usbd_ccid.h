#ifndef _USBD_H_
#define _USBD_H_

#include "usbd_ioreq.h"

#define CCID_IN_EP                                   0x84U  /* EP1 for data IN */
#define CCID_OUT_EP                                  0x04U  /* EP1 for data OUT */
#define CCID_CMD_EP                                  0x85U  /* EP2 for CDC commands */

#define CCID_DATA_PACKET_SIZE                        64

#define CCID_SET_PARAMS                     0x61
#define CCID_POWER_ON                       0x62
#define CCID_POWER_OFF                      0x63
#define CCID_SLOT_STATUS                    0x65
#define CCID_SECURE                         0x69
#define CCID_GET_PARAMS                     0x6C
#define CCID_RESET_PARAMS                   0x6D
#define CCID_XFR_BLOCK                      0x6F
#define CCID_DATA_BLOCK_RES                 0x80
#define CCID_SLOT_STATUS_RES                0x81
#define CCID_PARAMS_RES                     0x82

extern USBD_ClassTypeDef  USBD_CCID;

typedef struct
{
  uint32_t data[CCID_DATA_PACKET_SIZE / 4U];
  uint8_t  CmdOpCode;
  uint8_t  CmdLength;
  uint8_t  *RxBuffer;
  uint8_t  *TxBuffer;
  uint32_t RxLength;
  uint32_t TxLength;

  __IO uint32_t TxState;
  __IO uint32_t RxState;
}
USBD_CCID_HandleTypeDef;

#endif
