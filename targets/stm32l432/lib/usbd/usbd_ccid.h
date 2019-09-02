#ifndef _USBD_H_
#define _USBD_H_

#include "usbd_ioreq.h"

#define CCID_HEADER_SIZE            10
typedef struct
{
    uint8_t type;
    uint32_t len;
    uint8_t slot;
    uint8_t seq;
    uint8_t rsvd;
    uint16_t param;
}  __attribute__((packed)) CCID_HEADER;

#define CCID_IN_EP                                   0x86U  /* EP1 for data IN */
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

#define CCID_STATUS_ON                      0x00
#define CCID_STATUS_OFF                     0x02

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

uint8_t usb_ccid_recieve_callback(USBD_HandleTypeDef *pdev, uint8_t epnum);

#endif
