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

#define ABDATA_SIZE 261

typedef struct { 
    uint8_t bMessageType; /* Offset = 0*/
    uint32_t dwLength;    /* Offset = 1, The length field (dwLength) is the length  
                            of the message not including the 10-byte header.*/
    uint8_t bSlot;        /* Offset = 5*/
    uint8_t bSeq;         /* Offset = 6*/
    uint8_t bSpecific_0;  /* Offset = 7*/
    uint8_t bSpecific_1;  /* Offset = 8*/
    uint8_t bSpecific_2;  /* Offset = 9*/
    uint8_t abData [ABDATA_SIZE]; /* Offset = 10, For reference, the absolute 
                            maximum block size for a TPDU T=0 block is 260 bytes 
                            (5 bytes command; 255 bytes data), 
                            or for a TPDU T=1 block is 259 bytes, 
                            or for a short APDU T=1 block is 261 bytes, 
                            or for an extended APDU T=1 block is 65544 bytes.*/
} __attribute__((packed, aligned(1))) CCID_bulkin_data_t; 

typedef struct { 
    uint8_t bMessageType;   /* Offset = 0*/
    uint32_t dwLength;      /* Offset = 1*/
    uint8_t bSlot;          /* Offset = 5, Same as Bulk-OUT message */
    uint8_t bSeq;           /* Offset = 6, Same as Bulk-OUT message */
    uint8_t bStatus;        /* Offset = 7, Slot status as defined in ?? 6.2.6*/
    uint8_t bError;         /* Offset = 8, Slot error  as defined in ?? 6.2.6*/
    uint8_t bSpecific;      /* Offset = 9*/
    uint8_t abData[ABDATA_SIZE]; /* Offset = 10*/
    uint16_t u16SizeToSend; 
} __attribute__((packed, aligned(1))) CCID_bulkout_data_t;

#define CCID_IN_EP                          0x86U  /* EP1 for data IN */
#define CCID_OUT_EP                         0x04U  /* EP1 for data OUT */
#define CCID_CMD_EP                         0x85U  /* EP2 for CDC commands */

#define CCID_DATA_PACKET_SIZE               64

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

/* 6.3 Interrupt-IN Messages */
#define CCID_RDR_TO_PC_NOTIFYSLOTCHANGE     0x50
#define CCID_RDR_TO_PC_HARDWAREERROR        0x51

/* 6.3.1 RDR_to_PC_NotifySlotChange */
#define CCID_ICC_NOT_PRESENT                0x00
#define CCID_ICC_PRESENT                    0x01
#define CCID_ICC_CHANGE                     0x02
#define CCID_ICC_INSERTED_EVENT             (ICC_PRESENT+ICC_CHANGE)

/* Command status for USB Bulk In Messages : bmCommandStatus */
#define BM_ICC_PRESENT_ACTIVE               0x00
#define BM_ICC_PRESENT_INACTIVE             0x01
#define BM_ICC_NO_ICC_PRESENT               0x02

#define BM_COMMAND_STATUS_OFFSET            0x06
#define BM_COMMAND_STATUS_NO_ERROR          (0x00 << BM_COMMAND_STATUS_OFFSET)
#define BM_COMMAND_STATUS_FAILED            (0x01 << BM_COMMAND_STATUS_OFFSET)
#define BM_COMMAND_STATUS_TIME_EXTN         (0x02 << BM_COMMAND_STATUS_OFFSET)

/* ERROR CODES for USB Bulk In Messages : bError */
#define CCID_SLOT_NO_ERROR                  0x81
#define CCID_SLOTERROR_UNKNOWN              0x82

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
