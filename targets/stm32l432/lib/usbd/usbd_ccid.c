#include <stdint.h>
#include <stdbool.h>
#include "usbd_ccid.h"
#include "usbd_ctlreq.h"
#include "usbd_conf.h"
#include "usbd_core.h"

#include "log.h"

#ifdef ENABLE_CCID
#include "openpgplib.h"
#endif

static uint8_t  USBD_CCID_Init (USBD_HandleTypeDef *pdev,
                               uint8_t cfgidx);

static uint8_t  USBD_CCID_DeInit (USBD_HandleTypeDef *pdev,
                                 uint8_t cfgidx);

static uint8_t  USBD_CCID_Setup (USBD_HandleTypeDef *pdev,
                                USBD_SetupReqTypedef *req);

static uint8_t  USBD_CCID_DataIn (USBD_HandleTypeDef *pdev,
                                 uint8_t epnum);

static uint8_t  USBD_CCID_DataOut (USBD_HandleTypeDef *pdev,
                                 uint8_t epnum);

static uint8_t  USBD_CCID_EP0_RxReady (USBD_HandleTypeDef *pdev);


static bool ICCStateChanged = true;
static bool ICCPowered = false;

static const uint8_t ATRResponse[] = {
    0x3B, 0xDA, 0x11, 0xFF, 0x81, 0xB1, 0xFE, 0x55, 
    0x1F, 0x03, 0x00, 0x31, 0x84, 0x73, 0x80, 0x01, 
    0x80, 0x00, 0x90, 0x00, 0xE4 };
    
static const uint8_t ParamsT0Default[] = {
          // bmFindexDindex (B7-4 – FI – Index into the table 7 in ISO/IEC 7816-3:1997 selecting a clock rate conversion factor
          //                 B3-0 – DI - Index into the table 8 in ISO/IEC 7816-3:1997 selecting a baud rate conversion factor )
    0x11, // from TA1 ATR: Fi=372, Di=1, 372 cycles/ETU (10752 bits/s at 4.00 MHz, 13440 bits/s for fMax=5 MHz)
    0x10, // bmTCCKST0 (Checksum: LRC, Convention: direct, ignored by CCID)
    0x00, // bGuardTimeT0
    0x00, // bWaitingIntegerT0
    0x00, // bClockStop. 00h = Stopping the Clock is not allowed
    };

static const uint8_t ParamsT1Default[] = {
    0x11, // Fi=372, Di=1
    0x10, // Checksum: LRC, Convention: direct, ignored by CCID
    0x00, // No extra guard time
    0x15, // BWI = 1, CWI = 5
    0x00, // Stopping the Clock is not allowed
    0xFE, // IFSC = 0xFE
    0x00  // NAD
    };
  
USBD_ClassTypeDef  USBD_CCID =
{
  USBD_CCID_Init,
  USBD_CCID_DeInit,
  USBD_CCID_Setup,
  NULL,                 /* EP0_TxSent, */
  USBD_CCID_EP0_RxReady,
  USBD_CCID_DataIn,
  USBD_CCID_DataOut,
  NULL,
  NULL,
  NULL,

  NULL,
  NULL,
  NULL,
  NULL,
};

static uint8_t ccidmsg_buf[CCID_DATA_PACKET_SIZE];

static uint8_t  USBD_CCID_Init (USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
    uint8_t ret = 0U;
    USBD_CCID_HandleTypeDef   *hcdc;

    //Y
    USBD_LL_OpenEP(pdev, CCID_IN_EP, USBD_EP_TYPE_BULK,
                   CCID_DATA_PACKET_SIZE);

    USBD_LL_OpenEP(pdev, CCID_OUT_EP, USBD_EP_TYPE_BULK,
                   CCID_DATA_PACKET_SIZE);

    pdev->ep_in[CCID_IN_EP & 0xFU].is_used = 1U;
    pdev->ep_out[CCID_OUT_EP & 0xFU].is_used = 1U;


    USBD_LL_OpenEP(pdev, CCID_CMD_EP, USBD_EP_TYPE_INTR, CCID_DATA_PACKET_SIZE);
    pdev->ep_in[CCID_CMD_EP & 0xFU].is_used = 1U;

    // dump_pma_header("ccid.c");

    static USBD_CCID_HandleTypeDef mem;
    pdev->pClassData = &mem;

    hcdc = (USBD_CCID_HandleTypeDef*) pdev->pClassData;

    // init transfer states
    hcdc->TxState = 0U;
    hcdc->RxState = 0U;

    USBD_LL_PrepareReceive(&Solo_USBD_Device, CCID_OUT_EP, ccidmsg_buf,
                         CCID_DATA_PACKET_SIZE);

    return ret;
}

static uint8_t  USBD_CCID_DeInit (USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  uint8_t ret = 0U;
  //N

  USBD_LL_CloseEP(pdev, CCID_IN_EP);
  pdev->ep_in[CCID_IN_EP & 0xFU].is_used = 0U;

  USBD_LL_CloseEP(pdev, CCID_OUT_EP);
  pdev->ep_out[CCID_OUT_EP & 0xFU].is_used = 0U;

  USBD_LL_CloseEP(pdev, CCID_CMD_EP);
  pdev->ep_in[CCID_CMD_EP & 0xFU].is_used = 0U;

  /* DeInit  physical Interface components */
  if(pdev->pClassData != NULL)
  {
    pdev->pClassData = NULL;
  }

  return ret;
}

/**
  * @brief  USBD_CDC_Setup
  *         Handle the CDC specific requests
  * @param  pdev: instance
  * @param  req: usb requests
  * @retval status
  */
static uint8_t  USBD_CCID_Setup (USBD_HandleTypeDef *pdev,
                                USBD_SetupReqTypedef *req)
{
  USBD_CCID_HandleTypeDef   *hcdc = (USBD_CCID_HandleTypeDef*) pdev->pClassData;
  uint8_t ifalt = 0U;
  uint16_t status_info = 0U;
  uint8_t ret = USBD_OK;
  //N

  switch (req->bmRequest & USB_REQ_TYPE_MASK)
  {
  case USB_REQ_TYPE_CLASS :
    if (req->wLength)
    {
      if (req->bmRequest & 0x80U)
      {
          USBD_CtlSendData (pdev, (uint8_t *)(void *)hcdc->data, req->wLength);
      }
      else
      {
        hcdc->CmdOpCode = req->bRequest;
        hcdc->CmdLength = (uint8_t)req->wLength;

        USBD_CtlPrepareRx (pdev, (uint8_t *)(void *)hcdc->data, req->wLength);
      }
    }
    else
    {

    }
    break;

  case USB_REQ_TYPE_STANDARD:
    switch (req->bRequest)
    {
    case USB_REQ_GET_STATUS:
      if (pdev->dev_state == USBD_STATE_CONFIGURED)
      {
        USBD_CtlSendData (pdev, (uint8_t *)(void *)&status_info, 2U);
      }
      else
      {
        USBD_CtlError (pdev, req);
			  ret = USBD_FAIL;
      }
      break;

    case USB_REQ_GET_INTERFACE:
      if (pdev->dev_state == USBD_STATE_CONFIGURED)
      {
        USBD_CtlSendData (pdev, &ifalt, 1U);
      }
      else
      {
        USBD_CtlError (pdev, req);
			  ret = USBD_FAIL;
      }
      break;

    case USB_REQ_SET_INTERFACE:
      if (pdev->dev_state != USBD_STATE_CONFIGURED)
      {
        USBD_CtlError (pdev, req);
			  ret = USBD_FAIL;
      }
      break;
    case USB_REQ_GET_DESCRIPTOR:
    break;
    default:
      USBD_CtlError (pdev, req);
      ret = USBD_FAIL;
      break;
    }
    break;

  default:
    USBD_CtlError (pdev, req);
    ret = USBD_FAIL;
    break;
  }

  return ret;
}


/**
  * @brief  USBD_CDC_DataIn
  *         Data sent on non-control IN endpoint
  * @param  pdev: device instance
  * @param  epnum: endpoint number
  * @retval status
  */
static uint8_t  USBD_CCID_DataOut (USBD_HandleTypeDef *pdev, uint8_t epnum)
{
  return USBD_OK;
}
static uint8_t  USBD_CCID_DataIn (USBD_HandleTypeDef *pdev, uint8_t epnum)
{
  USBD_CCID_HandleTypeDef *hcdc = (USBD_CCID_HandleTypeDef*)pdev->pClassData;

  hcdc->TxState = 0U;
  return USBD_OK;
}

uint8_t  USBD_CCID_TransmitPacket(uint8_t * msg, uint16_t len)
{
    /* Update the packet total length */
    Solo_USBD_Device.ep_in[CCID_IN_EP & 0xFU].total_length = len;

    while (PCD_GET_EP_TX_STATUS(USB, CCID_IN_EP & 0x0fU) == USB_EP_TX_VALID)
        ;
    /* Transmit next packet */
    USBD_LL_Transmit(&Solo_USBD_Device, CCID_IN_EP, msg, len);

    //printf1(TAG_CCID,"<< ");
    //dump_hex1(TAG_CCID, msg, len);

    return USBD_OK;
}

static CCID_bulkout_data_t pck;

void ccid_send_status(CCID_HEADER * c, uint8_t status, uint8_t error)
{
    memset((uint8_t *)&pck, 0, sizeof(pck));

    pck.bMessageType = CCID_SLOT_STATUS_RES;
    pck.bSlot = c->slot;
    pck.bSeq = c->seq;
    pck.bStatus = status;
    pck.bError = error;
    
    USBD_CCID_TransmitPacket((uint8_t *)&pck, CCID_HEADER_SIZE);
}

void ccid_send_data_block(CCID_HEADER * c, uint8_t *data, uint32_t len, uint8_t status, uint8_t error)
{
    memset((uint8_t *)&pck, 0, sizeof(pck));
    
    pck.bMessageType = CCID_DATA_BLOCK_RES;
    pck.dwLength = len;
    pck.bSlot = c->slot;
    pck.bSeq = c->seq;
    pck.bStatus = status;
    pck.bError = error;

    memcpy(pck.abData, data, len);
    
    if (error != CCID_SLOT_NO_ERROR) {
        pck.dwLength = 0;
    }

    USBD_CCID_TransmitPacket((uint8_t *)&pck, CCID_HEADER_SIZE + pck.dwLength);
}

// abData and dwLength comes from old data
void ccid_send_data_block_noclear(CCID_HEADER * c, uint8_t status, uint8_t error)
{
    pck.bMessageType = CCID_DATA_BLOCK_RES;
    pck.bSlot = c->slot;
    pck.bSeq = c->seq;
    pck.bStatus = status;
    pck.bError = error;
    pck.bSpecific = 0;

    if (error != CCID_SLOT_NO_ERROR) {
        pck.dwLength = 0;
    }

    USBD_CCID_TransmitPacket((uint8_t *)&pck, CCID_HEADER_SIZE + pck.dwLength);
}

void ccid_send_parameters(CCID_HEADER * c, uint8_t status, uint8_t error)
{
    memset((uint8_t *)&pck, 0, sizeof(pck));

    pck.bMessageType = CCID_PARAMS_RES;
    pck.dwLength = 0;
    pck.bSlot = c->slot;
    pck.bSeq = c->seq;
    pck.bStatus = status;
    pck.bError = error;
    
    /*
    bSpecific - Specifies what protocol data structure follows.
    00h = Structure for protocol T=0
    01h = Structure for protocol T=1
    The following values are reserved for future use.
    80h = Structure for 2-wire protocol
    81h = Structure for 3-wire protocol
    82h = Structure for I2C protocol  
    */
    pck.bSpecific = 1;
    (void)ParamsT0Default; // suppress not using warning
    if (error == CCID_SLOT_NO_ERROR) {
        pck.dwLength = sizeof(ParamsT1Default);
        memcpy(pck.abData, ParamsT1Default, sizeof(ParamsT1Default));
    }
    
    USBD_CCID_TransmitPacket((uint8_t *)&pck, CCID_HEADER_SIZE + pck.dwLength);
}

void handle_ccid(uint8_t * msg, int len)
{
    CCID_HEADER * h = (CCID_HEADER *) msg;
    uint32_t rlength = 0;
    switch(h->type)
    {
        case CCID_SLOT_STATUS:
            //ccid_send_status(h, BM_COMMAND_STATUS_NO_ERROR | (ICCPowered ? BM_ICC_PRESENT_ACTIVE : BM_ICC_NO_ICC_PRESENT), CCID_SLOT_NO_ERROR);
            ccid_send_status(h, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, 0);
        break;
        case CCID_POWER_ON:
            if (h->rsvd >= VOLTS_1_8) {
                /* The Voltage specified is out of Spec */
                ccid_send_status(h, BM_COMMAND_STATUS_FAILED | BM_ICC_PRESENT_ACTIVE, CCID_SLOTERROR_BAD_POWERSELECT);
                return; 
            }
            
            ccid_send_data_block(h, (uint8_t *)ATRResponse, sizeof(ATRResponse), BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, CCID_SLOT_NO_ERROR);
            ICCPowered = true;
            ICCStateChanged = true;
        break;
        case CCID_POWER_OFF:
            ccid_send_status(h, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_NO_ICC_PRESENT, 0);
            ICCPowered = false;
            ICCStateChanged = true;
        break;
        case CCID_GET_PARAMS:
            ccid_send_parameters(h, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, CCID_SLOT_NO_ERROR);
        break;
        case CCID_RESET_PARAMS:
            ccid_send_parameters(h, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, CCID_SLOT_NO_ERROR);
        break;
        case CCID_SET_PARAMS:
            ccid_send_status(h, BM_COMMAND_STATUS_FAILED | BM_ICC_PRESENT_ACTIVE, CCID_SLOTERROR_CMD_NOT_SUPPORTED);
            //ccid_send_parameters(h, BM_COMMAND_STATUS_FAILED | BM_ICC_PRESENT_ACTIVE, 0); // bError field will contain the offset of the "offending" parameter
        break;
#ifdef ENABLE_CCID
        case CCID_XFR_BLOCK:
            OpenpgpExchange(&msg[CCID_HEADER_SIZE], h->len, pck.abData, &rlength);
            pck.dwLength = rlength;

            ccid_send_data_block_noclear(h, BM_COMMAND_STATUS_NO_ERROR | BM_ICC_PRESENT_ACTIVE, CCID_SLOT_NO_ERROR);
            
            if (DoReset) {
                while (PCD_GET_EP_TX_STATUS(USB, CCID_IN_EP & 0x0fU) == USB_EP_TX_VALID)
                    ;
                USBD_LL_Delay(100U);
                NVIC_SystemReset();
            }
        break;
#endif
        default:
            ccid_send_status(h, BM_COMMAND_STATUS_FAILED | BM_ICC_PRESENT_ACTIVE, CCID_SLOTERROR_CMD_NOT_SUPPORTED);
        break;
    }
}

uint8_t usb_ccid_int_tx_callback(USBD_HandleTypeDef *pdev, uint8_t epnum) {
    uint8_t state = (ICCPowered ? CCID_ICC_PRESENT : CCID_ICC_NOT_PRESENT) | (ICCStateChanged ? CCID_ICC_CHANGE : 0x00);
    uint8_t data[] = {CCID_RDR_TO_PC_NOTIFYSLOTCHANGE, state}; 
    ICCStateChanged = false;
    
    Solo_USBD_Device.ep_in[CCID_CMD_EP & 0xFU].total_length = sizeof(data);

    while (PCD_GET_EP_TX_STATUS(USB, CCID_CMD_EP & 0x0f) == USB_EP_TX_VALID)
        ;
    USBD_LL_Transmit(&Solo_USBD_Device, CCID_CMD_EP, data, sizeof(data));
    
    return USBD_OK;
}

/**
  * @brief  USBD_CDC_DataOut
  *         Data received on non-control Out endpoint
  * @param  pdev: device instance
  * @param  epnum: endpoint number
  * @retval status
  */
uint8_t usb_ccid_recieve_callback(USBD_HandleTypeDef *pdev, uint8_t epnum)
{
    USBD_CCID_HandleTypeDef *hcdc = (USBD_CCID_HandleTypeDef*) pdev->pClassData;

    /* Get the received data length */
    hcdc->RxLength = USBD_LL_GetRxDataSize (pdev, epnum);

    //printf1(TAG_CCID, ">> ");
    //dump_hex1(TAG_CCID, ccidmsg_buf, hcdc->RxLength);

    handle_ccid(ccidmsg_buf, hcdc->RxLength);

    USBD_LL_PrepareReceive(&Solo_USBD_Device, CCID_OUT_EP, ccidmsg_buf,
                           CCID_DATA_PACKET_SIZE);

    return USBD_OK;
}

/**
  * @brief  USBD_CDC_EP0_RxReady
  *         Handle EP0 Rx Ready event
  * @param  pdev: device instance
  * @retval status
  */
static uint8_t  USBD_CCID_EP0_RxReady (USBD_HandleTypeDef *pdev)
{
    return USBD_OK;
}
