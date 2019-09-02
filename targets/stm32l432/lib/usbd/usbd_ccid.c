#include <stdint.h>
#include "usbd_ccid.h"
#include "usbd_ctlreq.h"
#include "usbd_conf.h"
#include "usbd_core.h"

#include "log.h"

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

uint8_t  USBD_CCID_TransmitPacket(uint8_t * msg, int len)
{
    /* Update the packet total length */
    Solo_USBD_Device.ep_in[CCID_IN_EP & 0xFU].total_length = len;

    while (PCD_GET_EP_TX_STATUS(USB, CCID_IN_EP & 0x0f) == USB_EP_TX_VALID)
        ;
    /* Transmit next packet */
    USBD_LL_Transmit(&Solo_USBD_Device, CCID_IN_EP, msg,
                   len);

    printf1(TAG_CCID,"<< ");
    dump_hex1(TAG_CCID, msg, len);

    return USBD_OK;
}



void ccid_send_status(CCID_HEADER * c, uint8_t status)
{
    uint8_t msg[CCID_HEADER_SIZE];
    memset(msg,0,sizeof(msg));

    msg[0] = CCID_SLOT_STATUS_RES;
    msg[6] = c->seq;
    msg[7] = status;

    USBD_CCID_TransmitPacket(msg, sizeof(msg));

}

void ccid_send_data_block(CCID_HEADER * c, uint8_t status)
{
    uint8_t msg[CCID_HEADER_SIZE];
    memset(msg,0,sizeof(msg));

    msg[0] = CCID_DATA_BLOCK_RES;
    msg[6] = c->seq;
    msg[7] = status;

    USBD_CCID_TransmitPacket(msg, sizeof(msg));

}

void handle_ccid(uint8_t * msg, int len)
{
    CCID_HEADER * h = (CCID_HEADER *) msg;
    switch(h->type)
    {
        case CCID_SLOT_STATUS:
            ccid_send_status(h, CCID_STATUS_ON);
        break;
        case CCID_POWER_ON:
            ccid_send_data_block(h, CCID_STATUS_ON);
        break;
        case CCID_POWER_OFF:
            ccid_send_status(h, CCID_STATUS_OFF);
        break;
        default:
            ccid_send_status(h, CCID_STATUS_ON);
        break;
    }
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

    printf1(TAG_CCID, ">> ");
    dump_hex1(TAG_CCID, ccidmsg_buf, hcdc->RxLength);

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
