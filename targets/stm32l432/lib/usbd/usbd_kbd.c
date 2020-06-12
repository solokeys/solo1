/**
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; Copyright (c) 2017 STMicroelectronics International N.V.
  * All rights reserved.</center></h2>
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted, provided that the following conditions are met:
  *
  * 1. Redistribution of source code must retain the above copyright notice,
  *    this list of conditions and the following disclaimer.
  * 2. Redistributions in binary form must reproduce the above copyright notice,
  *    this list of conditions and the following disclaimer in the documentation
  *    and/or other materials provided with the distribution.
  * 3. Neither the name of STMicroelectronics nor the names of other
  *    contributors to this software may be used to endorse or promote products
  *    derived from this software without specific written permission.
  * 4. This software, including modifications and/or derivative works of this
  *    software, must execute solely and exclusively on microcontroller or
  *    microprocessor devices manufactured by or for STMicroelectronics.
  * 5. Redistribution and use of this software other than as permitted under
  *    this license is void and will automatically terminate your rights under
  *    this license.
  *
  * THIS SOFTWARE IS PROVIDED BY STMICROELECTRONICS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS, IMPLIED OR STATUTORY WARRANTIES, INCLUDING, BUT NOT
  * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
  * PARTICULAR PURPOSE AND NON-INFRINGEMENT OF THIRD PARTY INTELLECTUAL PROPERTY
  * RIGHTS ARE DISCLAIMED TO THE FULLEST EXTENT PERMITTED BY LAW. IN NO EVENT
  * SHALL STMICROELECTRONICS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
  * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
  * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
  * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  ******************************************************************************
  */

  /* BSPDependencies
  - "stm32xxxxx_{eval}{discovery}{nucleo_144}.c"
  - "stm32xxxxx_{eval}{discovery}_io.c"
  EndBSPDependencies */

/* Includes ------------------------------------------------------------------*/
#include "usbd_hid.h"
#include "usbd_ctlreq.h"
#include "usbd_conf.h"
#include "usbd_core.h"

#include "log.h"

static uint8_t  USBD_KBD_Init (USBD_HandleTypeDef *pdev,
                               uint8_t cfgidx);

static uint8_t  USBD_KBD_DeInit (USBD_HandleTypeDef *pdev,
                                 uint8_t cfgidx);

static uint8_t  USBD_KBD_Setup (USBD_HandleTypeDef *pdev,
                                USBD_SetupReqTypedef *req);

static uint8_t  USBD_KBD_DataIn (USBD_HandleTypeDef *pdev, uint8_t epnum);

static uint8_t key_map[][3] =
{
    {'0', 0, 0x27},
    {'-', 0, 0x2d},
    {'=', 0, 0x2e},
    {'[', 0, 0x2f},
    {']', 0, 0x30},
    {'\\', 0, 0x31},
    {';', 0, 0x33},
    {'\'', 0, 0x34},
    {'`', 0, 0x35},
    {',', 0, 0x36},
    {'.', 0, 0x37},
    {'/', 0, 0x38},
    {' ', 0, 0x2c},
    {'\n', 0, 0x28},

    {'~', 2, 0x35},
    {'!', 2, 0x1e},
    {'@', 2, 0x1f},
    {'#', 2, 0x20},
    {'$', 2, 0x21},
    {'%', 2, 0x22},
    {'^', 2, 0x23},
    {'&', 2, 0x24},
    {'*', 2, 0x25},
    {'(', 2, 0x26},
    {')', 2, 0x27},
    {'_', 2, 0x2d},
    {'+', 2, 0x2e},
    {'{', 2, 0x2f},
    {'}', 2, 0x30},
    {':', 2, 0x33},
    {'"', 2, 0x34},
    {'|', 2, 0x31},
    {'<', 2, 0x36},
    {'>', 2, 0x37},
    {'?', 2, 0x38},
    {0, 0, 0},
};

USBD_ClassTypeDef  USBD_KBD =
{
  USBD_KBD_Init,
  USBD_KBD_DeInit,
  USBD_KBD_Setup,
  NULL, /*EP0_TxSent*/
  NULL, /*EP0_RxReady*/
  USBD_KBD_DataIn, /*DataIn*/
  NULL, /*DataOut*/
  NULL, /*SOF */
  NULL,
  NULL,


  NULL,
  NULL,
  NULL,
  NULL,
};

/* USB HID device Configuration Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_Desc[USB_HID_DESC_SIZ]  __ALIGN_END  =
{
  /* 18 */
  0x09,         /*bLength: HID Descriptor size*/
  HID_DESCRIPTOR_TYPE, /*bDescriptorType: HID*/
  0x11,         /*bcdHID: HID Class Spec release number*/
  0x01,
  0x00,         /*bCountryCode: Hardware target country*/
  0x01,         /*bNumDescriptors: Number of HID class descriptors to follow*/
  0x22,         /*bDescriptorType*/
  HID_KBD_REPORT_DESC_SIZE,/*wItemLength: Total length of Report descriptor*/
  0x00,
};

__ALIGN_BEGIN static uint8_t HID_KBD_ReportDesc[HID_KBD_REPORT_DESC_SIZE]  __ALIGN_END =
{
              0x05, 0x01,     /* USAGE_PAGE (Generic Desktop)           */
              0x09, 0x06,     /* USAGE (Keyboard)                       */
              0xa1, 0x01,     /* COLLECTION (Application)               */
              0x05, 0x07,     /*   USAGE_PAGE (Keyboard)                */
              0x19, 0xe0,     /*   USAGE_MINIMUM (Keyboard LeftControl) */
              0x29, 0xe7,     /*   USAGE_MAXIMUM (Keyboard Right GUI)   */
              0x15, 0x00,     /*   LOGICAL_MINIMUM (0)                  */
              0x25, 0x01,     /*   LOGICAL_MAXIMUM (1)                  */
              0x75, 0x01,     /*   REPORT_SIZE (1)                      */
              0x95, 0x08,     /*   REPORT_COUNT (8)                     */
              0x81, 0x02,     /*   INPUT (Data,Var,Abs)                 */
              0x95, 0x01,     /*   REPORT_COUNT (1)                     */
              0x75, 0x08,     /*   REPORT_SIZE (8)                      */
              0x81, 0x03,     /*   INPUT (Cnst,Var,Abs)                 */
              0x95, 0x05,     /*   REPORT_COUNT (5)                     */
              0x75, 0x01,     /*   REPORT_SIZE (1)                      */
              0x05, 0x08,     /*   USAGE_PAGE (LEDs)                    */
              0x19, 0x01,     /*   USAGE_MINIMUM (Num Lock)             */
              0x29, 0x05,     /*   USAGE_MAXIMUM (Kana)                 */
              0x91, 0x02,     /*   OUTPUT (Data,Var,Abs)                */
              0x95, 0x01,     /*   REPORT_COUNT (1)                     */
              0x75, 0x03,     /*   REPORT_SIZE (3)                      */
              0x91, 0x03,     /*   OUTPUT (Cnst,Var,Abs)                */
              0x95, 0x06,     /*   REPORT_COUNT (6)                     */
              0x75, 0x08,     /*   REPORT_SIZE (8)                      */
              0x15, 0x00,     /*   LOGICAL_MINIMUM (0)                  */
              0x25, 0x65,     /*   LOGICAL_MAXIMUM (101)                */
              0x05, 0x07,     /*   USAGE_PAGE (Keyboard)                */
              0x19, 0x00,     /*   USAGE_MINIMUM (Reserved)             */
              0x29, 0x65,     /*   USAGE_MAXIMUM (Keyboard Application) */
              0x81, 0x00,     /*   INPUT (Data,Ary,Abs)                 */
              0xc0            /* END_COLLECTION                         */
};

/**
  * @brief  USBD_KBD_Init
  *         Initialize the HID interface
  * @param  pdev: device instance
  * @param  cfgidx: Configuration index
  * @retval status
  */

static uint8_t  USBD_KBD_Init (USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  /* Open EP IN */
  USBD_LL_OpenEP(pdev, KBD_EPIN_ADDR, USBD_EP_TYPE_INTR, KBD_EPIN_SIZE);
  static uint8_t mem[sizeof (USBD_HID_HandleTypeDef)];
  pdev->ep_in[KBD_EPIN_ADDR & 0xFU].is_used = 1U;

  pdev->pClassData = mem;

  ((USBD_HID_HandleTypeDef *)pdev->pClassData)->state = HID_IDLE;

  return USBD_OK;
}

/**
  * @brief  USBD_KBD_Init
  *         DeInitialize the HID layer
  * @param  pdev: device instance
  * @param  cfgidx: Configuration index
  * @retval status
  */
static uint8_t  USBD_KBD_DeInit (USBD_HandleTypeDef *pdev,
                                 uint8_t cfgidx)
{
  /* Close HID EPs */
  USBD_LL_CloseEP(pdev, KBD_EPIN_ADDR);
  pdev->ep_in[KBD_EPIN_ADDR & 0xFU].is_used = 0U;

  return USBD_OK;
}

/**
  * @brief  USBD_KBD_Setup
  *         Handle the HID specific requests
  * @param  pdev: instance
  * @param  req: usb requests
  * @retval status
  */
static uint8_t  USBD_KBD_Setup (USBD_HandleTypeDef *pdev,
                                USBD_SetupReqTypedef *req)
{
  USBD_HID_HandleTypeDef *hhid = (USBD_HID_HandleTypeDef*) pdev->pClassData;
  uint16_t len = 0U;
  uint8_t *pbuf = NULL;
  uint16_t status_info = 0U;
  USBD_StatusTypeDef ret = USBD_OK;
  req->wLength = req->wLength & 0x7f;

  switch (req->bmRequest & USB_REQ_TYPE_MASK)
  {
  case USB_REQ_TYPE_CLASS :
    switch (req->bRequest)
    {
    case HID_REQ_SET_PROTOCOL:
      hhid->Protocol = (uint8_t)(req->wValue);
      break;

    case HID_REQ_GET_PROTOCOL:
      USBD_CtlSendData (pdev, (uint8_t *)(void *)&hhid->Protocol, 1U);
      break;

    case HID_REQ_SET_IDLE:
      hhid->IdleState = (uint8_t)(req->wValue >> 8);
      break;

    case HID_REQ_GET_IDLE:
      USBD_CtlSendData (pdev, (uint8_t *)(void *)&hhid->IdleState, 1U);
      break;

    default:
      USBD_CtlError (pdev, req);
      ret = USBD_FAIL;
      break;
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

    case USB_REQ_GET_DESCRIPTOR:
      if(req->wValue >> 8 == HID_REPORT_DESC)
      {
        len = MIN(HID_KBD_REPORT_DESC_SIZE , req->wLength);
        pbuf = HID_KBD_ReportDesc;
        printf1(TAG_GREEN,"get report desc\r\n");
      }
      else if(req->wValue >> 8 == HID_DESCRIPTOR_TYPE)
      {
        pbuf = USBD_HID_Desc;
        len = MIN(USB_HID_DESC_SIZ, req->wLength);
      }
      else
      {
        USBD_CtlError (pdev, req);
        ret = USBD_FAIL;
        break;
      }
      USBD_CtlSendData (pdev, pbuf, len);
      break;

    case USB_REQ_GET_INTERFACE :
      if (pdev->dev_state == USBD_STATE_CONFIGURED)
      {
        USBD_CtlSendData (pdev, (uint8_t *)(void *)&hhid->AltSetting, 1U);
      }
      else
      {
        USBD_CtlError (pdev, req);
			  ret = USBD_FAIL;
      }
      break;

    case USB_REQ_SET_INTERFACE :
      if (pdev->dev_state == USBD_STATE_CONFIGURED)
      {
        hhid->AltSetting = (uint8_t)(req->wValue);
      }
      else
      {
        USBD_CtlError (pdev, req);
			  ret = USBD_FAIL;
      }
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
  * @brief  USBD_KBD_DataIn
  *         handle data IN Stage
  * @param  pdev: device instance
  * @param  epnum: endpoint index
  * @retval status
  */
static uint8_t  USBD_KBD_DataIn (USBD_HandleTypeDef *pdev,
                              uint8_t epnum)
{
  /* Ensure that the FIFO is empty before a new transfer, this condition could
  be caused by a new transfer before the end of the previous transfer */
  ((USBD_HID_HandleTypeDef *)pdev->pClassData)->state = HID_IDLE;
  return USBD_OK;
}

static void USBD_KBD_Transmit(uint8_t * msg)
{
    printf1(TAG_DUMP2,"<< ");
    dump_hex1(TAG_DUMP2, msg, KBD_PACKET_SIZE);

    Solo_USBD_Device.ep_in[KBD_EPIN_ADDR & 0xFU].total_length = KBD_PACKET_SIZE;

    while (PCD_GET_EP_TX_STATUS(USB, KBD_EPIN_ADDR & 0x0f) == USB_EP_TX_VALID)
        ;
    USBD_LL_Transmit(&Solo_USBD_Device, KBD_EPIN_ADDR, msg, KBD_PACKET_SIZE);
}

void usb_kbd_send(uint8_t *msg, int len)
{
    uint8_t report[8];
    for (int i = 0; i < len; i++)
    {
        memset(report, 0, sizeof(report));
        uint8_t ch = msg[i];
        if (ch >= 'a' && ch <= 'z')
        {
            report[2] = ch - 'a' + 4;
            USBD_KBD_Transmit(report);
        }
        else if (ch >= 'A' && ch <= 'Z')
        {
            report[0] = 2; //left shift
            report[2] = ch - 'A' + 4;
            USBD_KBD_Transmit(report);
        }
        else if (ch >= '1' && ch <= '9')
        {
            report[2] = ch - '1' + 0x1e;
            USBD_KBD_Transmit(report);
        }
        else
        {
            for (int j=0; key_map[j][0] != 0; j++)
            {
                if (ch == key_map[j][0]) {
                    report[0] = key_map[j][1];
                    report[2] = key_map[j][2];
                    USBD_KBD_Transmit(report);
                    break;
                }
            }
        }
        memset(report, 0, sizeof(report));
        USBD_KBD_Transmit(report);
    }
}
