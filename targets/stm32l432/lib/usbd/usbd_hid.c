/**
  ******************************************************************************
  * @file    usbd_hid.c
  * @author  MCD Application Team
  * @brief   This file provides the HID core functions.
  *
  * @verbatim
  *
  *          ===================================================================
  *                                HID Class  Description
  *          ===================================================================
  *           This module manages the HID class V1.11 following the "Device Class Definition
  *           for Human Interface Devices (HID) Version 1.11 Jun 27, 2001".
  *           This driver implements the following aspects of the specification:
  *             - The Boot Interface Subclass
  *             - The Mouse protocol
  *             - Usage Page : Generic Desktop
  *             - Usage : Joystick
  *             - Collection : Application
  *
  * @note     In HS mode and when the DMA is used, all variables and data structures
  *           dealing with the DMA during the transaction process should be 32-bit aligned.
  *
  *
  *  @endverbatim
  *
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

#include "fifo.h"
#include "log.h"

extern int usbhid_rdy ;


static uint8_t  USBD_HID_Init (USBD_HandleTypeDef *pdev,
                               uint8_t cfgidx);

static uint8_t  USBD_HID_DeInit (USBD_HandleTypeDef *pdev,
                                 uint8_t cfgidx);

static uint8_t  USBD_HID_Setup (USBD_HandleTypeDef *pdev,
                                USBD_SetupReqTypedef *req);

static uint8_t  *USBD_HID_GetFSCfgDesc (uint16_t *length);

static uint8_t  *USBD_HID_GetDeviceQualifierDesc (uint16_t *length);

static uint8_t  USBD_HID_DataIn (USBD_HandleTypeDef *pdev, uint8_t epnum);

static uint8_t  USBD_HID_DataOut (USBD_HandleTypeDef *pdev,
                              uint8_t epnum);


USBD_ClassTypeDef  USBD_HID =
{
  USBD_HID_Init,
  USBD_HID_DeInit,
  USBD_HID_Setup,
  NULL, /*EP0_TxSent*/
  NULL, /*EP0_RxReady*/
  USBD_HID_DataIn, /*DataIn*/
  USBD_HID_DataOut, /*DataOut*/
  NULL, /*SOF */
  NULL,
  NULL,


  USBD_HID_GetFSCfgDesc,
  USBD_HID_GetFSCfgDesc,
  USBD_HID_GetFSCfgDesc,
  USBD_HID_GetDeviceQualifierDesc,
};

#define USBD_HID_CfgHSDesc USBD_HID_OtherSpeedCfgDesc
#define USBD_HID_CfgFSDesc USBD_HID_OtherSpeedCfgDesc

/* USB HID device Other Speed Configuration Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_OtherSpeedCfgDesc[]  __ALIGN_END =
{
  0x09, /* bLength: Configuration Descriptor size */
  USB_DESC_TYPE_CONFIGURATION, /* bDescriptorType: Configuration */
  9 + 9 + 9+ 7+7,
  /* wTotalLength: Bytes returned */
  0x00,
  0x01,         /*bNumInterfaces: 1 interface*/
  0x01,         /*bConfigurationValue: Configuration value*/
  0x00,         /*iConfiguration: Index of string descriptor describing
  the configuration*/
  0x80,         /*bmAttributes: bus powered and Support Remote Wake-up */
  0x32,         /*MaxPower 100 mA: this current is used for detecting Vbus*/

  /************** Descriptor of Joystick Mouse interface ****************/
  /* 09 */
  0x09,         /*bLength: Interface Descriptor size*/
  USB_DESC_TYPE_INTERFACE,/*bDescriptorType: Interface descriptor type*/
  0x00,         /*bInterfaceNumber: Number of Interface*/
  0x00,         /*bAlternateSetting: Alternate setting*/
  0x02,         /*bNumEndpoints*/
  0x03,         /*bInterfaceClass: HID*/
  0x00,         /*bInterfaceSubClass : 1=BOOT, 0=no boot*/
  0x00,         /*nInterfaceProtocol : 0=none, 1=keyboard, 2=mouse*/
  2,            /*iInterface: Index of string descriptor*/
  /******************** Descriptor of Joystick Mouse HID ********************/
  /* 18 */
  0x09,         /*bLength: HID Descriptor size*/
  HID_DESCRIPTOR_TYPE, /*bDescriptorType: HID*/
  0x11,         /*bcdHID: HID Class Spec release number*/
  0x01,
  0x00,         /*bCountryCode: Hardware target country*/
  0x01,         /*bNumDescriptors: Number of HID class descriptors to follow*/
  0x22,         /*bDescriptorType*/
  HID_FIDO_REPORT_DESC_SIZE,/*wItemLength: Total length of Report descriptor*/
  0x00,
  /******************** Descriptor of Mouse endpoint ********************/
  0x07,          /*bLength: Endpoint Descriptor size*/
  USB_DESC_TYPE_ENDPOINT, /*bDescriptorType:*/
  HID_EPIN_ADDR,     /*bEndpointAddress: Endpoint Address (IN)*/
  0x03,          /*bmAttributes: Interrupt endpoint*/
  HID_EPIN_SIZE, /*wMaxPacketSize: 4 Byte max */
  0x00,
  HID_BINTERVAL,          /*bInterval: Polling Interval */


  0x07,          /*bLength: Endpoint Descriptor size*/
  USB_DESC_TYPE_ENDPOINT, /*bDescriptorType:*/
  HID_EPOUT_ADDR,     /*bEndpointAddress: Endpoint Address (IN)*/
  0x03,          /*bmAttributes: Interrupt endpoint*/
  HID_EPOUT_SIZE, /*wMaxPacketSize: 4 Byte max */
  0x00,
  HID_BINTERVAL,          /*bInterval: Polling Interval */
};


/* USB HID device Configuration Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_Desc[USB_HID_DESC_SIZ]  __ALIGN_END  =
{
  /* 18 */
  0x09,         /*bLength: HID Descriptor size*/
  HID_DESCRIPTOR_TYPE, /*bDescriptorType: HID*/
  0x11,         /*bcdHID: HID Class Spec release number*/
  0x00,
  0x00,         /*bCountryCode: Hardware target country*/
  0x01,         /*bNumDescriptors: Number of HID class descriptors to follow*/
  0x22,         /*bDescriptorType*/
  HID_FIDO_REPORT_DESC_SIZE,/*wItemLength: Total length of Report descriptor*/
  0x00,
};

/* USB Standard Device Descriptor */
__ALIGN_BEGIN static uint8_t USBD_HID_DeviceQualifierDesc[USB_LEN_DEV_QUALIFIER_DESC]  __ALIGN_END =
{
  USB_LEN_DEV_QUALIFIER_DESC,
  USB_DESC_TYPE_DEVICE_QUALIFIER,
  0x00,
  0x02,
  0x00,
  0x00,
  0x00,
  0x40,
  0x01,
  0x00,
};
__ALIGN_BEGIN static uint8_t HID_MOUSE_ReportDesc[HID_FIDO_REPORT_DESC_SIZE]  __ALIGN_END =
{

    0x06, 0xd0, 0xf1,// USAGE_PAGE (FIDO Alliance)
        0x09, 0x01,// USAGE (Keyboard)
        0xa1, 0x01,// COLLECTION (Application)

        0x09, 0x20,                   //   USAGE (Input Report Data)
        0x15, 0x00,                   //   LOGICAL_MINIMUM (0)
        0x26, 0xff, 0x00,             //   LOGICAL_MAXIMUM (255)
        0x75, 0x08,                   //   REPORT_SIZE (8)
        0x95, HID_PACKET_SIZE,                   //   REPORT_COUNT (64)
        0x81, 0x02,                   //   INPUT (Data,Var,Abs)
        0x09, 0x21,                   //   USAGE(Output Report Data)
        0x15, 0x00,                   //   LOGICAL_MINIMUM (0)
        0x26, 0xff, 0x00,             //   LOGICAL_MAXIMUM (255)
        0x75, 0x08,                   //   REPORT_SIZE (8)
        0x95, HID_PACKET_SIZE,                   //   REPORT_COUNT (64)
        0x91, 0x02,                   //   OUTPUT (Data,Var,Abs)

    0xc0,// END_COLLECTION

};

static uint8_t hidmsg_buf[64];

void usb_hid_recieve_callback(uint8_t ep)
{
    fifo_hidmsg_add(hidmsg_buf);
    memset(hidmsg_buf,0,64);
    USBD_LL_PrepareReceive(&Solo_USBD_Device,
            HID_ENDPOINT,
            hidmsg_buf,
            HID_PACKET_SIZE);
}

// static void dump_pma()
// {
//
//     register uint32_t _wRegBase = (uint32_t)USB;
//     _wRegBase += (uint32_t)(USB)->BTABLE + 0x400;
//
//     uint16_t * pma_ptr = (uint16_t *)_wRegBase;
//     uint16_t val;
//     uint32_t offset = (uint32_t)(USB)->BTABLE;
//
//     printf1(TAG_GREEN,"btable: %02lx\r\n",offset);
//
//     for (int i = 0; i < 2; i++)
//     {
//         uint16_t addr_tx = pma_ptr[i * 4 + 0];
//         uint16_t cnt_tx = pma_ptr[i * 4 + 1];
//         uint16_t addr_rx = pma_ptr[i * 4 + 2];
//         uint16_t cnt_rx = pma_ptr[i * 4 + 3];
//
//         printf1(TAG_GREEN,"EP%d addr_tx == %02x, count_tx == %02x\r\n", i, addr_tx,cnt_tx );
//         printf1(TAG_GREEN,"EP%d addr_rx == %02x, count_rx == %02x\r\n", i, addr_rx,cnt_rx );
//     }
//
//     uint16_t ep1_tx = pma_ptr[1 * 4 + 0];
//
//     for (int i  = 0; i < 32; i++)
//     {
//         val = pma_ptr[ep1_tx + i];
//         printf1(TAG_GREEN,"%04x ",val);
//     }
//     printf1(TAG_GREEN,"\r\n");
// }

/**
  * @brief  USBD_HID_Init
  *         Initialize the HID interface
  * @param  pdev: device instance
  * @param  cfgidx: Configuration index
  * @retval status
  */

static uint8_t  USBD_HID_Init (USBD_HandleTypeDef *pdev, uint8_t cfgidx)
{
  /* Open EP IN */
  USBD_LL_OpenEP(pdev, HID_EPIN_ADDR, USBD_EP_TYPE_INTR, HID_EPIN_SIZE);
  USBD_LL_OpenEP(pdev, HID_EPOUT_ADDR, USBD_EP_TYPE_INTR, HID_EPOUT_SIZE);
  static uint8_t mem[sizeof (USBD_HID_HandleTypeDef)];
  pdev->ep_in[HID_EPIN_ADDR & 0xFU].is_used = 1U;
  pdev->ep_out[HID_EPOUT_ADDR & 0xFU].is_used = 1U;

  pdev->pClassData = mem;

  ((USBD_HID_HandleTypeDef *)pdev->pClassData)->state = HID_IDLE;


  USBD_LL_PrepareReceive(&Solo_USBD_Device,
          HID_ENDPOINT,
          hidmsg_buf,
          HID_PACKET_SIZE);

  return USBD_OK;
}

/**
  * @brief  USBD_HID_Init
  *         DeInitialize the HID layer
  * @param  pdev: device instance
  * @param  cfgidx: Configuration index
  * @retval status
  */
static uint8_t  USBD_HID_DeInit (USBD_HandleTypeDef *pdev,
                                 uint8_t cfgidx)
{
  /* Close HID EPs */
  USBD_LL_CloseEP(pdev, HID_EPIN_ADDR);
  USBD_LL_CloseEP(pdev, HID_EPOUT_ADDR);
  pdev->ep_in[HID_EPIN_ADDR & 0xFU].is_used = 0U;
  pdev->ep_out[HID_EPOUT_ADDR & 0xFU].is_used = 0U;

  return USBD_OK;
}

/**
  * @brief  USBD_HID_Setup
  *         Handle the HID specific requests
  * @param  pdev: instance
  * @param  req: usb requests
  * @retval status
  */
static uint8_t  USBD_HID_Setup (USBD_HandleTypeDef *pdev,
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
      req->wLength = req->wLength & 0x7f;
      if(req->wValue >> 8 == HID_REPORT_DESC)
      {
        len = MIN(HID_FIDO_REPORT_DESC_SIZE , req->wLength);
        pbuf = HID_MOUSE_ReportDesc;
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
  * @brief  USBD_HID_GetCfgFSDesc
  *         return FS configuration descriptor
  * @param  speed : current device speed
  * @param  length : pointer data length
  * @retval pointer to descriptor buffer
  */
static uint8_t  *USBD_HID_GetFSCfgDesc (uint16_t *length)
{
  *length = sizeof (USBD_HID_CfgFSDesc);
  return USBD_HID_CfgFSDesc;
}

/**
  * @brief  USBD_HID_DataIn
  *         handle data IN Stage
  * @param  pdev: device instance
  * @param  epnum: endpoint index
  * @retval status
  */
static uint8_t  USBD_HID_DataIn (USBD_HandleTypeDef *pdev,
                              uint8_t epnum)
{
  /* Ensure that the FIFO is empty before a new transfer, this condition could
  be caused by a new transfer before the end of the previous transfer */
  ((USBD_HID_HandleTypeDef *)pdev->pClassData)->state = HID_IDLE;
  return USBD_OK;
}

static uint8_t  USBD_HID_DataOut (USBD_HandleTypeDef *pdev,
                              uint8_t epnum)
{
  /* Ensure that the FIFO is empty before a new transfer, this condition could
  be caused by a new transfer before the end of the previous transfer */
  ((USBD_HID_HandleTypeDef *)pdev->pClassData)->state = HID_IDLE;
  return USBD_OK;
}

/**
* @brief  DeviceQualifierDescriptor
*         return Device Qualifier descriptor
* @param  length : pointer data length
* @retval pointer to descriptor buffer
*/
static uint8_t  *USBD_HID_GetDeviceQualifierDesc (uint16_t *length)
{
  *length = sizeof (USBD_HID_DeviceQualifierDesc);
  return USBD_HID_DeviceQualifierDesc;
}
