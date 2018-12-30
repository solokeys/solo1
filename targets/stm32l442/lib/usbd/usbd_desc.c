/**
  ******************************************************************************
  * @file    USB_Device/HID_Standalone/Src/usbd_desc.c
  * @author  MCD Application Team
  * @brief   This file provides the USBD descriptors and string formating method.
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

/* Includes ------------------------------------------------------------------*/
#include "usbd_core.h"
#include "usbd_desc.h"
#include "usbd_conf.h"
#include APP_CONFIG


#define USBD_VID                        0x0483
#define USBD_PID                        0xA2CA
#define USBD_LANGID_STRING              0x409
#ifndef SOLO_HACKER
#define USBD_MANUFACTURER_STRING        "Solo Keys"
#define USBD_PRODUCT_FS_STRING          "Solo"
#define USBD_SERIAL_NUM                 "solocafebabe"
#else
#define USBD_MANUFACTURER_STRING        "Solo Keys"
#define USBD_PRODUCT_FS_STRING          "Solo HACKER (Unlocked)"
#define USBD_SERIAL_NUM                 "solocafebabe"
#endif

uint8_t *USBD_HID_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
uint8_t *USBD_HID_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);
uint8_t *USBD_HID_ManufacturerStrDescriptor (USBD_SpeedTypeDef speed, uint16_t *length);
uint8_t *USBD_HID_ProductStrDescriptor (USBD_SpeedTypeDef speed, uint16_t *length);
uint8_t *USBD_HID_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length);

#ifdef USB_SUPPORT_USER_STRING_DESC
uint8_t *USBD_HID_USRStringDesc (USBD_SpeedTypeDef speed, uint8_t idx, uint16_t *length);
#endif

USBD_DescriptorsTypeDef Solo_Desc = {
  USBD_HID_DeviceDescriptor,
  USBD_HID_LangIDStrDescriptor,
  USBD_HID_ManufacturerStrDescriptor,
  USBD_HID_ProductStrDescriptor,
  USBD_HID_SerialStrDescriptor,
};

/* USB Standard Device Descriptor */
const uint8_t USBD_DeviceDesc[USB_LEN_DEV_DESC]= {
  0x12,                       /* bLength */
  USB_DESC_TYPE_DEVICE,       /* bDescriptorType */
  0x00,                       /* bcdUSB */
  0x02,
  0x00,                       /* bDeviceClass */
  0x00,                       /* bDeviceSubClass */
  0x00,                       /* bDeviceProtocol */
  USB_MAX_EP0_SIZE,           /* bMaxPacketSize */
  LOBYTE(USBD_VID),           /* idVendor */
  HIBYTE(USBD_VID),           /* idVendor */
  LOBYTE(USBD_PID),           /* idVendor */
  HIBYTE(USBD_PID),           /* idVendor */
  0x00,                       /* bcdDevice rel. 2.00 */
  0x02,
  USBD_IDX_MFC_STR,           /* Index of manufacturer string */
  USBD_IDX_PRODUCT_STR,       /* Index of product string */
  USBD_IDX_SERIAL_STR,        /* Index of serial number string */
  USBD_MAX_NUM_CONFIGURATION  /* bNumConfigurations */
}; /* USB_DeviceDescriptor */

/* USB Standard Device Descriptor */
const uint8_t USBD_LangIDDesc[USB_LEN_LANGID_STR_DESC]=
{
  USB_LEN_LANGID_STR_DESC,
  USB_DESC_TYPE_STRING,
  LOBYTE(USBD_LANGID_STRING),
  HIBYTE(USBD_LANGID_STRING),
};

uint8_t USBD_StrDesc[32];

/**
  * @brief  Returns the device descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_HID_DeviceDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  *length = sizeof(USBD_DeviceDesc);
  return (uint8_t*)USBD_DeviceDesc;
}

/**
  * @brief  Returns the LangID string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_HID_LangIDStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  *length = sizeof(USBD_LangIDDesc);
  return (uint8_t*)USBD_LangIDDesc;
}

/**
  * @brief  Returns the product string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_HID_ProductStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  USBD_GetString((uint8_t *)USBD_PRODUCT_FS_STRING, USBD_StrDesc, length);
  return USBD_StrDesc;
}

/**
  * @brief  Returns the manufacturer string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_HID_ManufacturerStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  USBD_GetString((uint8_t *)USBD_MANUFACTURER_STRING, USBD_StrDesc, length);
  return USBD_StrDesc;
}

/**
  * @brief  Returns the serial number string descriptor.
  * @param  speed: Current device speed
  * @param  length: Pointer to data length variable
  * @retval Pointer to descriptor buffer
  */
uint8_t *USBD_HID_SerialStrDescriptor(USBD_SpeedTypeDef speed, uint16_t *length)
{
  USBD_GetString((uint8_t *)USBD_SERIAL_NUM, USBD_StrDesc, length);
  return USBD_StrDesc;
}
