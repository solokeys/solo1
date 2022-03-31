/**
  ******************************************************************************
  * @file    usbd_hid.h
  * @author  MCD Application Team
  * @brief   Header file for the usbd_hid_core.c file.
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
#ifndef __USB_HID_H
#define __USB_HID_H

#ifdef __cplusplus
 extern "C" {
#endif

#include  "usbd_ioreq.h"

// endpoint 1 is HID
#define HID_ENDPOINT                    1

#define HID_PACKET_SIZE                 64
#define HID_EPIN_ADDR                   0x81U
#define HID_EPIN_SIZE                   HID_PACKET_SIZE
#define HID_EPOUT_ADDR                  0x01U
#define HID_EPOUT_SIZE                  HID_PACKET_SIZE

#define KBD_PACKET_SIZE                 8
#define KBD_EPIN_ADDR                   0x82U
#define KBD_EPIN_SIZE                   KBD_PACKET_SIZE

#define USB_HID_DESC_SIZ                9U
#define HID_FIDO_REPORT_DESC_SIZE       34U
#define HID_KBD_REPORT_DESC_SIZE        63U

#define HID_DESCRIPTOR_TYPE             0x21U
#define HID_REPORT_DESC                 0x22U

#define HID_BINTERVAL                   5
#define KBD_BINTERVAL                   10

#define HID_REQ_SET_PROTOCOL            0x0BU
#define HID_REQ_GET_PROTOCOL            0x03U

#define HID_REQ_SET_IDLE                0x0AU
#define HID_REQ_GET_IDLE                0x02U

#define HID_REQ_SET_REPORT              0x09U
#define HID_REQ_GET_REPORT              0x01U

typedef enum
{
  HID_IDLE = 0,
  HID_BUSY,
}
HID_StateTypeDef;

typedef struct
{
  uint32_t             Protocol;
  uint32_t             IdleState;
  uint32_t             AltSetting;
  HID_StateTypeDef     state;
}
USBD_HID_HandleTypeDef;

extern USBD_ClassTypeDef  USBD_HID;
extern USBD_ClassTypeDef  USBD_KBD;


void usb_hid_recieve_callback(uint8_t ep);
void usb_kbd_send(uint8_t *msg, int len);


#ifdef __cplusplus
}
#endif

#endif

/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
