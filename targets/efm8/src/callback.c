/*
 * Copyright (C) 2018 SoloKeys, Inc. <https://solokeys.com/>
 * 
 * This file is part of Solo.
 * 
 * Solo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Solo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Solo.  If not, see <https://www.gnu.org/licenses/>
 * 
 * This code is available under licenses for commercial use.
 * Please contact SoloKeys for more information.
 */
#include <SI_EFM8UB1_Register_Enums.h>
#include <efm8_usb.h>
#include <stdio.h>
#include "printing.h"
#include "descriptors.h"
#include "app.h"

#define UNUSED(expr) do { (void)(expr); } while (0)

#define HID_INTERFACE_INDEX 0

uint8_t tmpBuffer;



void USBD_ResetCb(void) {
//	cprints("USBD_ResetCb\r\n");
//	u2f_print_ev("USBD_ResetCb\r\n");
}


void USBD_DeviceStateChangeCb(USBD_State_TypeDef oldState,
		USBD_State_TypeDef newState) {

//	cprints("USBD_DeviceStateChangeCb\r\n");
	UNUSED(oldState);
	UNUSED(newState);

//	u2f_print_ev("USBD_DeviceStateChangeCb\r\n");
}

bool USBD_IsSelfPoweredCb(void) {
//	cprints("USBD_IsSelfPoweredCb\r\n");
	return false;
}

// Necessary routine for USB HID
USB_Status_TypeDef USBD_SetupCmdCb(
		SI_VARIABLE_SEGMENT_POINTER(setup, USB_Setup_TypeDef, MEM_MODEL_SEG)) {

	USB_Status_TypeDef retVal = USB_STATUS_REQ_UNHANDLED;


	if ((setup->bmRequestType.Type == USB_SETUP_TYPE_STANDARD)
			&& (setup->bmRequestType.Direction == USB_SETUP_DIR_IN)
			&& (setup->bmRequestType.Recipient == USB_SETUP_RECIPIENT_INTERFACE)) {
		// A HID device must extend the standard GET_DESCRIPTOR command
		// with support for HID descriptors.

		switch (setup->bRequest) {
		case GET_DESCRIPTOR:
			if (setup->wIndex == 0)
			{
				if ((setup->wValue >> 8) == USB_HID_REPORT_DESCRIPTOR) {

						USBD_Write(EP0, ReportDescriptor0,
								EFM8_MIN(sizeof(ReportDescriptor0), setup->wLength),
								false);
						retVal = USB_STATUS_OK;

				} else if ((setup->wValue >> 8) == USB_HID_DESCRIPTOR) {

						USBD_Write(EP0, (&configDesc[18]),
								EFM8_MIN(USB_HID_DESCSIZE, setup->wLength), false);
						retVal = USB_STATUS_OK;

				}
			}
			break;
		}
	}
	else if ((setup->bmRequestType.Type == USB_SETUP_TYPE_CLASS)
	           && (setup->bmRequestType.Recipient == USB_SETUP_RECIPIENT_INTERFACE)
	           && (setup->wIndex == HID_INTERFACE_INDEX))
	  {
	    // Implement the necessary HID class specific commands.
	    switch (setup->bRequest)
	    {
	      case USB_HID_SET_IDLE:
	        if (((setup->wValue & 0xFF) == 0)             // Report ID
	            && (setup->wLength == 0)
	            && (setup->bmRequestType.Direction != USB_SETUP_DIR_IN))
	        {
	          retVal = USB_STATUS_OK;
	        }
	        break;

	      case USB_HID_GET_IDLE:
	        if ((setup->wValue == 0)                      // Report ID
	            && (setup->wLength == 1)
	            && (setup->bmRequestType.Direction == USB_SETUP_DIR_IN))
	        {
	          tmpBuffer = 24;
	          USBD_Write(EP0, &tmpBuffer, 1, false);
	          retVal = USB_STATUS_OK;
	        }
	        break;
	      default:
	    	  break;
	    }
	  }

	return retVal;
}




uint16_t USBD_XferCompleteCb(uint8_t epAddr, USB_Status_TypeDef status,
		uint16_t xferred, uint16_t remaining ) {

	UNUSED(status);
	UNUSED(xferred);
	UNUSED(remaining);

	if (epAddr == INPUT_ENDPOINT)
	{
		usb_transfer_complete();
	}
	else if (epAddr == OUTPUT_ENDPOINT)
	{
		usb_writeback_complete();
	}
	return 0;
}


