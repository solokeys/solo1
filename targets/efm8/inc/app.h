/*
 * app.h
 *
 *  Created on: Jun 25, 2018
 *      Author: conor
 */

#ifndef INC_APP_H_
#define INC_APP_H_

#define USE_PRINTING

void usb_transfer_complete();
void spi_transfer_complete();



#define INPUT_ENDPOINT		EP2OUT
#define OUTPUT_ENDPOINT		EP3IN

#define INPUT_ENDPOINT_NUM		0x83
#define OUTPUT_ENDPOINT_NUM		0x02

//#define INPUT_ENDPOINT		EP1OUT
//#define OUTPUT_ENDPOINT		EP1IN
//
//#define INPUT_ENDPOINT_NUM		0x81
//#define OUTPUT_ENDPOINT_NUM		0x01


void delay(int ms);

#endif /* INC_APP_H_ */
