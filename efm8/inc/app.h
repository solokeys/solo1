/*
 * app.h
 *
 *  Created on: Jun 25, 2018
 *      Author: conor
 */

#ifndef INC_APP_H_
#define INC_APP_H_

//#define USE_PRINTING

void usb_transfer_complete();
void spi_transfer_complete();

#define EFM32_RW_PIN	P1_B2
#define MSG_RDY_INT_PIN	P1_B1

void delay(int ms);

#endif /* INC_APP_H_ */
