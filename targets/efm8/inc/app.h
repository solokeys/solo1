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
