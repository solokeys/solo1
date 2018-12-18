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
#ifndef SRC_APP_H_
#define SRC_APP_H_

#define USING_DEV_BOARD

#define USING_PC

#define DEBUG_LEVEL 1

#define ENABLE_U2F

//#define BRIDGE_TO_WALLET

void printing_init();

//                              0xRRGGBB
#define LED_INIT_VALUE			0x000800
#define LED_WINK_VALUE			0x000008
#define LED_MAX_SCALER          30
#define LED_MIN_SCALER          1
// # of ms between each change in LED
#define HEARTBEAT_PERIOD        100
// Each LED channel will be multiplied by a integer between LED_MAX_SCALER
// and LED_MIN_SCALER to cause the slow pulse.  E.g.
// #define LED_INIT_VALUE			0x301000
// #define LED_MAX_SCALER          30
// #define LED_MIN_SCALER          1
// #define HEARTBEAT_PERIOD        8
// Will pulse from 0x301000 to 0x903000 to 0x301000 ...
// Which will take ~8 * (30)*2 ms


#endif /* SRC_APP_H_ */
