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
 * nfc.c
 *
 *  Created on: Jul 22, 2018
 *      Author: conor
 */

#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#include "em_chip.h"
#include "em_gpio.h"
#include "em_i2c.h"

#include "log.h"
#include "util.h"
#include "nfc.h"
#include "app.h"

#define NFC_DEV_ADDR		(0xa0|(0x0<<1))
#define NFC_DEV_USART		USART1
#ifndef IS_BOOTLOADER
I2C_TransferReturn_TypeDef I2CSPM_Transfer(I2C_TypeDef *i2c, I2C_TransferSeq_TypeDef *seq)
{
  I2C_TransferReturn_TypeDef ret;
  uint32_t timeout = 10000;
  /* Do a polled transfer */
  ret = I2C_TransferInit(i2c, seq);

  while (ret == i2cTransferInProgress && timeout--)
  {
    ret = I2C_Transfer(i2c);
  }
  return ret;
}

// data must be 16 bytes
void read_block(uint8_t block, uint8_t * data)
{
	uint8_t addr = NFC_DEV_ADDR;
	I2C_TransferSeq_TypeDef    seq;
	I2C_TransferReturn_TypeDef ret;
	uint8_t i2c_read_data[16];
	uint8_t i2c_write_data[1];

	seq.addr  = addr;
	seq.flags = I2C_FLAG_WRITE_READ;
	/* Select command to issue */
	i2c_write_data[0] = block;
	seq.buf[0].data   = i2c_write_data;
	seq.buf[0].len    = 1;
	/* Select location/length of data to be read */
	seq.buf[1].data = i2c_read_data;
	seq.buf[1].len  = 16;

	ret = I2CSPM_Transfer(I2C0, &seq);

	if (ret != i2cTransferDone) {
		printf("I2C fail %04x\r\n",ret);
		exit(1);
	}
	memmove(data, i2c_read_data, 16);
}

// data must be 16 bytes
void write_block(uint8_t block, uint8_t * data)
{
	uint8_t addr = NFC_DEV_ADDR;
	I2C_TransferSeq_TypeDef    seq;
	I2C_TransferReturn_TypeDef ret;
	uint8_t i2c_write_data[1 + 16];

	seq.addr  = addr;
	seq.flags = I2C_FLAG_WRITE;
	/* Select command to issue */
	i2c_write_data[0] = block;
	memmove(i2c_write_data + 1, data, 16);
	seq.buf[0].data   = i2c_write_data;
	seq.buf[0].len    = 17;
	/* Select location/length of data to be read */
	seq.buf[1].data = NULL;
	seq.buf[1].len  = 0;

	ret = I2CSPM_Transfer(I2C0, &seq);

	if (ret != i2cTransferDone) {
		printf("I2C fail %04x\r\n",ret);
		exit(1);
	}
}

void write_reg_flash(uint8_t reg_addr, uint8_t mask,uint8_t data)
{
	uint8_t addr = NFC_DEV_ADDR;
	I2C_TransferSeq_TypeDef    seq;
	I2C_TransferReturn_TypeDef ret;
	uint8_t i2c_write_data[4];

	seq.addr  = addr;
	seq.flags = I2C_FLAG_WRITE;
	i2c_write_data[0] = 0x3a;
	i2c_write_data[1] = reg_addr;
	i2c_write_data[2] = mask;
	i2c_write_data[3] = data;

	seq.buf[0].data   = i2c_write_data;
	seq.buf[0].len    = 4;
	seq.buf[1].data = NULL;
	seq.buf[1].len  = 0;

	ret = I2CSPM_Transfer(I2C0, &seq);

	if (ret != i2cTransferDone) {
		printf("I2C fail %04x\r\n",ret);
		exit(1);
	}
}

void write_reg(uint8_t reg_addr, uint8_t data)
{

	uint8_t mode = 0x00 | (reg_addr & 0x1f);
//	delay(10);

//	delay(10);
	GPIO_PinOutClear(NFC_DEV_SS);
	delay(1);
	USART_SpiTransfer(NFC_DEV_USART, mode);
	mode = USART_SpiTransfer(NFC_DEV_USART, data);
	GPIO_PinOutSet(NFC_DEV_SS);
}

void write_command(uint8_t cmd)
{

	uint8_t mode = cmd;
//	delay(10);

//	delay(10);
	GPIO_PinOutClear(NFC_DEV_SS);
	delay(1);
	USART_SpiTransfer(NFC_DEV_USART, mode);
	GPIO_PinOutSet(NFC_DEV_SS);
	GPIO_PinOutClear(NFC_DEV_SS);

}

void write_eeprom(uint8_t block, uint8_t * data)
{

	uint8_t mode = 0x40;
//	delay(10);

//	delay(10);
	GPIO_PinOutClear(NFC_DEV_SS);
	delay(1);
	USART_SpiTransfer(NFC_DEV_USART, mode);
	mode = block << 1;
	USART_SpiTransfer(NFC_DEV_USART, mode);
	USART_SpiTransfer(NFC_DEV_USART, *data++);
	USART_SpiTransfer(NFC_DEV_USART, *data++);
	USART_SpiTransfer(NFC_DEV_USART, *data++);
	USART_SpiTransfer(NFC_DEV_USART, *data++);

	GPIO_PinOutSet(NFC_DEV_SS);
	GPIO_PinOutClear(NFC_DEV_SS);

}

void read_eeprom(uint8_t block, uint8_t * data)
{

	uint8_t mode = 0x7f;
//	delay(10);

//	delay(10);
	GPIO_PinOutClear(NFC_DEV_SS);
	delay(1);
	USART_SpiTransfer(NFC_DEV_USART, mode);
	mode = block << 1;
	USART_SpiTransfer(NFC_DEV_USART, mode);
	*data++ = USART_SpiTransfer(NFC_DEV_USART, 0);
	*data++ = USART_SpiTransfer(NFC_DEV_USART, 0);
	*data++ = USART_SpiTransfer(NFC_DEV_USART, 0);
	*data++ = USART_SpiTransfer(NFC_DEV_USART, 0);


	GPIO_PinOutSet(NFC_DEV_SS);
	GPIO_PinOutClear(NFC_DEV_SS);

}

uint8_t read_reg(uint8_t reg_addr)
{

	uint8_t mode = 0x20 | (reg_addr & 0x1f);
//	delay(10);

//	delay(10);
	GPIO_PinOutClear(NFC_DEV_SS);
	delay(1);
	USART_SpiTransfer(NFC_DEV_USART, mode);
	mode = USART_SpiTransfer(NFC_DEV_USART, 0);
	GPIO_PinOutSet(NFC_DEV_SS);

	GPIO_PinOutClear(NFC_DEV_SS);

//	printf("%02x: %x\n",(reg_addr),(int)mode);
	return mode;
}

void read_buffer(uint8_t * data, int len)
{

	uint8_t mode = 0xC0;
	int i;
	if (len > 32)
	{
		printf("warning, max len is 32\n");
		len = 32;
	}

	GPIO_PinOutClear(NFC_DEV_SS);
	delay(1);
	USART_SpiTransfer(NFC_DEV_USART, mode);
	for(i = 0; i < len; i++)
	{
		*data++ = USART_SpiTransfer(NFC_DEV_USART, 0);
	}
	GPIO_PinOutSet(NFC_DEV_SS);

	GPIO_PinOutClear(NFC_DEV_SS);

}

// data must be 14 bytes long
void read_reg_block(uint8_t * data)
{
	int i;
	uint8_t mode = 0x20 | (0 & 0x1f);
	GPIO_PinOutClear(NFC_DEV_SS);
	delay(1);
	USART_SpiTransfer(NFC_DEV_USART, mode);
	for (i = 0; i < 0x20; i++)
	{
		mode = USART_SpiTransfer(NFC_DEV_USART, 0);
		if (i < 6 || (i >=8 && i < 0x0f) || (i >= 0x1e))
		{
			*data = mode;
			data++;
		}
	}

	GPIO_PinOutSet(NFC_DEV_SS);
	GPIO_PinOutClear(NFC_DEV_SS);
}



typedef struct {
	uint8_t header;
	uint8_t tlen;
	uint8_t plen;
	uint8_t ilen;
	uint8_t rtype;
} NDEF;

typedef struct {
	uint8_t io;
	uint8_t conf0;
	uint8_t conf1;
	uint8_t conf2;
	uint8_t rfid_status;
	uint8_t ic_status;
	uint8_t mask0;
	uint8_t mask1;
	uint8_t int0;
	uint8_t int1;
	uint8_t buf_status2;
	uint8_t buf_status1;
	uint8_t last_nfc_address;
	uint8_t maj;
	uint8_t minor;
} __attribute__((packed)) AMS_REGS;

void nfc_test()
{
	uint8_t data[32];
	uint8_t ns_reg;
	uint8_t last_ns_reg;
	// magic-number,
	uint8_t cc[] = {0xE1,0x10,0x08, 0x00};

	uint8_t ndef[32] = "\x03\x11\xD1\x01\x0D\x55\x01adafruit.com";

	AMS_REGS  * regs;

	return ;



	delay(10);
	GPIO_PinOutSet(NFC_DEV_SS);
	delay(10);
	GPIO_PinOutClear(NFC_DEV_SS);
	delay(10);

//	uint8_t reg = read_reg(0);
	write_command(0xC2);				// Set to default state
	write_command(0xC4);				// Clear buffer

	write_reg(0x3, 0x80 | 0x40);		// enable tunneling mode and RF configuration



	read_reg_block(data);

	printf("regs: "); dump_hex(data,15);

	delay(100);


	read_reg_block(data);

	printf("regs: "); dump_hex(data,15);



	if (0)
	{
		read_eeprom(0x7F, data);
		printf("initial config: "); dump_hex(data,4);

		data[0] = (1<<2) | 0x03;	// save cfg1 setting for energy harvesting
		data[1] = 0x80 | 0x40;	// save cfg2 setting for tunneling
		write_eeprom(0x7F, data);

		printf("updated config: "); dump_hex(data,4);
	}

	while (1)
	{
//		delay(100);
//		read_reg_block(data);
//		regs = (AMS_REGS *)data;
//
//		if ((regs->buf_status2 & 0x3f) && !(regs->buf_status2 & 0x80))
//		{
//			read_buffer(data, regs->buf_status2 & 0x3f);
//			printf("data: ");
//
//			dump_hex(data, regs->buf_status2 & 0x3f);
//		}

//		dump_hex(data,15);
	}

}

#endif
