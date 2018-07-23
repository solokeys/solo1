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
	uint8_t addr = 0xAA;
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
void write_reg_flash(uint8_t reg_addr, uint8_t mask,uint8_t data)
{
	uint8_t addr = 0xAA;
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
void write_reg(uint8_t reg_addr, uint8_t mask,uint8_t data)
{
	uint8_t addr = 0xAA;
	I2C_TransferSeq_TypeDef    seq;
	I2C_TransferReturn_TypeDef ret;
	uint8_t i2c_write_data[4];

	seq.addr  = addr;
	seq.flags = I2C_FLAG_WRITE;
	i2c_write_data[0] = 0xFE;
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

uint8_t read_reg(uint8_t reg_addr)
{
	I2C_TransferSeq_TypeDef    seq;
	I2C_TransferReturn_TypeDef ret;
	uint8_t write_data[2];
	uint8_t read_data[1];

	seq.addr  = 0xAA;
	seq.flags = I2C_FLAG_WRITE_READ;
	write_data[0] = 0xFE;
	write_data[1] = reg_addr;

	seq.buf[0].data   = write_data;
	seq.buf[0].len    = 2;
	seq.buf[1].data = read_data;
	seq.buf[1].len  = 1;

	ret = I2CSPM_Transfer(I2C0, &seq);

	if (ret != i2cTransferDone) {
		printf("I2C fail %04x\r\n",ret);
		exit(1);
	}

	return read_data[0];
}

void read_reg_block(uint8_t * data)
{
	int i;
	for (i = 0; i < 7; i++)
	{
		*data = read_reg(i);
//		printf("data %d: %x\n" ,i,(int)(*data));
		data++;
	}
}


void nfc_test()
{
	uint8_t data[16];
	printf("-NFC test-\n");

	read_block(0x00, data);
	printf("block 00: "); dump_hex(data,16);

	read_reg_block(data);
	printf("block 3A [init]:"); dump_hex(data,8);

	write_reg(0, 0xff, 0x43);
	write_reg_flash(0, 0xff, 0x43);
	write_reg(2, 0xff, 0x01);

	read_reg_block(data);
	printf("block 3A [done]:"); dump_hex(data,8);
//
//	read_block(0x3A, data);
//	printf("block 3A [done]:"); dump_hex(data,16);

	while(1)
		;

}
