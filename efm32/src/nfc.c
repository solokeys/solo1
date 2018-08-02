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
void write_reg(uint8_t reg_addr, uint8_t mask,uint8_t data)
{
	uint8_t addr = NFC_DEV_ADDR;
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
	uint8_t write_data[1];
	uint8_t read_data[1];

	seq.addr  = NFC_DEV_ADDR;
	seq.flags = I2C_FLAG_WRITE_READ;
	write_data[0] = (0x1f & reg_addr) | (0x20);
	printf("mode: 0x%x = 0x%02x\n",NFC_DEV_ADDR, (int)write_data[0]);

	seq.buf[0].data   = write_data;
	seq.buf[0].len    = 1;
	seq.buf[1].data   = read_data;
	seq.buf[1].len    = 1;

	ret = I2CSPM_Transfer(I2C0, &seq);

	if (ret != i2cTransferDone) {
		printf("I2C fail %04x\r\n",ret);
		exit(1);
	}

	return read_data[0];
}

// data must be 17 bytes long
void read_reg_block(uint8_t * data)
{
	int i;
	for (i = 0; i < 15; i++)
	{

		*data = read_reg(i);
		printf("data %d: %x\n" ,i,(int)(*data));
		data++;
	}
	*data++ = read_reg(0x1E);
	*data++ = read_reg(0x1F);
}
#define NS_REG_ADDR		6
typedef enum{
	RF_FIELD_PRESENT = 	0x01,
	EEPROM_WR_BUSY = 	0x02,
	EEPROM_WR_ERR = 	0x04,
	SRAM_RF_READY = 	0x08,
	SRAM_I2C_READY = 	0x10,
	RF_LOCKED = 		0x20,
	I2C_LOCKED = 		0x40,
	NDEF_DATA_READ = 	0x80,
} NS_REG_BIT;

#define RF_FIELD_PRESENT		0x01
#define EEPROM_WR_BUSY			0x02
#define SRAM_RF_READY			0x02

typedef struct {
	uint8_t header;
	uint8_t tlen;
	uint8_t plen;
	uint8_t ilen;
	uint8_t rtype;
} NDEF;

void nfc_test()
{
	uint8_t data[17];
	uint8_t ns_reg;
	uint8_t last_ns_reg;
	// magic-number,
	uint8_t cc[] = {0xE1,0x10,0x08, 0x00};

	uint8_t ndef[32] = "\x03\x11\xD1\x01\x0D\x55\x01adafruit.com";

	printf("-NFC test-\n");

	GPIO_PinOutSet(NFC_DEV_SS);
	delay(10);
	GPIO_PinOutClear(NFC_DEV_SS);
	delay(10);

	read_reg_block(data);

	printf("regs:\n");
	dump_hex(data,17);

	while(1)
		;

	while (1)
	{
		delay(1090);
		read_reg_block(data);
	}


	return;
//
////
//	read_block(0x00, data);
//	read_block(0x00, data);
//	printf("block 00: "); dump_hex(data,16);
//
//	printf("capability container [init]: "); dump_hex(data+12,4);
//
//	data[0] = 0xaa;
//	memmove(data+12,cc,4);
//
//	write_block(0x00,data);
//	delay(10);
//	write_block(0x01,ndef);
//	delay(10);
//	write_block(0x02,ndef+16);
//	delay(10);
//	printf("wrote block\n");
//
//	read_block(0x00, data);
//
//	printf("capability container [done]: "); dump_hex(data+12,4);
//
//	read_reg_block(data);
//	printf("regs [init]:"); dump_hex(data,8);

//	write_reg(0, 0xff, 0x42);
//	write_reg(2, 0xff, 0x01);
//
//	read_reg_block(data);
//	printf("block 3A [done]:"); dump_hex(data,8);
//
//	read_block(0x3A, data);
//	printf("block 3A [done]:"); dump_hex(data,16);

//	while(1)
//	{
//		delay(250);
//		read_reg_block(data);
//		printf("regs:"); dump_hex(data,8);
//
//		ns_reg = read_reg(NS_REG_ADDR);
//		if (ns_reg & SRAM_I2C_READY)
//		{
//			printf("Data in sram\r\n");
//		}
//
////		if ((ns_reg & RF_FIELD_PRESENT) && !(last_ns_reg & RF_FIELD_PRESENT))
////		{
////			printf("RF present\r\n");
////		}
////		if (!(ns_reg & RF_FIELD_PRESENT) && (last_ns_reg & RF_FIELD_PRESENT))
////		{
////			printf("RF gone\r\n");
////		}
//		last_ns_reg = ns_reg;
//	}

}
