#include <string.h>

#include "stm32l4xx_ll_spi.h"

#include "ams.h"
#include "log.h"
#include "util.h"
#include "device.h"
#include "nfc.h"

static void flush_rx(void)
{
    while(LL_SPI_IsActiveFlag_RXNE(SPI1) != 0)
    {
        LL_SPI_ReceiveData8(SPI1);
    }
}


static void wait_for_tx(void)
{
    // while (LL_SPI_IsActiveFlag_BSY(SPI1) == 1)
    //     ;
    while(LL_SPI_GetTxFIFOLevel(SPI1) != LL_SPI_TX_FIFO_EMPTY)
        ;
}


static void wait_for_rx(void)
{
    while(LL_SPI_IsActiveFlag_RXNE(SPI1) == 0)
        ;
}


void ams_print_device(AMS_DEVICE * dev)
{
    printf1(TAG_NFC, "AMS_DEVICE:\r\n");
    printf1(TAG_NFC, "    io_conf:        %02x\r\n",dev->regs.io_conf);
    printf1(TAG_NFC, "    ic_conf0:       %02x\r\n",dev->regs.ic_conf0);
    printf1(TAG_NFC, "    ic_conf1:       %02x\r\n",dev->regs.ic_conf1);
    printf1(TAG_NFC, "    ic_conf2:       %02x\r\n",dev->regs.ic_conf2);
    printf1(TAG_NFC, "    rfid_status:    %02x\r\n",dev->regs.rfid_status);
    printf1(TAG_NFC, "    ic_status:      %02x\r\n",dev->regs.ic_status);
    printf1(TAG_NFC, "    mask_int0:      %02x\r\n",dev->regs.mask_int0);
    printf1(TAG_NFC, "    mask_int1:      %02x\r\n",dev->regs.mask_int1);
    printf1(TAG_NFC, "    int0:           %02x\r\n",dev->regs.int0);
    printf1(TAG_NFC, "    int1:           %02x\r\n",dev->regs.int1);
    printf1(TAG_NFC, "    buffer_status2: %02x\r\n",dev->regs.buffer_status2);
    printf1(TAG_NFC, "    buffer_status1: %02x\r\n",dev->regs.buffer_status1);
    printf1(TAG_NFC, "    last_nfc_addr:  %02x\r\n",dev->regs.last_nfc_addr);
    printf1(TAG_NFC, "    product_type:   %02x\r\n",dev->regs.product_type);
    printf1(TAG_NFC, "    product_subtype:%02x\r\n",dev->regs.product_subtype);
    printf1(TAG_NFC, "    version_maj:    %02x\r\n",dev->regs.version_maj);
    printf1(TAG_NFC, "    version_min:    %02x\r\n",dev->regs.version_min);
}

static uint8_t send_recv(uint8_t b)
{
    wait_for_tx();
    LL_SPI_TransmitData8(SPI1, b);
    wait_for_rx();
    b  = LL_SPI_ReceiveData8(SPI1);
    return b;
}


void ams_write_reg(uint8_t addr, uint8_t tx)
{
    send_recv(0x00| addr);
    send_recv(tx);

    UNSELECT();
    SELECT();
}


uint8_t ams_read_reg(uint8_t addr)
{
    send_recv(0x20| (addr & 0x1f));
    uint8_t data = send_recv(0);
    UNSELECT();
    SELECT();
    return data;
}


// data must be 14 bytes long
void read_reg_block(AMS_DEVICE * dev)
{
	int i;
	uint8_t mode = 0x20 | (4 );
    flush_rx();

	send_recv(mode);
	for (i = 0x04; i < 0x0d; i++)
	{
		dev->buf[i] = send_recv(0);
	}

    UNSELECT();
    SELECT();
}

void ams_read_buffer(uint8_t * data, int len)
{
    send_recv(0xa0);
    while(len--)
    {
        *data++ = send_recv(0x00);
    }

    UNSELECT();
    SELECT();
}

void ams_write_buffer(uint8_t * data, int len)
{
    send_recv(0x80);
    while(len--)
    {
        send_recv(*data++);
    }

    UNSELECT();
    SELECT();
}

// data must be 4 bytes
void ams_read_eeprom_block(uint8_t block, uint8_t * data)
{
    send_recv(0x7f);
    send_recv(block << 1);

    data[0] = send_recv(0);
    data[1] = send_recv(0);
    data[2] = send_recv(0);
    data[3] = send_recv(0);

    UNSELECT();
    SELECT();
}


// data must be 4 bytes
void ams_write_eeprom_block(uint8_t block, uint8_t * data)
{
    send_recv(0x40);
    send_recv(block << 1);

    send_recv(data[0]);
    send_recv(data[1]);
    send_recv(data[2]);
    send_recv(data[3]);

    UNSELECT();
    SELECT();
}

void ams_write_command(uint8_t cmd)
{
	send_recv(0xc0 | cmd);
    UNSELECT();
	SELECT();
}

const char * ams_get_state_string(uint8_t regval)
{
    if (regval & AMS_STATE_INVALID)
    {
        return "STATE_INVALID";
    }
    switch (regval & AMS_STATE_MASK)
    {
        case AMS_STATE_OFF:
            return "STATE_OFF";
        case AMS_STATE_SENSE:
            return "STATE_SENSE";
        case AMS_STATE_RESOLUTION:
            return "STATE_RESOLUTION";
        case AMS_STATE_RESOLUTION_L2:
            return "STATE_RESOLUTION_L2";
        case AMS_STATE_SELECTED:
            return "STATE_SELECTED";
        case AMS_STATE_SECTOR2:
            return "STATE_SECTOR2";
        case AMS_STATE_SECTORX_2:
            return "STATE_SECTORX_2";
        case AMS_STATE_SELECTEDX:
            return "STATE_SELECTEDX";
        case AMS_STATE_SENSEX_L2:
            return "STATE_SENSEX_L2";
        case AMS_STATE_SENSEX:
            return "STATE_SENSEX";
        case AMS_STATE_SLEEP:
            return "STATE_SLEEP";
    }
    return "STATE_WRONG";
}

int ams_state_is_valid(uint8_t regval)
{
    if (regval & AMS_STATE_INVALID)
    {
        return 0;
    }
    switch (regval & AMS_STATE_MASK)
    {
        case AMS_STATE_OFF:
        case AMS_STATE_SENSE:
        case AMS_STATE_RESOLUTION:
        case AMS_STATE_RESOLUTION_L2:
        case AMS_STATE_SELECTED:
        case AMS_STATE_SECTOR2:
        case AMS_STATE_SECTORX_2:
        case AMS_STATE_SELECTEDX:
        case AMS_STATE_SENSEX_L2:
        case AMS_STATE_SENSEX:
        case AMS_STATE_SLEEP:
            return 1;
    }
    return 0;
}

void ams_print_int0(uint8_t int0)
{
#if DEBUG_LEVEL
    uint32_t tag = (TAG_NFC)|(TAG_NO_TAG);
    printf1(TAG_NFC,"    ");
    if (int0 & AMS_INT_XRF)
        printf1(tag," XRF");
    if (int0 & AMS_INT_TXE)
        printf1(tag," TXE");
    if (int0 & AMS_INT_RXE)
        printf1(tag," RXE");
    if (int0 & AMS_INT_EER_RF)
        printf1(tag," EER_RF");
    if (int0 & AMS_INT_EEW_RF)
        printf1(tag," EEW_RF");
    if (int0 & AMS_INT_SLP)
        printf1(tag," SLP");
    if (int0 & AMS_INT_WU_A)
        printf1(tag," WU_A");
    if (int0 & AMS_INT_INIT)
        printf1(tag," INIT");

    printf1(tag,"\r\n");
#endif
}

void ams_print_int1(uint8_t int0)
{
#if DEBUG_LEVEL
    uint32_t tag = (TAG_NFC)|(TAG_NO_TAG);
    printf1(TAG_NFC,"    ");
    if (int0 & AMS_INT_ACC_ERR)
        printf1(tag," ACC_ERR");
    if (int0 & AMS_INT_EEAC_ERR)
        printf1(tag," EEAC_ERR");
    if (int0 & AMS_INT_IO_EEWR)
        printf1(tag," IO_EEWR");
    if (int0 & AMS_INT_BF_ERR)
        printf1(tag," BF_ERR");
    if (int0 & AMS_INT_CRC_ERR)
        printf1(tag," CRC_ERR");
    if (int0 & AMS_INT_PAR_ERR)
        printf1(tag," PAR_ERR");
    if (int0 & AMS_INT_FRM_ERR)
        printf1(tag," FRM_ERR");
    if (int0 & AMS_INT_RXS)
        printf1(tag," RXS");

    printf1(tag,"\r\n");
#endif
}

int ams_init(void)
{
    LL_GPIO_SetPinMode(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN,LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN);

    LL_SPI_SetClockPolarity(SPI1,LL_SPI_POLARITY_LOW);
    LL_SPI_SetClockPhase(SPI1,LL_SPI_PHASE_2EDGE);
    LL_SPI_SetRxFIFOThreshold(SPI1,LL_SPI_RX_FIFO_TH_QUARTER);
    LL_SPI_Enable(SPI1);

    // delay(10);
    SELECT();
    delay(1);

    uint8_t productType = ams_read_reg(AMS_REG_PRODUCT_TYPE);
    if (productType == 0x14)
    {
        return 1;
    }
    return 0;
}

void ams_configure(void)
{
    // Should not be used during passive operation.
    uint8_t block[4];

	// check connection
	uint8_t productType = ams_read_reg(AMS_REG_PRODUCT_TYPE);
	if (productType != 0x14)
	{
		printf1(TAG_ERR, "Have wrong product type [0x%02x]. AMS3956 connection error.\n", productType);
	}

	printf1(TAG_NFC,"AMS3956 product type 0x%02x.\n", productType);

    ams_read_eeprom_block(AMS_CONFIG_UID_ADDR, block);
    printf1(TAG_NFC,"UID: 3F 14 02 - "); dump_hex1(TAG_NFC,block,4);

    ams_read_eeprom_block(AMS_CONFIG_BLOCK0_ADDR, block);
    printf1(TAG_NFC,"conf0: "); dump_hex1(TAG_NFC,block,4);

    uint8_t sense1 = 0x44;
    uint8_t sense2 = 0x00;
    uint8_t selr   = 0x20;    // SAK

    if(block[0] != sense1 || block[1] != sense2 || block[2] != selr)
    {
        printf1(TAG_NFC,"Writing config block 0\r\n");
        block[0] = sense1;
        block[1] = sense2;
        block[2] = selr;
        block[3] = 0x00;

        ams_write_eeprom_block(AMS_CONFIG_BLOCK0_ADDR, block);
        UNSELECT();
        delay(10);
        SELECT();
        delay(10);

        ams_read_eeprom_block(AMS_CONFIG_BLOCK0_ADDR, block);
        printf1(TAG_NFC,"conf0: "); dump_hex1(TAG_NFC,block,4);
    }

    ams_read_eeprom_block(AMS_CONFIG_BLOCK1_ADDR, block);
    printf1(TAG_NFC,"conf1: "); dump_hex1(TAG_NFC,block,4);

    uint8_t ic_cfg1 = AMS_CFG1_OUTPUT_RESISTANCE_100 | AMS_CFG1_VOLTAGE_LEVEL_2V0;
    uint8_t ic_cfg2 = AMS_CFG2_TUN_MOD;

    if (block[0] != ic_cfg1 || block[1] != ic_cfg2)
    {

        printf1(TAG_NFC,"Writing config block 1\r\n");

        ams_write_reg(AMS_REG_IC_CONF1,ic_cfg1);
        ams_write_reg(AMS_REG_IC_CONF2,ic_cfg2);

        // set IC_CFG1
        block[0] = ic_cfg1;

        // set IC_CFG2
        block[1] = ic_cfg2;

        // mask interrupt bits
        block[2] = 0x80;
        block[3] = 0;

        ams_write_eeprom_block(AMS_CONFIG_BLOCK1_ADDR, block);

        UNSELECT();
        delay(10);
        SELECT();
        delay(10);

        ams_read_eeprom_block(0x7F, block);
        printf1(TAG_NFC,"conf1: "); dump_hex1(TAG_NFC,block,4);
    }


}
