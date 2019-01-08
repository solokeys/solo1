#include <string.h>

#include "stm32l4xx.h"
#include "stm32l4xx_ll_gpio.h"
#include "stm32l4xx_ll_spi.h"
#include "nfc.h"
#include "log.h"
#include "util.h"

#define SELECT() LL_GPIO_ResetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN)
#define UNSELECT() LL_GPIO_SetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN)


static void flush_rx()
{
    while(LL_SPI_IsActiveFlag_RXNE(SPI1) != 0)
    {
        LL_SPI_ReceiveData8(SPI1);
    }
}
static void wait_for_tx()
{
    // while (LL_SPI_IsActiveFlag_BSY(SPI1) == 1)
    //     ;
    while(LL_SPI_GetTxFIFOLevel(SPI1) != LL_SPI_TX_FIFO_EMPTY)
        ;
}
static void wait_for_rx()
{
    while(LL_SPI_IsActiveFlag_RXNE(SPI1) == 0)
        ;
}


static void ams_print_device(AMS_DEVICE * dev)
{
    printf1(TAG_NFC, "AMS_DEVICE:\r\n");
    printf1(TAG_NFC, "    io_conf: %02x\r\n",dev->regs.io_conf);
    printf1(TAG_NFC, "    ic_conf0: %02x\r\n",dev->regs.ic_conf0);
    printf1(TAG_NFC, "    ic_conf1: %02x\r\n",dev->regs.ic_conf1);
    printf1(TAG_NFC, "    ic_conf2: %02x\r\n",dev->regs.ic_conf2);
    printf1(TAG_NFC, "    rfid_status: %02x\r\n",dev->regs.rfid_status);
    printf1(TAG_NFC, "    ic_status: %02x\r\n",dev->regs.ic_status);
    printf1(TAG_NFC, "    mask_int0: %02x\r\n",dev->regs.mask_int0);
    printf1(TAG_NFC, "    mask_int1: %02x\r\n",dev->regs.mask_int1);
    printf1(TAG_NFC, "    int0: %02x\r\n",dev->regs.int0);
    printf1(TAG_NFC, "    int1: %02x\r\n",dev->regs.int1);
    printf1(TAG_NFC, "    buffer_status2: %02x\r\n",dev->regs.buffer_status2);
    printf1(TAG_NFC, "    buffer_status1: %02x\r\n",dev->regs.buffer_status1);
    printf1(TAG_NFC, "    last_nfc_addr: %02x\r\n",dev->regs.last_nfc_addr);
    printf1(TAG_NFC, "    product_type: %02x\r\n",dev->regs.product_type);
    printf1(TAG_NFC, "    product_subtype: %02x\r\n",dev->regs.product_subtype);
    printf1(TAG_NFC, "    version_maj: %02x\r\n",dev->regs.version_maj);
    printf1(TAG_NFC, "    version_min: %02x\r\n",dev->regs.version_min);
}

static uint8_t send_recv(uint8_t b)
{
    wait_for_tx();
    LL_SPI_TransmitData8(SPI1, b);
    wait_for_rx();
    b  = LL_SPI_ReceiveData8(SPI1);
    return b;
}


static void ams_write_reg(uint8_t addr, uint8_t tx)
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
void read_reg_block2(AMS_DEVICE * dev)
{
	int i;

    for (i = 0; i < 0x20; i++)
	{
		dev->buf[i] = ams_read_reg(i);
	}
}


// data must be 14 bytes long
void read_reg_block(AMS_DEVICE * dev)
{
	int i;
	uint8_t mode = 0x20 | (0 );
    flush_rx();

	send_recv(mode);
	for (i = 0; i < 0x20; i++)
	{
		dev->buf[i] = send_recv(0);
	}

    UNSELECT();
    SELECT();

}

void ams_write_command(uint8_t cmd)
{
	send_recv(0xc0 | cmd);
    UNSELECT();
	SELECT();
}

void nfc_init()
{
    LL_GPIO_SetPinMode(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN,LL_GPIO_MODE_OUTPUT);
    LL_GPIO_SetOutputPin(SOLO_AMS_CS_PORT,SOLO_AMS_CS_PIN);

    LL_SPI_SetClockPolarity(SPI1,LL_SPI_POLARITY_LOW);
    LL_SPI_SetClockPhase(SPI1,LL_SPI_PHASE_2EDGE);
    LL_SPI_SetRxFIFOThreshold(SPI1,LL_SPI_RX_FIFO_TH_QUARTER);
    LL_SPI_Enable(SPI1);
}

void nfc_loop()
{

        static int run = 0;
        AMS_DEVICE ams,ams2;

        if (!run)
        {
            run = 1;

        	delay(10);
            SELECT();
            delay(10);

            ams_write_command(AMS_CMD_DEFAULT);
            ams_write_command(AMS_CMD_CLEAR_BUFFER);

            ams_write_reg(AMS_REG_IC_CONF1,7);

            int x;
            for (x = 0 ; x < 2; x++)
            {
                read_reg_block(&ams);
                printf1(TAG_NFC,"regs: "); dump_hex1(TAG_NFC,ams.buf,sizeof(AMS_DEVICE));
                ams_print_device(&ams);
            }

            printf1(TAG_NFC,"---\r\n");
            for (x = 0 ; x < 2; x++)
            {
                read_reg_block2(&ams2);
                printf1(TAG_NFC,"regs: "); dump_hex1(TAG_NFC,ams.buf,sizeof(AMS_DEVICE));
            }

            printf1(TAG_NFC,"Version: %02x vs %02x\r\n",ams_read_reg(0x1e), ams.regs.version_maj);
            printf1(TAG_NFC,"Product Type: %02x vs %02x\r\n",ams_read_reg(0x1c), ams.regs.product_type);
            printf1(TAG_NFC,"Electrical: %02x vs %02x\r\n",ams_read_reg(2), ams.regs.ic_conf1);

        }
}
